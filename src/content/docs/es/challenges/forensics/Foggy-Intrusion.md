---
title: "Foggy Intrusion"
description: "Writeup de Foggy Intrusion - Hack The Box - Forensics 200pts. pcap con RCE PHP via query string (-d allow_url_include) y comandos PowerShell base64+deflate exfiltran config.php con la flag como DB_PASSWORD."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - pcap
  - tshark
  - php
  - rce
  - powershell
  - base64
  - deflate
---

# Foggy Intrusion

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 200
> 👤 Autor: warrior866

---

## Descripción

Se entrega un `capture.pcap`. Hay que reconstruir la intrusión y encontrar la flag oculta en la comunicación cifrada.

---

## Análisis inicial del pcap

```bash
tshark -r capture.pcap -q -z io,phs
tshark -r capture.pcap -Y "http.request" -T fields -e http.request.uri | head -20
```

Se detecta una petición PHP anómala:

```text
/?-d+allow_url_include=1+-d+auto_prepend_file=php://input
```

**CVE clásico de PHP-CGI** (o configuración CGI mal usada): los parámetros `-d` en la query string se pasan como directivas PHP al intérprete cuando el servidor usa `php-cgi`. `allow_url_include=1` + `auto_prepend_file=php://input` permite ejecutar código PHP enviado en el body de la petición.

---

## Extracción de comandos PowerShell

El atacante envía código PHP que ejecuta comandos PowerShell codificados en base64. El tráfico de respuesta usa compresión deflate + base64.

```python
import base64, zlib, subprocess, re

raw = subprocess.run(
    ['tshark', '-r', 'capture.pcap', '-q', '-z', 'follow,tcp,ascii,3'],
    capture_output=True, text=True
).stdout

# Comandos enviados (base64 en el POST body)
for b64 in re.findall(r"base64_decode\('([^']+)'\)", raw):
    try:
        print("CMD:", base64.b64decode(b64).decode('utf-16-le'))
    except:
        pass

# Respuestas del servidor (deflate comprimido + base64)
for blob in re.findall(r'^([A-Za-z0-9+/]{30,}={0,2})$', raw, re.M):
    try:
        print("RSP:", zlib.decompress(base64.b64decode(blob), -15).decode())
    except:
        pass
```

Comandos ejecutados visibles tras decodificar:

```text
CMD: Get-ChildItem C:\inetpub\wwwroot\ -Recurse
CMD: Get-Content C:\inetpub\wwwroot\config.php
```

---

## Flag en config.php

La respuesta del comando `Get-Content config.php` contiene:

```text
<?php
define('DB_HOST', 'localhost');
define('DB_USER', 'web_user');
define('DB_PASSWORD', 'HTB{FLAG}');
define('DB_NAME', 'spooky_web');
?>
```

La flag está almacenada como contraseña de la base de datos en el fichero de configuración exfiltrado.

---

## Cadena de Ataque

```text
1. GET /?-d+allow_url_include=1+-d+auto_prepend_file=php://input
   + PHP code en el body → RCE en el servidor web PHP-CGI
       ↓
2. PowerShell Get-ChildItem → enumera el webroot
       ↓
3. PowerShell Get-Content config.php → exfiltra configuración
       ↓
4. Respuesta comprimida (deflate) + codificada (base64)
       ↓
5. Descomprimir → DB_PASSWORD = flag
```

---

## Lecciones Aprendidas

- **PHP-CGI argument injection**: cuando PHP se ejecuta como CGI, los parámetros de query string pueden pasar directivas al intérprete. Usar PHP-FPM o mod_php y deshabilitar la exposición de PHP-CGI directamente.
- **PowerShell over HTTP**: los comandos se codifican en base64 (evasión de IDS) y las respuestas se comprimen (reduce tamaño y ofusca el contenido). Para analizar: siempre intentar base64 + deflate en ambas direcciones.
- **Credenciales en config.php**: los archivos de configuración de aplicaciones web son objetivos de alto valor para el atacante. Usar variables de entorno en lugar de hardcodear credenciales en ficheros.

---

## Referencias

- [PHP-CGI Argument Injection (CVE-2012-1823)](https://nvd.nist.gov/vuln/detail/CVE-2012-1823)
- [tshark — Follow TCP stream](https://www.wireshark.org/docs/wsug_html_chunked/ChStatFollowStream.html)
