---
title: "Fishy HTTP"
description: "Writeup de Fishy HTTP - Hack The Box - Forensics 260pts. PE32+ exe + pcapng con C2 HTTP; patrón GET / → POST /submit_feedback repetido; exportar objetos HTTP con tshark y analizar respuestas revela comandos del C2 con la flag fragmentada en dos partes."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - pcap
  - tshark
  - http
  - c2
  - malware
  - pe32
  - windows
---

# Fishy HTTP

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 260
> 👤 Autor: warrior866

---

## Descripción

El ZIP contiene dos artefactos: `smphost.exe` (un PE32+ x86-64 de Windows) y `sustraffic.pcapng` con el tráfico de red generado por el ejecutable. El malware usa HTTP como canal C2 con un patrón fijo de polling: el agente hace `GET /` para recibir comandos del servidor, y `POST /submit_feedback` para exfiltrar los resultados. El tráfico es entre `10.142.0.4` (víctima) y `10.142.0.3:80` (C2). Exportando los objetos HTTP del pcap y analizando las respuestas del servidor, se recuperan los comandos enviados al agente — que contienen la flag dividida en dos partes.

---

## Análisis inicial de los artefactos

```bash
unzip -P 'hackthebox' a12c73c1-6a81-4971-88d0-79a3e41f9d2d.zip -d "fishy-http"
cd fishy-http

file smphost.exe
# smphost.exe: PE32+ executable (console) x86-64, for MS Windows

file sustraffic.pcapng
# sustraffic.pcapng: pcapng capture file - version 1.0

# IP addresses en el pcap
tshark -r sustraffic.pcapng -T fields -e ip.src -e ip.dst | sort -u
# 10.142.0.3  10.142.0.4
# 10.142.0.4  10.142.0.3
```

Todo el tráfico es interno entre dos hosts — la víctima y el C2 en la misma red.

---

## Reconocimiento del tráfico HTTP

```bash
tshark -r sustraffic.pcapng -Y "http" \
    -T fields -e http.request.method -e http.request.uri -e http.response.code
```

```
GET  /                     200
POST /submit_feedback      200
GET  /                     200
POST /submit_feedback      200
GET  /                     200
POST /submit_feedback      200
GET  /                     200
POST /submit_feedback      200
GET  /                     200
```

El patrón es claro: 5 GETs y 4 POSTs alternos. El agente C2 polls con GET para recibir comandos, ejecuta el comando localmente, y envía el resultado con POST.

---

## Exportación de objetos HTTP

```bash
mkdir http_resp
tshark -r sustraffic.pcapng --export-objects http,http_resp
ls http_resp/
```

Los objetos exportados incluyen tanto las respuestas a los GET (comandos del C2) como los cuerpos de los POST (resultados del agente).

---

## Análisis de las respuestas GET (comandos del C2)

```bash
# Revisar todas las respuestas del servidor
for f in http_resp/*; do
    echo "=== $f ==="
    cat "$f"
    echo
done
```

Las respuestas a `GET /` contienen los comandos que el servidor envía al agente. Analizando el contenido:

```bash
strings http_resp/* | grep -i "htb\|user\|Documents\|type\|dir" | head -20
```

Los comandos del C2 encontrados incluyen:

```
dir && cd \Users\pakcyberbot\Documents\ && type HTB{Th4ts_d07n37_
```

Y en otra respuesta GET:

```
h77P_s73417hy_revSHELL}
```

---

## Reconstrucción de la flag

Los comandos del C2 contienen la flag fragmentada en dos respuestas GET consecutivas:

```
Parte 1: HTB{Th4ts_d07n37_
Parte 2: h77P_s73417hy_revSHELL}
```

Flag completa: `HTB{Th4ts_d07n37_h77P_s73417hy_revSHELL}` → **HTB{FLAG}**

El nombre "revSHELL" en la flag hace referencia al tipo de implante — una reverse shell sobre HTTP, usando el protocolo como transporte.

---

## Análisis del ejecutable (smphost.exe)

```bash
strings smphost.exe | grep -E "http|submit|feedback|10\." | head -20
```

```
http://10.142.0.3/
http://10.142.0.3/submit_feedback
WinHttpOpen
WinHttpConnect
WinHttpSendRequest
```

El binario usa la API nativa `WinHTTP` para el C2 — más difícil de detectar que `curl` o `WebClient` de PowerShell. El nombre `smphost.exe` imita a `svchost.exe` (Windows Service Host) para pasar desapercibido en listas de procesos.

---

## Cadena de Ataque

```text
1. smphost.exe ejecutado en 10.142.0.4 (Windows víctima)
       ↓
2. GET http://10.142.0.3/ → C2 responde con comando: "dir && cd ... && type HTB{Th4ts..."
       ↓
3. Agente ejecuta el comando localmente
       ↓
4. POST /submit_feedback → envía el output del comando al C2
       ↓
5. GET / → siguiente comando: "h77P_s73417hy_revSHELL}"
       ↓
6. Repetición 5 veces → flag completa distribuida entre 2 respuestas
```

---

## Script Python de análisis automatizado

```python
import subprocess
import os

pcap = "sustraffic.pcapng"
export_dir = "http_resp"

# Identificar respuestas GET (contienen comandos del C2)
result = subprocess.run(
    ["tshark", "-r", pcap, "-Y", "http.response and http.request.uri == /",
     "-T", "fields", "-e", "http.file_data"],
    capture_output=True, text=True
)

for i, line in enumerate(result.stdout.strip().split('\n'), 1):
    if line:
        try:
            # Los datos HTTP pueden estar en hex
            decoded = bytes.fromhex(line).decode('utf-8', errors='ignore')
        except ValueError:
            decoded = line
        print(f"[CMD {i}] {decoded[:200]}")
```

---

## Lecciones Aprendidas

- **HTTP polling C2**: el patrón GET→POST repetido es una firma clara de beacon C2 sobre HTTP. Detectar con análisis de periodicidad del tráfico — los beacons tienen intervalos regulares.
- **WinHTTP vs WinINet**: malware sofisticado usa `WinHTTP` (API de bajo nivel) en lugar de `WinINet` (usada por IE/Edge) para evitar proxies del usuario y detección por hooks en WinINet.
- **Nombre engañoso**: `smphost.exe` imita a `svchost.exe` (Service Host). En análisis de memoria o logs, hay que revisar la ruta completa del ejecutable, no solo el nombre.
- **Exportar objetos HTTP con tshark**: `--export-objects http,<dir>` es la forma más rápida de extraer todos los archivos transferidos por HTTP de un pcap, incluyendo respuestas del servidor.

---

## Referencias

- [MITRE ATT&CK — Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [WinHTTP API](https://docs.microsoft.com/en-us/windows/win32/winhttp/winhttp-start-page)
- [HackTricks — C2 HTTP](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/c2)
- [tshark --export-objects](https://www.wireshark.org/docs/man-pages/tshark.html)
