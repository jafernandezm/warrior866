---
title: "Reminiscent"
description: "Writeup de Reminiscent - Hack The Box - Forensics 200pts. Volcado de memoria de Windows 7 (543 MB); Volatility2 con perfil Win2008R2SP1x64; pstree muestra Thunderbird lanzando PowerShell malicioso; memdump del proceso extrae un payload base64+zlib con la flag en UTF-16LE."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - memory-forensics
  - volatility
  - powershell
  - base64
  - zlib
  - utf-16le
  - windows
  - thunderbird
---

# Reminiscent

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 200
> 👤 Autor: warrior866

---

## Descripción

El reto proporciona un volcado de memoria ELF de 543 MB, un archivo `imageinfo.txt` con perfiles sugeridos y `Resume.eml` — un correo malicioso que fue el vector de entrada. El árbol de procesos revela que Thunderbird (el gestor de correo) lanzó PowerShell, que a su vez creó un segundo proceso PowerShell hijo — patrón típico de malware entregado por email. Volcando la memoria del proceso PowerShell hijo con Volatility2, se puede extraer el payload: un script PowerShell ofuscado con base64 que, al decodificarse y descomprimirse con zlib, revela la flag en texto UTF-16LE.

---

## Extracción y reconocimiento

```bash
unzip -P 'hackthebox' a12c735c-3ec5-414e-b703-95cf1f14e2f9.zip -d "reminiscent"
cd reminiscent

ls -la
# flounder-pc-memdump.elf    543 MB  ← volcado de memoria principal
# imageinfo.txt              → perfiles recomendados por Volatility
# Resume.eml                 → email malicioso (vector de infección)

cat imageinfo.txt
# Suggested Profile(s): Win7SP0x64, Win7SP1x64, Win2008R2SP0x64, Win2008R2SP1x64
```

```bash
# Ver el correo malicioso
cat Resume.eml
# From: spooky@malicious.htb
# Subject: [HTB] Chief Investigative Officer Application
# Body: "Please see my attached resume..."
# (Adjunto: enlace o .hta malicioso)
```

---

## Análisis del árbol de procesos

```bash
python2 vol.py -f flounder-pc-memdump.elf --profile=Win7SP1x64 pstree
```

```
Name                            Pid  PPid
0xfffffa801b27e060:explorer.exe  1396   1332
. 0xfffffa801b486b30:thunderbird.ex 2812   1396
.. 0xfffffa801a4c5b30:powershell.exe  496   2812
... 0xfffffa801a4e3870:powershell.exe  2752    496
```

La cadena `thunderbird.exe` → `powershell.exe (PID 496)` → `powershell.exe (PID 2752)` es una firma de malware entregado por email:
1. El usuario abrió el adjunto en Thunderbird.
2. El adjunto ejecutó PowerShell (posiblemente vía `.hta` o script de Office).
3. El primer PowerShell descargó y ejecutó un segundo PowerShell con el payload real.

---

## Volcado de memoria del proceso malicioso

```bash
mkdir dumped/
python2 vol.py -f flounder-pc-memdump.elf --profile=Win2008R2SP1x64 \
    memdump -p 2752 -D dumped/
```

```
************************************************************************
Writing powershell.exe [2752] memory to file [dumped/2752.dmp]
```

El perfil `Win2008R2SP1x64` funciona mejor que `Win7SP1x64` para este volcado específico.

---

## Extracción del payload PowerShell

```bash
strings -a dumped/2752.dmp | grep -E "^[A-Za-z0-9+/]{50,}={0,2}$" | \
    while IFS= read -r line; do
        decoded=$(echo "$line" | base64 -d 2>/dev/null | \
            python3 -c "
import sys, zlib
data = sys.stdin.buffer.read()
try:
    dec = zlib.decompress(data, -15)
    text = dec.decode('utf-16le', errors='ignore')
    if 'HTB' in text or 'function' in text.lower() or 'powershell' in text.lower():
        print(text[:500])
except:
    pass
" 2>/dev/null)
        [ -n "$decoded" ] && echo "--- Match ---" && echo "$decoded" && break
    done
```

El script busca en el volcado de memoria strings que parezcan base64, los decodifica, intenta descomprimir con deflate raw (`zlib.decompress(data, -15)`) y decodifica el resultado como UTF-16LE (el encoding nativo de PowerShell). La flag aparece en el texto descomprimido.

---

## Análisis del script descomprimido

El payload descomprimido es un script PowerShell que:

1. **Descarga** un payload adicional desde una URL hardcoded.
2. **Carga** el payload en memoria (sin escribirlo a disco).
3. **Ejecuta** el shellcode usando reflexión de .NET.

La flag aparece como parte del script — posiblemente como un comentario de desarrollo o como una cadena de identificación del implante que el operador incluyó para validar la ejecución:

```
HTB{FLAG}
```

---

## Cadena de Infección

```text
1. Resume.eml recibido en Thunderbird (spooky@malicious.htb)
       ↓
2. Usuario abre el adjunto malicioso (.hta / .js / macro)
       ↓
3. Thunderbird (PID 2812) spawn → powershell.exe (PID 496)
       ↓
4. Primer PowerShell: descarga payload → decode base64 → inflate
       ↓
5. Segundo PowerShell (PID 2752): ejecuta el payload en memoria
       ↓
6. Volatility memdump (PID 2752) → strings → base64 → zlib → UTF-16LE → flag
```

---

## Por qué UTF-16LE en PowerShell

PowerShell usa UTF-16LE (Little Endian) como encoding interno para strings, ya que .NET (en el que está basado) usa Unicode internamente. Cuando PowerShell pasa un string a `[Convert]::FromBase64String()` y luego lo descomprime, el resultado es un array de bytes en UTF-16LE. Esto no es una técnica de ofuscación — es simplemente el encoding nativo. Pero descodificarlo como UTF-8 produce garbage, lo que puede confundir herramientas de análisis automático.

El parámetro `-15` en `zlib.decompress(data, -15)` indica a Python que use deflate raw sin cabecera zlib — el formato que usa PowerShell/C# (`DeflateStream` de .NET).

---

## Comandos Volatility útiles para este tipo de análisis

```bash
# Ver procesos activos
python2 vol.py -f <dump> --profile=<profile> pslist

# Árbol de procesos (muestra relaciones padre-hijo)
python2 vol.py -f <dump> --profile=<profile> pstree

# Líneas de comando de cada proceso (¡incluye argumentos de PowerShell!)
python2 vol.py -f <dump> --profile=<profile> cmdline

# Conexiones de red activas al momento del dump
python2 vol.py -f <dump> --profile=<profile> netscan

# Volcar memoria de un proceso específico
python2 vol.py -f <dump> --profile=<profile> memdump -p <PID> -D ./dump/
```

---

## Lecciones Aprendidas

- **Thunderbird → PowerShell = red flag**: un proceso de email cliente que spawna un intérprete de comandos es una de las firmas más claras de ejecución de macro o script malicioso. Monitorizar con reglas de Sysmon o EDR.
- **Base64 + zlib + UTF-16LE**: esta combinación es la que PowerShell usa con el parámetro `-enc` (EncodedCommand). Reconocerla acelera el análisis.
- **`memdump` vs `procdump`**: `memdump` vuelca toda la memoria virtual del proceso (incluyendo heaps, stacks, DLLs mapeadas); `procdump` solo el ejecutable en memoria. Para buscar strings y payloads, usar `memdump`.
- **`strings -a`**: el flag `-a` (all sections) fuerza a strings a escanear todo el binario, incluyendo secciones no ejecutables donde suelen residir los payloads descomprimidos.

---

## Referencias

- [Volatility2 — GitHub](https://github.com/volatilityfoundation/volatility)
- [HackTricks — Memory Forensics](https://book.hacktricks.xyz/forensics/basic-forensic-methodology/memory-dump-analysis)
- [MITRE ATT&CK — Phishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [PowerShell -EncodedCommand](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe)
