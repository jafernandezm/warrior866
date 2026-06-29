---
title: "Obscure"
description: "Writeup de Obscure - Hack The Box - Forensics 260pts. pcap + webshell PHP con XOR+gzip; descifrar tráfico C2 revela exfiltración de base de datos KeePass; crackear con john (rockyou) y abrir con keepassxc-cli da la flag."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - pcap
  - tshark
  - php-webshell
  - xor
  - gzip
  - keepass
  - john
  - keepassxc-cli
---

# Obscure

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 260
> 👤 Autor: warrior866

---

## Descripción

Se entregan tres archivos: `19-05-21_22532255.pcap`, `support.php` (webshell PHP) y `to-do.txt`. El pcap captura tráfico HTTP entre un atacante y un servidor comprometido. Hay que descifrar el tráfico de C2 para recuperar la flag de una base de datos KeePass exfiltrada.

---

## Análisis inicial del pcap

```bash
tshark -r 19-05-21_22532255.pcap -q -z io,phs
```

```text
frame     frames:469 bytes:517183
  sll → ip → tcp
    http    frames:52 bytes:46419
```

```bash
tshark -r 19-05-21_22532255.pcap -Y "http.request" -T fields \
  -e ip.src -e http.request.method -e http.request.uri
```

```text
66.249.81.77    GET   /upload.php          ← Googlebot
23.129.64.207   POST  /uploads/support.php ← atacante (×4)
195.181.160.247 GET   /                    ← navegación legítima
```

El atacante (`23.129.64.207`) usa `support.php` como webshell C2.

---

## Esquema de cifrado de la webshell

Leyendo `support.php`, el esquema de cifrado es:
- **Codificación**: `base64(xor(gzcompress(output), key))`
- **Decodificación**: `gzuncompress(xor(base64_decode(input), key))`
- **Clave XOR**: `80e32263` (hardcodeada en el PHP)

---

## Identificar streams del atacante

```bash
tshark -r 19-05-21_22532255.pcap \
  -Y "ip.src == 23.129.64.207" -T fields -e tcp.stream | sort -u
```

```text
1  23  24  25
```

---

## Script de descifrado

```python
import base64, zlib

KEY = "80e32263"

def xor_crypt(data, key):
    key = key.encode()
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def decrypt(response):
    pad = "=" * (-len(response) % 4)
    decoded = base64.b64decode(response + pad)
    decrypted = xor_crypt(decoded, KEY)
    return zlib.decompress(decrypted).decode()

# Respuestas (parte después del prefijo de sesión en cada stream)
streams = {
    "Stream 1":  "QKxO/n6DAwXuGEoc5X9/H3HkMXv1Ih75Fx1NdSPRNDPUmHTy",
    "Stream 23": "QKzo43k49AMoNoVOfAMh+6h3eu...RZKQ==",
    "Stream 24": "QKy2/Pr9e+Z3eUh4//sZexUyZR8mN/g=",
    "Stream 25": "QKxIp/Wcsms0dFq7N4u3..."  # base64 del kdbx
}

for name, data in streams.items():
    print(f"\n[{name}]:\n{decrypt(data)}")
```

**Resultados:**

```text
[Stream 1]:
uid=33(www-data) gid=33(www-data) groups=33(www-data)

[Stream 23]:
drwxr-xr-x developer developer 4.0K May 21 20:37 .
-rw-r--r-- developer developer 1.6K May 21 20:37 pwdb.kdbx

[Stream 24]:
/home/developer

[Stream 25]:
(binario base64 de pwdb.kdbx — base de datos KeePass exfiltrada)
```

El atacante ejecutó `whoami`, enumeró `/home/developer` (encontró `pwdb.kdbx`), y exfiltró la base de datos KeePass en el stream 25.

---

## Crackear la base de datos KeePass

Reconstruir el `.kdbx` y crackear con John:

```bash
# Guardar el base64 del stream 25 en pwdb.txt
cat pwdb.txt | base64 -d > pass.kdbx

# Extraer hash para john
keepass2john pass.kdbx > hash.txt

# Fuerza bruta con rockyou
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

```text
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
chainsaw  (pass)
1g 0:00:00:03 DONE — 0.3278g/s 7050p/s
Session completed.
```

Contraseña maestra: **`chainsaw`**

---

## Flag en la entrada KeePass

```bash
keepassxc-cli show -s pass.kdbx "Passwords/Flag"
```

```text
Enter password to unlock pass.kdbx: chainsaw

Title: Flag
UserName: artikrh
Password: HTB{FLAG}
URL: https://github.com/epinna/weevely3
```

La URL apunta a Weevely — la webshell usada originalmente (aunque el pcap muestra una versión personalizada con XOR).

---

## Cadena de Ataque

```text
1. pcap → 4 POST a /uploads/support.php desde 23.129.64.207
       ↓
2. Analizar support.php → esquema XOR(key=80e32263) + gzip + base64
       ↓
3. Seguir streams TCP 1, 23, 24, 25 → extraer payloads cifrados
       ↓
4. Descifrar → whoami, ls /home/developer, pwd, contenido kdbx (base64)
       ↓
5. cat pwdb.txt | base64 -d > pass.kdbx
       ↓
6. keepass2john + john + rockyou → chainsaw
       ↓
7. keepassxc-cli show → Passwords/Flag → flag
```

---

## Lecciones Aprendidas

- **Webshells con C2 cifrado**: la webshell `support.php` cifra comandos y respuestas, dificultando la detección por contenido. Para detectar: anomalías en el payload (muchos caracteres base64 en POST), user-agent inusual, comportamiento de respuesta uniforme.
- **XOR con clave corta**: XOR con clave de 8 bytes es débil — dado suficiente ciphertext y conocimiento del esquema, se puede recuperar la clave o los datos. Usar cifrado real (AES).
- **KeePass como objetivo de exfiltración**: los `.kdbx` son objetivos de alto valor. El atacante identificó `pwdb.kdbx` en el home del usuario. Master passwords débiles hacen que la exfiltración de la BD sea equivalente a exponer todas las contraseñas.

---

## Referencias

- [Weevely — PHP webshell](https://github.com/epinna/weevely3)
- [keepass2john](https://github.com/openwall/john/blob/bleeding-jumbo/src/keepass2john.c)
- [MITRE ATT&CK — T1560 Archive Collected Data](https://attack.mitre.org/techniques/T1560/)
