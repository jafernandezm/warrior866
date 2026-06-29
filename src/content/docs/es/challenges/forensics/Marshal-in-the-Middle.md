---
title: "Marshal in the Middle"
description: "Writeup de Marshal in the Middle - Hack The Box - Forensics 200pts. Logs de Zeek + pcapng con secrets.log TLS keylog; tshark descifra tráfico HTTPS hacia pastebin.com; el POST más grande contiene tarjetas de crédito robadas y la flag embebida en el dataset."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - zeek
  - pcap
  - tshark
  - tls
  - https
  - pastebin
  - keylog
  - mitm
---

# Marshal in the Middle

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 200
> 👤 Autor: warrior866

---

## Descripción

El ZIP contiene logs de Zeek (`bro/`), un archivo de captura de red (`chalcap.pcapng`) y un `secrets.log` — un archivo de claves de sesión TLS en formato SSLKEYLOGFILE. Zeek y tshark pueden usar este keylog para descifrar el tráfico HTTPS capturado. La IP interna `10.10.20.13` realiza consultas DNS a `pastebin.com` y luego hace tres POSTs a la API de Pastebin para exfiltrar datos robados. El tercer POST (el más grande) contiene miles de tarjetas de crédito American Express, con la flag embebida como una entrada más en el dataset.

---

## Extracción y reconocimiento inicial

```bash
unzip -o -P 'hackthebox' a12c7336-0225-4805-98f8-e98056ce0ebb.zip -d "marshal-in-the-middle"
cd marshal-in-the-middle

ls -R
# bro/conn.log  bro/dns.log  bro/files.log  bro/http.log
# bro/ssl.log   bro/weird.log  bro/packet_filter.log
# bundle.pem  chalcap.pcapng  secrets.log
```

El archivo `secrets.log` es el artefacto clave — contiene las claves de sesión TLS negociadas durante la captura, lo que permite descifrar el tráfico HTTPS retroactivamente.

---

## Análisis de logs Zeek: identificación de la IP sospechosa

```bash
# Ver qué dominios consultó la IP 10.10.20.13
cat bro/dns.log | awk -F'\t' '$3 == "10.10.20.13" { printf "%s\t%s\n", $14, $10 }' | sort | uniq -c | sort -bnr
#       3 A       pastebin.com
#       3 AAAA    pastebin.com
#       1 PTR     14.20.10.10.in-addr.arpa
#       1 A       mysql-m1.prod.htb
```

`10.10.20.13` hace 3 resoluciones de `pastebin.com` — señal de posible exfiltración de datos.

---

## Descifrado del tráfico HTTPS con tshark

```bash
# Filtrar tráfico HTTP de 10.10.20.13 usando el SSLKEYLOGFILE
tshark -2 -R "ip.src==10.10.20.13 and http" \
    -o 'tls.keylog_file:./secrets.log' \
    -r chalcap.pcapng
```

```
1  170.203546  10.10.20.13 → 104.20.208.21  POST /api/api_post.php (1804 bytes)
2  186.485524  10.10.20.13 → 104.20.209.21  POST /api/api_post.php (1278 bytes)
3  237.038819  10.10.20.13 → 104.20.208.21  POST /api/api_post.php (6855 bytes)
```

Tres POSTs a la API de Pastebin. El tercero (6855 bytes) es el más grande y el más interesante.

---

## Extracción del contenido del POST grande

```bash
tshark -2 -R "ip.src==10.10.20.13 and http and frame.len==6855" \
    -T fields -e http.file_data \
    -o 'tls.keylog_file:./secrets.log' \
    -r chalcap.pcapng \
    | python3 -c "import sys; print(bytes.fromhex(sys.stdin.read().strip()).decode('utf-8', errors='replace'))"
```

```
api_user_key=ed67c1aec48d47270dd002d0baa29814&api_dev_key=bb8aa307a7d4b6073976149b65977bae&api_paste_private=2&api_option=paste&api_paste_code=IssuingNetwork,CardNumber
American Express,345806846723249
American Express,345390632937883
...
HTB{FLAG}
...
American Express,343588840524078
```

La flag aparece embebida entre las entradas de tarjetas de crédito como una línea más del dataset exfiltrado.

---

## Cadena de Ataque

```text
1. IP 10.10.20.13 consulta DNS → pastebin.com (×3)
       ↓
2. Establece sesión TLS con Pastebin (capturada en chalcap.pcapng)
       ↓
3. POST /api/api_post.php con api_paste_code = dataset de tarjetas robadas
       ↓
4. Tercer POST (6855 bytes) contiene ~100 tarjetas + flag embebida
       ↓
5. tshark + secrets.log → descifra TLS → extrae flag
```

---

## Por qué funciona el SSLKEYLOGFILE

Los navegadores modernos y algunas aplicaciones pueden configurarse para escribir las claves de sesión TLS en un archivo (`SSLKEYLOG_FILE` env variable). Este archivo no contiene la clave privada del servidor — solo las claves de sesión simétricas negociadas durante el handshake. Si se capturó el handshake TLS en el pcap, y se tiene el SSLKEYLOGFILE de esa sesión, se puede descifrar el tráfico cifrado de forma retroactiva. Wireshark y tshark lo soportan nativamente.

---

## Lecciones Aprendidas

- **SSLKEYLOGFILE como artefacto forense**: en entornos corporativos con proxies de inspección TLS o EDRs avanzados, las claves de sesión pueden registrarse automáticamente. En análisis forense, siempre buscar archivos `*.log` de claves TLS.
- **Pastebin como canal de exfiltración**: la API de Pastebin es un vector clásico de exfiltración — parece tráfico legítimo y no bloquea por defecto muchos firewalls. Monitorizar POSTs a `pastebin.com/api/`.
- **Logs de Zeek para triage**: Zeek genera logs estructurados por protocolo. `dns.log` revela rápidamente qué dominios resolvió cada IP interna sin necesitar descifrar el tráfico.
- **`--assume-clean` en mdadm**: los archivos de captura completos a veces incluyen artefactos de análisis como el SSLKEYLOGFILE que el usuario guardó junto con la captura.

---

## Referencias

- [NSS Key Log Format](https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html)
- [Wireshark — TLS decryption](https://wiki.wireshark.org/TLS#using-the-pre-master-secret)
- [Pastebin API](https://pastebin.com/doc_api)
- [Zeek Network Monitor](https://zeek.org/)
