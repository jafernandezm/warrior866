---
title: "No Place To Hide"
description: "Writeup de No Place To Hide - Hack The Box - Forensics 200pts. Caché de bitmaps RDP (Cache0000.bin); bmc-tools extrae 1162 tiles BMP; inspeccionando visualmente los tiles relevantes con catimg se reconstruye la flag fragmentada en piezas de sesión RDP."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - rdp
  - bitmap-cache
  - bmc-tools
  - visual-forensics
  - catimg
---

# No Place To Hide

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 200
> 👤 Autor: warrior866

---

## Descripción

RDP (Remote Desktop Protocol) usa un sistema de caché de bitmaps para optimizar el ancho de banda: las porciones de pantalla que no cambian no se retransmiten, sino que se almacenan en caché en el cliente. El reto proporciona dos archivos de caché RDP (`bcache24.bmc` y `Cache0000.bin`). La herramienta `bmc-tools` permite extraer los tiles individuales en formato BMP. La flag está distribuida visualmente entre varios tiles que representan fragmentos de la sesión RDP capturada — hay que identificar los tiles con texto legible y ordenarlos para reconstruir la flag.

---

## Análisis inicial de los archivos

```bash
7z x archivo.zip -p"hackthebox" -o"no-place-to-hide"
cd no-place-to-hide

ls -la
# bcache24.bmc    (0 bytes — vacío)
# Cache0000.bin   (17 MB — datos de caché RDP)

file Cache0000.bin
# Cache0000.bin: data

du -h Cache0000.bin bcache24.bmc
# 18M   Cache0000.bin
# 0     bcache24.bmc
```

El archivo `bcache24.bmc` está vacío; el archivo `Cache0000.bin` contiene la caché de bitmaps activa.

---

## Extracción de tiles con bmc-tools

```bash
git clone https://github.com/anssi-fr/bmc-tools
python3 bmc-tools/bmc-tools.py -s Cache0000.bin -d .
```

```
[+++] Processing a single file: 'Cache0000.bin'.
[===] 1162 tiles successfully extracted in the end.
[===] Successfully exported 1162 files.
```

Se extraen **1162 tiles** BMP de la caché. Cada tile es un fragmento de 64×64 píxeles de la pantalla RDP de la sesión capturada.

---

## Búsqueda de tiles con la flag

Con 1162 tiles, hay que identificar cuáles contienen texto legible. La estrategia es usar `catimg` para previsualizar tiles en la terminal, empezando por los índices más recientes (suelen ser los más relevantes):

```bash
# Revisar tiles numerados — los últimos tiles suelen ser los más recientes
catimg Cache0000.bin_1038.bmp
# Muestra: "HTB"

catimg Cache0000.bin_1039.bmp
# Muestra: "{w4"

catimg Cache0000.bin_1069.bmp
# Muestra: "{w47ch_y"

catimg Cache0000.bin_1068.bmp
# (fragmento adicional)

catimg Cache0000.bin_1149.bmp
# Muestra: "3C71}"

catimg Cache0000.bin_1151.bmp
# Muestra: "0ur_c0Nn"
```

---

## Reconstrucción de la flag

Los tiles contienen los fragmentos de texto que aparecían en la pantalla durante la sesión RDP. Ordenando los fragmentos visibles:

| Tile | Contenido |
|------|-----------|
| _1038 | `HTB` |
| _1039 | `{w4` |
| _1069 | `{w47ch_y` (repetición/confirmación) |
| _1151 | `0ur_c0Nn` |
| _1149 | `3C71}` |

Ensamblando: `HTB{w47ch_y0ur_c0Nn3C71}` → **HTB{FLAG}**

---

## Cadena de Ataque (perspectiva del analista)

```text
1. Examinar archivos: bcache24.bmc (vacío), Cache0000.bin (17 MB)
       ↓
2. bmc-tools -s Cache0000.bin → 1162 tiles BMP extraídos
       ↓
3. Revisar tiles numerados con catimg → identificar fragmentos de texto
       ↓
4. Concentrarse en tiles del rango 1038-1161 (más recientes)
       ↓
5. Leer y ordenar los fragmentos → reconstruir la flag
```

---

## Por qué existe la caché de bitmaps RDP

El protocolo RDP implementa caché de bitmaps para reducir el ancho de banda: cuando una porción de pantalla se repite (iconos, texto estático, fondos), el cliente la guarda localmente y el servidor solo envía un código de referencia. Esto hace que la caché contenga "fotografías" de todo lo que apareció en pantalla durante la sesión, incluyendo texto, contraseñas visibles, archivos abiertos, etc. Es una fuente de información forense muy valiosa.

---

## Lecciones Aprendidas

- **Caché RDP como artefacto forense**: los archivos `*.bmc` y `Cache*.bin` en `%APPDATA%\Microsoft\Terminal Server Client\Cache\` pueden revelar el contenido visual de sesiones RDP anteriores incluso sin acceso a logs.
- **bmc-tools**: herramienta de referencia del ANSSI para analizar cachés de bitmaps RDP. Extrae tiles individuales como BMP que pueden visualizarse con cualquier visor.
- **Tiles no ordenados**: el orden de los tiles en la caché no corresponde al orden en pantalla — hay que revisar visualmente para identificar los relevantes.
- **Información sensible en caché**: contraseñas tecleadas, documentos abiertos, terminales con comandos — todo puede quedar capturado en la caché de bitmaps.

---

## Referencias

- [bmc-tools — ANSSI](https://github.com/ANSSI-FR/bmc-tools)
- [RDP Bitmap Cache forensics](https://rdpbitmapcache.wordpress.com/)
- [HackTricks — RDP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-rdp)
