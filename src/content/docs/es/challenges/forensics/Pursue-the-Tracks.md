---
title: "Pursue the Tracks"
description: "Writeup de Pursue the Tracks - Hack The Box - Forensics 200pts. Archivo z.mft (NTFS Master File Table); analyzeMFT.py convierte la MFT a CSV; csvcut permite consultar archivos por nombre, timestamps y tamaño para responder preguntas del servidor netcat."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - ntfs
  - mft
  - analyzeMFT
  - windows
  - filesystem
  - csv
---

# Pursue the Tracks

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 200
> 👤 Autor: warrior866

---

## Descripción

El ZIP contiene `z.mft`, identificado por `file` como "data" — es la Master File Table (MFT) de una partición NTFS. La MFT es el directorio central de NTFS: cada archivo y directorio tiene un registro de 1 KB que almacena nombre, timestamps, atributos y la lista de clusters (VCN) donde están los datos. `analyzeMFT` parsea la MFT y genera un CSV que permite buscar archivos por nombre, fecha de creación/modificación, tamaño y número de record. El servidor netcat del reto hace preguntas sobre los metadatos de archivos específicos.

---

## Extracción y reconocimiento

```bash
unzip -P 'hackthebox' a12c7341-f048-4e9e-9524-18ce680e3a9f.zip -d "pursue-the-tracks"
cd pursue-the-tracks

file z.mft
# z.mft: data

wc -c z.mft
# 6291456 bytes (6 MB — tamaño típico de una MFT pequeña-mediana)
```

---

## Parseo de la MFT con analyzeMFT

```bash
pip3 install analyzeMFT
# o bien:
git clone https://github.com/rowingdude/analyzeMFT.git
cd analyzeMFT

python3 analyzeMFT.py -f ../z.mft -o ../mft_output.csv --csv
cd ..

wc -l mft_output.csv
# 1537 registros (cada uno = un archivo o directorio)
```

El CSV tiene columnas como `Record Number`, `Full Path`, `Filename`, `$SI Creation Time`, `$FN Creation Time`, `$SI Modification Time`, `Active`, `Last VCN`, entre otras.

---

## Consultas clave con csvcut

```bash
pip3 install csvkit

# Ver todos los nombres de columna
head -1 mft_output.csv | tr ',' '\n' | nl

# Buscar un archivo específico por nombre
csvcut -c "Record Number,Filename,Full Path,$SI Creation Time,$SI Modification Time,Last VCN" mft_output.csv \
    | grep -i "Final_Annual_Report"

# Buscar archivos .xlsx creados en 2023
csvcut -c "Record Number,Filename,$SI Creation Time" mft_output.csv \
    | grep "2023"

# Listar todos los archivos únicos por año
csvcut -c "Filename,$SI Creation Time" mft_output.csv \
    | awk -F, 'NR>1 {split($2, a, "-"); print a[1]}' | sort | uniq -c
```

---

## Respuestas al servidor netcat

```bash
nc 161.35.173.231 32571
```

```
Q: ¿En qué años se crearon archivos? (separados por coma)
> 2023,2024
[+] Correct!

Q: ¿Qué archivo fue creado más recientemente?
> Final_Annual_Report.xlsx
[+] Correct!

Q: ¿Qué archivo fue modificado más recientemente?
> Marketing_Plan.xlsx
[+] Correct!

Q: ¿Cuántos archivos ocultos hay?
> 1
[+] Correct!

Q: ¿Qué archivo sospechoso fue encontrado?
> credentials.txt
[+] Correct!

Q: ¿Qué archivo financiero fue guardado en un directorio diferente?
> Financial_Statement_draft.xlsx
[+] Correct!

Q: ¿Qué PDF fue guardado?
> Project_Proposal.pdf
[+] Correct!

Q: ¿Cuál es el nombre del reporte anual sin "Final"?
> Annual_Report.xlsx
[+] Correct!

Q: ¿Cuántos bytes ocupa el PDF? (basado en Last VCN)
> 57344
[+] Correct!

[+] HTB{FLAG}
```

---

## Cálculo del tamaño por Last VCN

La pregunta sobre los bytes del PDF requiere entender cómo NTFS almacena los datos en clusters:

```bash
csvcut -c "Record Number,Filename,Last VCN" mft_output.csv | grep -i "Project_Proposal.pdf"
# Record 40: Final_Project_Proposal.pdf, Last VCN = 13
```

El tamaño se calcula como:

```
tamaño = (Last_VCN + 1) × cluster_size
tamaño = (13 + 1) × 4096 = 14 × 4096 = 57344 bytes
```

El tamaño de cluster estándar en NTFS es 4096 bytes (4 KB). `Last VCN` es el último Virtual Cluster Number — el número del último cluster asignado al archivo, contando desde 0. Por tanto, el archivo ocupa `Last VCN + 1` clusters.

---

## Estructura de la MFT de NTFS

```text
Partición NTFS
├── $MFT           → La MFT misma (mapeada en sí misma como Record 0)
├── $MFTMirr       → Backup de los primeros 4 records de la MFT (Record 1)
├── $LogFile       → Journal de transacciones NTFS (Record 2)
├── $Volume        → Metadata del volumen (Record 3)
├── Record 0-23    → Archivos del sistema ($Bitmap, $Boot, $BadClus, etc.)
└── Record 24+     → Archivos de usuario
     ├── Record 40  → Final_Project_Proposal.pdf
     ├── Record 45  → Annual_Report.xlsx
     └── ...
```

Cada record de la MFT tiene tamaño fijo de 1 KB y contiene atributos variables-length:
- `$STANDARD_INFORMATION` ($SI): timestamps de acceso, creación, modificación
- `$FILE_NAME` ($FN): nombre del archivo (puede haber múltiples por nombres cortos 8.3)
- `$DATA`: los datos reales (si son pequeños, inline; si no, lista de runs de clusters)

---

## Lecciones Aprendidas

- **La MFT es el corazón de NTFS**: recuperar la MFT de un sistema comprometido o imagen forense permite reconstruir toda la estructura de archivos, incluyendo archivos borrados (cuyos records se marcan como inactivos pero no se sobrescriben).
- **analyzeMFT + csvkit**: la combinación transforma un binario NTFS opaco en datos consultables con herramientas Unix estándar. Útil para analizar miles de archivos rápidamente.
- **VCN para estimar tamaño**: cuando no se puede acceder al archivo directamente, `(Last VCN + 1) × cluster_size` da el tamaño lógico asignado (no necesariamente el tamaño real del contenido).
- **`credentials.txt` como IOC**: un archivo con ese nombre fuera de directorios esperados es una señal clara de exfiltración de credenciales o staging de datos.

---

## Referencias

- [analyzeMFT — GitHub](https://github.com/rowingdude/analyzeMFT)
- [NTFS MFT — Wikipedia](https://en.wikipedia.org/wiki/NTFS#Master_File_Table)
- [csvkit — documentación](https://csvkit.readthedocs.io/)
- [HackTricks — Windows Artifacts](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/windows-artifacts)
