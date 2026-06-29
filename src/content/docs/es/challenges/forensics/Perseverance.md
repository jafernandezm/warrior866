---
title: "Perseverance"
description: "Writeup de Perseverance - Hack The Box - Forensics 200pts. Repositorio WMI (OBJECTS.DATA) con persistencia maliciosa; PyWMIPersistenceFinder o flare-wmi revelan un CommandLineEventConsumer con PowerShell -enc; el payload base64 se descomprime con zlib y contiene la flag en otro string base64."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - wmi
  - persistence
  - powershell
  - base64
  - zlib
  - windows
  - flare-wmi
---

# Perseverance

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 200
> 👤 Autor: warrior866

---

## Descripción

El ZIP contiene los archivos del repositorio WMI de Windows: `INDEX.BTR`, `MAPPING1.MAP`, `MAPPING2.MAP`, `MAPPING3.MAP` y `OBJECTS.DATA`. WMI (Windows Management Instrumentation) es uno de los mecanismos de persistencia más sofisticados en Windows: el atacante registra un `CommandLineEventConsumer` que ejecuta un comando cuando ocurre un evento específico. En este caso, el evento dispara cada 60 segundos cuando el sistema lleva entre 120 y 325 segundos activo. El payload es un comando PowerShell con `-enc BASE64`, cuya cadena base64 al decodificarse y descomprimirse contiene otro base64 que revela la flag.

---

## Extracción y herramientas

```bash
unzip -P 'hackthebox' a12c7392-07e5-4fd7-bc6b-e782c02c5b7e.zip -d "perseverance"
cd perseverance

ls -la
# INDEX.BTR      5.1 MB
# MAPPING1.MAP    78 KB
# MAPPING2.MAP    78 KB
# MAPPING3.MAP    77 KB
# OBJECTS.DATA    23 MB
```

**Opción A — PyWMIPersistenceFinder** (más legacy, requiere Python 2):

```bash
git clone https://github.com/davidpany/WMI_Forensics.git
python2 WMI_Forensics/PyWMIPersistenceFinder.py OBJECTS.DATA
```

**Opción B — flare-wmi** (herramienta moderna de FireEye/Mandiant):

```bash
git clone https://github.com/fireeye/flare-wmi.git
python3 flare-wmi/samples/show_filtertoconsumerbindings.py win7 ./
```

---

## Bindings WMI encontrados

Ambas herramientas revelan dos bindings:

```
1. SCM Event Log Consumer-SCM Event Log Filter
   → Consumer: NTEventLogEventConsumer ~ SCM Event Log Consumer
   → Filter: select * from MSFT_SCMEventLogEvent
   → (Binding legítimo del sistema)

2. Windows Update-Windows Update
   → Consumer: CommandLineEventConsumer
   → Arguments: cmd /C powershell.exe -Sta -Nop -Window Hidden -enc JABmAG...
   → Filter: SELECT * FROM __InstanceModificationEvent WITHIN 60
             WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'
             AND TargetInstance.SystemUpTime >= 120
             AND TargetInstance.SystemUpTime < 325
```

El segundo binding se llama "Windows Update" para camuflarse como legítimo, pero el `CommandLineEventConsumer` ejecuta PowerShell con un payload base64 ofuscado. El trigger es un evento de modificación del objeto de rendimiento del SO cada 60 segundos.

---

## Decodificación del payload multi-capa

El payload base64 en el argumento de PowerShell es demasiado largo para extraerse manualmente. Se extrae del binario y se descodifica:

```bash
# Buscar el string base64 en OBJECTS.DATA (comienza con "7Vp9cFzVdT")
strings OBJECTS.DATA | grep "7Vp9cFzVdT" | head -1 > base64.txt

# Decodificar base64 → descomprimir deflate raw → decodificar UTF-16LE
cat base64.txt | base64 -d | python3 -c "
import sys, zlib
data = sys.stdin.buffer.read()
decompressed = zlib.decompress(data, -15)   # -15 = deflate raw sin cabecera
print('Longitud en bytes:', len(decompressed))
print(decompressed.decode('utf-16le', errors='replace'))
"
```

El resultado es un blob de bytes que corresponde a un **ensamblado .NET**. Dentro del ensamblado se encuentra la propiedad `Property` del objeto `Win32_MemoryArrayDevice` con un segundo string base64:

```
SFRCezFfdGgwdWdodF9XTTFfdzRzX2p1c3RfNF9NNE40ZzNtM250X1QwMGx9
```

---

## Extracción de la flag

```bash
echo "SFRCezFfdGgwdWdodF9XTTFfdzRzX2p1c3RfNF9NNE40ZzNtM250X1QwMGx9" | base64 -d
```

```text
HTB{FLAG}
```

---

## Arquitectura del mecanismo de persistencia WMI

```text
1. Atacante gana ejecución inicial en Windows
       ↓
2. Registra en el repositorio WMI (OBJECTS.DATA):
   - __EventFilter: dispara cada 60s cuando SystemUpTime está entre 120-325s
   - CommandLineEventConsumer: ejecuta cmd /C powershell.exe -enc [BASE64]
   - __FilterToConsumerBinding: enlaza filtro → consumidor ("Windows Update")
       ↓
3. En cada reinicio: 2-5 minutos después, WMI dispara el comando PowerShell
       ↓
4. PowerShell: base64 → zlib.decompress → load .NET assembly → execve
       ↓
5. Persistencia silenciosa, sin archivos en disco, solo en OBJECTS.DATA
```

---

## WMI como persistencia "fileless"

El repositorio WMI almacena los datos en archivos binarios propietarios (`OBJECTS.DATA`, `INDEX.BTR`, `MAPPING*.MAP`). Los scripts de PowerShell no se escriben en disco — el payload existe solo dentro de la base de datos WMI. Esto hace que:
- Los antivirus que escanean el sistema de archivos no lo detecten.
- Sobreviva a limpiezas manuales del directorio de archivos.
- Sea persistente a través de reinicios sin modificar el registro ni el directorio Startup.

---

## Lecciones Aprendidas

- **WMI como vector de persistencia avanzado (APT)**: grupos como APT29, Carbanak y FIN6 han usado WMI extensively. Detectar con `Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding`.
- **Dos capas de codificación**: base64 → deflate → ensamblado .NET → base64 de la flag. Cada capa añade fricción al análisis.
- **`strings` como primer triage**: incluso en binarios WMI, `strings OBJECTS.DATA` permite localizar payloads base64 por sus características visuales.
- **flare-wmi vs PyWMIPersistenceFinder**: flare-wmi es más moderno y activo; PyWMIPersistenceFinder es Python 2 pero sigue siendo válido para entornos legacy.

---

## Referencias

- [WMI Forensics — FireEye whitepaper](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf)
- [flare-wmi — GitHub](https://github.com/fireeye/flare-wmi)
- [WMI_Forensics — PyWMIPersistenceFinder](https://github.com/davidpany/WMI_Forensics)
- [MITRE ATT&CK — Windows Management Instrumentation Event Subscription](https://attack.mitre.org/techniques/T1546/003/)
