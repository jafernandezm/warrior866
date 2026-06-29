---
title: "Persistence"
description: "Writeup de Persistence - Hack The Box - Forensics 200pts. Análisis de hive de registro Windows (NTUSER.DAT); clave Run contiene ejecutable con nombre en base64 que decodifica a la flag."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - windows
  - registry
  - regipy
  - base64
  - persistence
  - run-key
---

# Persistence

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 200
> 👤 Autor: warrior866

---

## Descripción

El reto describe conexiones maliciosas que se reestablecen tras reiniciar el sistema, incluso después de que el antivirus borra los archivos. Se entrega un ZIP con un fichero `query` — un hive de registro Windows. Hay que encontrar el mecanismo de persistencia.

---

## Identificación del artefacto

```bash
unzip a12c73a9-dfb3-4705-bf1e-d2359bdf7362.zip -d persistence
file persistence/query
```

```text
persistence/query: MS Windows registry file, NT/2000 or above
```

El fichero `query` es un hive NTUSER.DAT (registro de perfil de usuario de Windows).

---

## Análisis del hive con regipy

El contexto del reto apunta a persistencia en la clave `Run`. Con Python y `regipy` se puede recorrer el hive buscando valores que apunten a ejecutables o recursos externos:

```python
from regipy.registry import RegistryHive

hive = RegistryHive('persistence/query')

def walk(key, path=""):
    full = f"{path}\\{key.name}" if path else key.name
    try:
        for val in key.get_values():
            v = str(val.value)
            if any(x in v.lower() for x in ['exe', 'cmd', 'powershell', 'http', 'run']):
                print(f"[{full}]")
                print(f"  {val.name} = {v}")
    except:
        pass
    try:
        for sk in key.iter_subkeys():
            walk(sk, full)
    except:
        pass

walk(hive.root)
```

Salida relevante:

```text
[ROOT\Software\Microsoft\Windows\CurrentVersion\Run]
  Windows Update = C:\Windows\System32\SFRCezFfQzRuX2t3M3J5XzRMUjE5aDd9.exe
```

La clave `Run` tiene una entrada que finge ser "Windows Update" pero apunta a un ejecutable con nombre sospechoso: `SFRCezFfQzRuX2t3M3J5XzRMUjE5aDd9.exe`. El patrón de caracteres base64 es inmediato.

---

## Decodificar el nombre del ejecutable

```bash
echo "SFRCezFfQzRuX2t3M3J5XzRMUjE5aDd9" | base64 -d
```

```text
HTB{FLAG}
```

La flag está codificada en base64 como el nombre del ejecutable malicioso de persistencia.

---

## Contexto del ataque

El atacante estableció persistencia via `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`:
- Clave: `Windows Update` (nombre engañoso para evitar sospechas).
- Valor: ruta a un binario cuyo nombre en sí mismo es la flag codificada.
- El AV podía borrar el binario del disco, pero la clave del registro permanecía, y el binario se recreaba en cada reinicio (probablemente desde un dropper en red o tarea programada adicional).

---

## Cadena de Análisis

```text
1. Extraer ZIP → fichero query (hive NTUSER.DAT)
       ↓
2. file query → MS Windows registry file
       ↓
3. regipy → recorrer hive buscando exe/cmd/powershell
       ↓
4. HKCU\...\CurrentVersion\Run → "Windows Update" → SFRCezFfQzRuX2t3M3J5XzRMUjE5aDd9.exe
       ↓
5. base64 -d → flag
```

---

## Lecciones Aprendidas

- **Run keys como persistencia clásica**: `HKCU\...\CurrentVersion\Run` y `HKLM\...\CurrentVersion\Run` son los vectores de persistencia más comunes en Windows. Siempre revisar en análisis forense.
- **Nombres de fichero en base64**: los atacantes usan names ofuscados para evitar detección por nombre de fichero. Los nombres que contienen solo caracteres base64 válidos (`A-Za-z0-9+/=`) son sospechosos.
- **regipy**: herramienta Python para parsear hives de registro sin necesitar una VM Windows. Alternativa: `regripper`, `reg.exe export` + análisis manual.

---

## Referencias

- [regipy — GitHub](https://github.com/mkorman90/regipy)
- [MITRE ATT&CK — T1547.001 Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)
- [HackTricks — Windows Persistence](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries)
