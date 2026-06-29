---
title: "Peel Back The Layers"
description: "Writeup de Peel Back The Layers - Hack The Box - Forensics 200pts. Imagen Docker pública steammaintainer/gearrepairimage; extraer capas tar revela librs.so; radare2 muestra instrucciones movabs con bytes de la flag; el ELF es un reverse shell que envía la flag al conectarse."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - docker
  - tar
  - elf
  - radare2
  - reverse-engineering
  - reverse-shell
  - movabs
---

# Peel Back The Layers

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 200
> 👤 Autor: warrior866

---

## Descripción

Una imagen Docker pública (`steammaintainer/gearrepairimage`) contiene malware en una de sus capas. Después de descargar la imagen, exportarla como tar y extraer las capas individuales, una capa contiene `usr/share/lib/librs.so` — un ELF compilado como shared object pero que en realidad es un reverse shell. El análisis con radare2 revela instrucciones `movabs` que cargan los bytes de la flag directamente en registros como string — la flag se encuentra distribuida en varios `movabs` consecutivos en la función de inicialización del ELF.

---

## Extracción de la imagen Docker

La imagen es pública en Docker Hub y puede descargarse sin credenciales:

```bash
docker pull steammaintainer/gearrepairimage:latest
docker image save steammaintainer/gearrepairimage -o image.tar
tar xf image.tar
ls
# blobs/  index.json  manifest.json  oci-layout
```

El formato OCI (Open Container Initiative) almacena todas las capas bajo `blobs/sha256/` como archivos tar comprimidos.

---

## Identificación de la capa maliciosa

```bash
ls blobs/sha256/
# (múltiples archivos hash sha256)

# Buscar archivos no comprimidos que sean tars con contenido
for f in blobs/sha256/*; do file "$f"; done | grep -v "gzip"
```

Identificar cuáles son capas de filesystem (tar) vs manifiestos (JSON):

```bash
# Extraer la capa sospechosa (la de mayor tamaño suele ser la del OS base)
# Buscar capas que contengan archivos no estándar
for f in blobs/sha256/*; do
    if file "$f" | grep -q "POSIX tar"; then
        echo "=== $f ==="
        tar tf "$f" | grep -v "^\./" | head -20
    fi
done
```

La capa `0a9080e8e7b0e66532e403a406ccdbc7c58fea8493928a3baaf5ca83e2943e26` contiene un archivo sospechoso:

```bash
tar tf blobs/sha256/0a9080... | grep -v "^\./"
# usr/share/lib/librs.so
```

---

## Análisis estático de librs.so

```bash
tar xf blobs/sha256/0a9080e8e7b0e66532e403a406ccdbc7c58fea8493928a3baaf5ca83e2943e26 \
    usr/share/lib/librs.so

file usr/share/lib/librs.so
# ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), not stripped
```

La librería **no está stripped** — los símbolos están disponibles para análisis.

```bash
nm usr/share/lib/librs.so | grep -E "U |T "
```

Las funciones importadas revelan el propósito: `getenv`, `write`, `htons`, `dup2`, `execve`, `inet_addr`, `socket`, `connect`, `fork` — el conjunto clásico de un **reverse shell** que conecta a un host remoto, duplica el socket a stdin/stdout/stderr, y ejecuta una shell.

---

## Análisis con radare2: extracción de la flag

```bash
r2 usr/share/lib/librs.so
```

```r2
[0x00001110]> aaa
[0x00001110]> afl
# sym.imp.getenv  sym.imp.write  sym.imp.htons
# sym.imp.dup2    sym.imp.execve sym.imp.inet_addr
# sym.imp.socket  sym.imp.connect sym.imp.fork
# entry.init1     fcn.00001160

[0x00001110]> pdf @entry.init1
```

La función `entry.init1` (función de inicialización del ELF, equivalente a `__attribute__((constructor))`) contiene la cadena de la flag cargada con instrucciones `movabs`:

```asm
0x000011d7   48b8485442317b425448   movabs rax, 0x33725f317b425448
             ; 'HTB{1_r3'
0x000011e1   48ba346c6c5f796c6c34   movabs rdx, 0x6b316c5f796c6c34
             ; '4lly_l1k'
0x000011f3   48b8335f73745f616d70   movabs rax, 0x706d343374735f33
             ; '3_st34mp'
0x000011fd   48ba756e6b5f72306230   movabs rdx, 0x306230725f6b6e75
             ; 'unk_r0b0'
0x0000120f   48b8747321217d0a0d00   movabs rax, 0x0d0a7d2121217374
             ; 'ts!!!}\n\r'
```

Cada `movabs` carga 8 bytes directamente en un registro. Concatenando los valores ASCII en el orden correcto:

`HTB{1_r3` + `4lly_l1k` + `3_st34mp` + `unk_r0b0` + `ts!!!}` → **HTB{FLAG}**

---

## ¿Qué hace librs.so en tiempo de ejecución?

```r2
[0x00001110]> pdf @fcn.00001160
```

La función principal:
1. `getenv("REMOTE_ADDR")` → dirección IP del C2
2. `getenv("REMOTE_PORT")` → puerto del C2
3. `socket()` → crea socket TCP
4. `connect()` → conecta al C2
5. `write()` → **envía la flag string al C2** (los bytes cargados con los `movabs`)
6. `dup2(sockfd, 0/1/2)` → redirige stdin/stdout/stderr al socket
7. `execve("/bin/sh")` → lanza shell interactiva

Al arrancar el contenedor con las variables `REMOTE_ADDR` y `REMOTE_PORT` configuradas, el malware conecta al servidor del atacante, le envía la flag (como si fuera un "check-in"), y luego entrega una shell interactiva.

---

## Cadena de Ataque

```text
1. Imagen Docker publicada en Docker Hub bajo nombre aparentemente legítimo
       ↓
2. La imagen contiene una capa extra con usr/share/lib/librs.so
       ↓
3. librs.so es un ELF inicializado como .so (se ejecuta al cargar la librería)
       ↓
4. Al arrancar el contenedor: conecta al C2 (REMOTE_ADDR/PORT via env vars)
       ↓
5. Envía string de flag → dup2 + execve → shell reversa al atacante
```

---

## Lecciones Aprendidas

- **Supply chain en Docker Hub**: nombres similares a proyectos legítimos (typosquatting en Hub) pueden distribuir imágenes maliciosas. Siempre usar imágenes oficiales (`docker.io/library/`) o verificar el publisher.
- **Auditoría de capas OCI**: `docker image save` + análisis de capas tar permite inspeccionar cada capa individualmente, incluso sin ejecutar el contenedor. Herramientas como `dive` automatizan este proceso.
- **`movabs` como almacenamiento de strings**: en x86-64, las constantes de 64 bits se cargan con `movabs`. Es una señal de que el compilador incrustó una cadena literal directamente en el código — útil para extracción forense.
- **Funciones de inicialización ELF**: los `entry.init*` de radare2 corresponden a funciones con `__attribute__((constructor))` en C — se ejecutan **antes** de `main()`, incluso antes de que el usuario llame a ninguna función de la librería.

---

## Referencias

- [Dive — explorador de capas Docker](https://github.com/wagoodman/dive)
- [radare2 book](https://book.rada.re/)
- [ELF constructor/destructor functions](https://gcc.gnu.org/onlinedocs/gcc-4.7.0/gcc/Function-Attributes.html)
- [HackTricks — Docker Forensics](https://book.hacktricks.xyz/forensics/docker-forensics)
