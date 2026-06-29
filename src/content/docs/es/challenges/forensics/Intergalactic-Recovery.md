---
title: "Intergalactic Recovery"
description: "Writeup de Intergalactic Recovery - Hack The Box - Forensics. Tres imágenes de disco de un RAID-5 degradado; una imagen es el disco faltante (vacío); reconstruir el array con mdadm permite montar el volumen y recuperar el PDF con la flag."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - raid
  - mdadm
  - disk-forensics
  - linux
  - filesystem-recovery
---

# Intergalactic Recovery

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 👤 Autor: warrior866

---

## Descripción

Se proporcionan tres imágenes de disco que pertenecen a un array RAID-5 degradado. Una de las imágenes (`0c584923.img`) es el disco faltante o dañado — tiene solo 3.7 KB frente a los 5 MB de las otras dos. RAID-5 puede reconstruir los datos de un disco perdido usando la paridad distribuida en los discos restantes. Con `mdadm` se reconstruye el array indicando `missing` en la posición del disco ausente, y el sistema puede montarse para recuperar el archivo PDF que contiene la flag.

---

## Extracción y reconocimiento

```bash
unzip -o -P 'hackthebox' a12c7356-2b84-454c-8753-457e1c84f7b5.zip -d "intergalactic-recovery"
cd intergalactic-recovery/forensics_intergalactic_recovery/

ls -la
# fef0d1cd.img   5.0 MB  ← disco 1
# 0c584923.img   3.7 KB  ← disco faltante/dañado
# 06f98d35.img   5.0 MB  ← disco 2
```

La diferencia de tamaño entre `0c584923.img` (3.7 KB) y las otras dos (5 MB cada una) confirma que es el disco que debe marcarse como `missing` en el RAID.

---

## Reconstrucción del RAID-5 con mdadm

```bash
# Asociar los dos discos válidos a dispositivos loop
sudo losetup /dev/loop1 06f98d35.img
sudo losetup /dev/loop2 fef0d1cd.img

# Crear el RAID-5 degradado indicando el disco faltante
sudo mdadm --create --assume-clean --level=5 --raid-devices=3 \
  /dev/md0 /dev/loop1 /dev/loop2 missing
```

```
To optimize recovery speed, it is recommended to enable write-intent bitmap, do you want to enable it now? [y/N]? y
mdadm: Defaulting to version 1.2 metadata
mdadm: array /dev/md1 started.
```

El flag `--assume-clean` es crítico: le indica a `mdadm` que no intente resincronizar el array (lo que destruiría los datos), sino que asuma que los discos ya están en un estado coherente.

---

## Montaje y recuperación del PDF

```bash
mkdir /mnt/tmpraid
sudo mount /dev/md0 /mnt/tmpraid

ls /mnt/tmpraid
# imw_1337.pdf

cp /mnt/tmpraid/imw_1337.pdf .
```

El PDF contiene la flag.

---

## Limpieza del entorno

```bash
sudo umount /mnt/tmpraid
sudo mdadm --stop /dev/md0
sudo losetup -d /dev/loop1
sudo losetup -d /dev/loop2
```

---

## Cadena de Análisis

```text
1. 3 imágenes: 2 discos válidos (5MB c/u) + 1 imagen vacía (3.7KB)
       ↓
2. losetup → asignar imágenes a dispositivos de bloque /dev/loopN
       ↓
3. mdadm --create --assume-clean --level=5 /dev/md0 loop1 loop2 missing
       ↓
4. RAID-5 reconstituido: paridad de los 2 discos recalcula el disco faltante
       ↓
5. mount /dev/md0 → ls → imw_1337.pdf → flag
```

---

## Lecciones Aprendidas

- **RAID-5 y resiliencia**: RAID-5 puede reconstruir el contenido de UN disco perdido usando las bandas de paridad distribuidas. Con dos discos sanos de un RAID-5 de 3 discos, la recuperación es posible.
- **`--assume-clean` es indispensable**: sin este flag, `mdadm` intentaría recalcular la paridad desde cero, sobrescribiendo los datos originales y destruyendo el volumen. Siempre usarlo en contextos forenses.
- **Dispositivos loop en Linux**: `losetup` permite tratar archivos de imagen de disco como dispositivos de bloque reales, habilitando su uso con herramientas como `mdadm`, `mount`, o `fsck`.
- **Triage por tamaño**: comparar el tamaño de las imágenes es el indicador más rápido del disco faltante antes de intentar montar.

---

## Referencias

- [mdadm manual](https://linux.die.net/man/8/mdadm)
- [RAID-5 explained](https://en.wikipedia.org/wiki/Standard_RAID_levels#RAID_5)
- [HackTricks — Disk Forensics](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving)
