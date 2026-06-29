---
title: "Insider"
description: "Writeup de Insider - Hack The Box - Forensics 200pts. Análisis de perfil Firefox extraído de zip; historial apunta a Tomcat Manager interno; firefox_decrypt descifra las credenciales guardadas y revela la flag como contraseña."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - firefox
  - browser-forensics
  - credential-decryption
  - sqlite
  - firefox-decrypt
  - tomcat
---

# Insider

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 200
> 👤 Autor: warrior866

---

## Descripción

Se entrega un archivo ZIP protegido con contraseña que contiene un perfil completo de Mozilla Firefox. Hay que analizar el perfil para identificar actividad sospechosa y extraer la flag de las credenciales almacenadas.

---

## Extracción y estructura del perfil

```bash
unzip a12c73ae-3239-482c-84f3-5fae461504e8.zip -d insider
```

El ZIP contiene un directorio `Mozilla/Firefox/Profiles/` con dos perfiles:
- `yodxf5e0.default` — perfil vacío.
- `2542z9mo.default-release` — perfil activo con historial, cookies, contraseñas.

Archivos clave del perfil `default-release`:
- `places.sqlite` — historial de navegación y marcadores.
- `logins.json` — credenciales guardadas (cifradas).
- `key4.db` — clave maestra NSS para descifrar `logins.json`.

---

## Análisis del historial (places.sqlite)

```bash
sqlite3 insider/Mozilla/Firefox/Profiles/2542z9mo.default-release/places.sqlite \
  "SELECT url FROM moz_places LIMIT 50;"
```

```text
https://support.mozilla.org/...
http://22.22.22.129:8080/
http://acc01:8080/
http://acc01:8080/manager
http://acc01:8080/manager/html
https://www.google.com/search?client=firefox-b-d&q=wsl+on+old+windows
file:///C:/Users/user/AppData/Roaming/Mozilla/
```

El usuario accedió a `http://acc01:8080/manager/html` — la interfaz **Tomcat Manager** de un servidor interno. Esto indica que probablemente tenga credenciales guardadas para ese endpoint.

---

## Credenciales cifradas en logins.json

```bash
cat insider/Mozilla/Firefox/Profiles/2542z9mo.default-release/logins.json | jq '.'
```

```json
{
  "logins": [
    {
      "hostname": "http://acc01:8080",
      "httpRealm": "Tomcat Manager Application",
      "encryptedUsername": "MDIEEPgAAAAAAAAAAAAAAAAAAAEw...",
      "encryptedPassword": "MEIEEPgAAAAAAAAAAAAAAAAAAAEw...",
      "encType": 1
    }
  ]
}
```

Las credenciales están cifradas con la clave NSS almacenada en `key4.db`. Sin contraseña maestra (master password), se pueden descifrar con `firefox_decrypt`.

---

## Descifrado con firefox_decrypt

```bash
git clone https://github.com/unode/firefox_decrypt
python3 firefox_decrypt/firefox_decrypt.py \
  insider/Mozilla/Firefox/Profiles/2542z9mo.default-release/
```

```text
2026-06-08 15:37:07,060 - WARNING - profile.ini not found in ...
2026-06-08 15:37:07,060 - WARNING - Continuing and assuming '...' is a profile location

Website:   http://acc01:8080
Username: 'admin'
Password: 'HTB{FLAG}'
```

La flag está almacenada como contraseña del Tomcat Manager en el perfil del navegador.

---

## Cadena de Ataque (análisis forense)

```text
1. Extraer ZIP → directorio Mozilla/Firefox/Profiles/
       ↓
2. Identificar perfil activo: 2542z9mo.default-release
       ↓
3. places.sqlite → historial accede a acc01:8080/manager (Tomcat)
       ↓
4. logins.json → credenciales cifradas para http://acc01:8080
       ↓
5. firefox_decrypt + key4.db → descifra credenciales
       ↓
6. Password = flag
```

---

## Lecciones Aprendidas

- **Firefox guarda credenciales cifradas localmente**: `logins.json` + `key4.db` contienen todas las contraseñas guardadas. Sin master password, cualquier persona con acceso al perfil puede descifrarlas con herramientas públicas como `firefox_decrypt`.
- **Master password en Firefox**: activar el master password de Firefox cifra `key4.db` con la contraseña del usuario, haciendo el ataque de descifrado inviable sin conocerla.
- **Artefactos de perfil de browser en forense**: los perfiles de navegador son una de las fuentes más ricas de evidencia forense — historial, contraseñas, cookies, historial de descargas, búsquedas. Siempre analizarlos en incidentes.

---

## Herramientas utilizadas

| Herramienta | Uso |
|-------------|-----|
| `unzip` | Extracción del archivo ZIP |
| `sqlite3` | Consulta del historial de navegación |
| `jq` | Inspección de `logins.json` |
| `firefox_decrypt` | Descifrado de contraseñas del perfil |

---

## Referencias

- [firefox_decrypt — GitHub](https://github.com/unode/firefox_decrypt)
- [Mozilla NSS Key Storage](https://firefox-source-docs.mozilla.org/security/nss/)
