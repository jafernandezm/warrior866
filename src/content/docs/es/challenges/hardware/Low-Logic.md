---
title: "Low Logic"
description: "Writeup de Low Logic - Hack The Box - Hardware 130pts. Imagen de chip lógico y CSV con 4 columnas de bits de entrada; la foto revela compuertas AND y OR; implementar la función booleana (i1 AND i2) OR (i3 AND i4) sobre el CSV produce bits que, agrupados en bytes, forman la flag."
sidebar:
  badge:
    text: Hardware
    variant: tip
tags:
  - htb
  - hardware
  - logic-gates
  - boolean-algebra
  - python
  - csv
  - and-gate
  - or-gate
---

# Low Logic

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Hardware
> 🏆 Puntos: 130
> 👤 Autor: warrior866

---

## Descripción

El ZIP contiene dos archivos: `chip.jpg` — una fotografía de un circuito integrado lógico — e `input.csv` con cuatro columnas de bits (`in0`, `in1`, `in2`, `in3`) que representan las entradas al chip a lo largo del tiempo. Analizando la imagen del chip se identifican compuertas lógicas AND y OR. La función booleana que implementa el circuito es `(in1 AND in2) OR (in3 AND in4)`. Aplicando esta función fila a fila sobre el CSV se obtiene un stream de bits que, agrupados en bytes de 8 bits, producen los caracteres ASCII de la flag.

---

## Análisis de la imagen del chip

```bash
unzip -P 'hackthebox' a12c7355-ac49-4aab-9291-fb9c57f96b1b.zip -d "low-logic"
cd low-logic

ls
# chip.jpg    input.csv
```

La imagen `chip.jpg` muestra el esquema interno del circuito integrado:

```
in0 ──┐
       AND ──┐
in1 ──┘      OR ── OUT
in2 ──┐      │
       AND ──┘
in3 ──┘
```

El circuito tiene **dos compuertas AND** alimentando una **compuerta OR**:
- Primera AND: `in0 AND in1`
- Segunda AND: `in2 AND in3`
- OR final: `(in0 AND in1) OR (in2 AND in3)`

---

## Inspección del CSV de entrada

```bash
head -5 input.csv
```

```
in0,in1,in2,in3
0,1,0,1
1,0,0,1
1,1,0,0
0,0,1,1
...
```

El CSV tiene múltiplos de 8 filas — cada grupo de 8 filas de salida formará un byte de la flag.

```bash
wc -l input.csv
# 361 líneas (360 filas de datos + 1 cabecera)
# 360 / 8 = 45 bytes → flag de 45 caracteres
```

---

## Script Python: aplicar la función booleana

```python
import csv

bits = []
with open('input.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        i0 = int(row['in0'])
        i1 = int(row['in1'])
        i2 = int(row['in2'])
        i3 = int(row['in3'])
        
        # Función booleana: (in0 AND in1) OR (in2 AND in3)
        out = (i0 & i1) | (i2 & i3)
        bits.append(out)

# Agrupar en bytes de 8 bits (MSB primero)
flag = ''
for i in range(0, len(bits), 8):
    byte_bits = bits[i:i+8]
    if len(byte_bits) == 8:
        char_val = int(''.join(map(str, byte_bits)), 2)
        flag += chr(char_val)

print(flag)
# HTB{FLAG}
```

---

## Verificación paso a paso

Para las primeras 8 filas del CSV:

```
Fila  in0  in1  in2  in3  │ AND1=(i0&i1)  AND2=(i2&i3)  OUT=AND1|AND2
  1     0    1    0    1   │     0              0             0
  2     1    0    0    1   │     0              0             0
  3     1    1    0    0   │     1              0             1
  4     0    0    1    1   │     0              1             1
  5     ...                │
  6     ...                │
  7     ...                │
  8     ...                │
```

Los 8 bits de salida se leen de MSB a LSB, se convierten a entero con `int('bits', 2)`, y se convierten a carácter con `chr()`.

---

## Álgebra booleana y compuertas lógicas

Las compuertas usadas en este reto son las más fundamentales:

| Compuerta | Símbolo | Tabla de verdad |
|-----------|---------|-----------------|
| AND | `A & B` | 1 solo si A=1 Y B=1 |
| OR  | `A | B` | 1 si A=1 O B=1 (o ambos) |

El circuito `(A AND B) OR (C AND D)` es una función de suma de productos (SOP, Sum of Products), la forma canónica más común en álgebra de Boole. Es la base de cómo los procesadores modernos implementan operaciones aritméticas y lógicas en hardware.

---

## Lecciones Aprendidas

- **Identificar la función del circuito**: antes de escribir código, hay que entender qué hace el chip. La imagen es el punto de partida — leer el datasheet o esquema del IC antes de procesar los datos.
- **Streams de bits como encoding**: muchos retos de hardware usan señales digitales (0/1) que representan datos binarios. Siempre verificar el orden de bits (MSB/LSB primero) y el tamaño del frame (aquí, 8 bits por carácter ASCII).
- **CSV como entrada de simulación**: los retos de hardware a menudo simulan las entradas de un chip a lo largo del tiempo en un CSV. La cantidad de filas dividida por el frame size da la longitud del mensaje.
- **Python para procesamiento de señales**: `csv.DictReader` + operaciones de bits es suficiente para este tipo de análisis. Para señales más complejas, `numpy` permite vectorizar las operaciones.

---

## Referencias

- [Álgebra de Boole — Wikipedia](https://en.wikipedia.org/wiki/Boolean_algebra)
- [AND gate](https://en.wikipedia.org/wiki/AND_gate)
- [OR gate](https://en.wikipedia.org/wiki/OR_gate)
- [Sum of products (SOP)](https://en.wikipedia.org/wiki/Canonical_normal_form)
