# Práctica NetFlow - Resumen para Examen

## Objetivo

Implementar una versión simplificada de **NetFlow** que procese una traza PCAP y genere estadísticas de flujos TCP y UDP.

Un flujo se identifica mediante una **5-tupla**:

```text
(IP origen,
 IP destino,
 protocolo,
 puerto origen,
 puerto destino)
```

Ejemplo:

```text
192.168.1.10:52341
      ↓
142.250.184.78:443
TCP
```

Todos los paquetes que compartan la misma 5-tupla pertenecen al mismo flujo.

---

# Fase 1: Lectura de argumentos

## Objetivo

Cumplir el formato:

```bash
python3 netflow.py -i ejemplo.pcap -T 10
```

## Implementación

```python
args.i
args.T
```

usando:

```python
argparse
```

## Teoría

### PCAP

```text
-i ejemplo.pcap
```

Archivo de captura a analizar.

### Timeout

```text
-T 10
```

Tiempo máximo de inactividad permitido para un flujo.

Si:

```text
tiempo_actual - último_paquete > T
```

el flujo expira.

---

# Fase 2: Apertura del PCAP

## Implementación

```python
pcap_open_offline()
```

## Teoría

Un fichero PCAP contiene:

```text
Cabecera global
Paquete 1
Paquete 2
...
```

Cada paquete contiene:

```text
Timestamp
Longitud
Datos
```

---

# Fase 3: Lectura de paquetes

## Implementación

```python
pcap_loop()
```

## Funcionamiento

Por cada paquete leído:

```text
PCAP
 ↓
pcap_loop()
 ↓
procesa_paquete()
```

La callback recibe:

```python
procesa_paquete(user, pkt_header, pkt_data)
```

---

# Fase 4: Ethernet

## Objetivo

Determinar qué protocolo encapsula la trama.

## Cabecera Ethernet

```text
MAC destino    6 bytes
MAC origen     6 bytes
EtherType      2 bytes
```

Total:

```text
14 bytes
```

## Implementación

```python
ethertype = int.from_bytes(pkt_data[12:14], "big")
```

## EtherTypes comunes

```text
0x0800 → IPv4
0x86DD → IPv6
0x0806 → ARP
```

Solo nos interesa IPv4:

```python
if ethertype != 0x0800:
    return
```

---

# Fase 5: IPv4

## Cabecera IPv4

Tamaño mínimo:

```text
20 bytes
```

Primer byte:

```text
Version | IHL
```

Ejemplo:

```text
0100 0101
```

```text
Version = 4
IHL = 5
```

## IHL

Internet Header Length.

Número de palabras de:

```text
32 bits = 4 bytes
```

Por tanto:

```python
ip_header_len = ihl * 4
```

## Validación

```python
if ihl < 5:
    return
```

porque:

```text
5 × 4 = 20 bytes
```

es el mínimo válido.

## Direcciones IP

Posiciones:

```text
12-15 → IP origen
16-19 → IP destino
```

Implementación:

```python
src_ip
dst_ip
```

---

# Fase 6: TCP y UDP

## Campo protocolo

Posición:

```python
ip_start + 9
```

Valores:

```text
6  → TCP
17 → UDP
```

## TCP

Cabecera mínima:

```text
20 bytes
```

## UDP

Cabecera:

```text
8 bytes
```

## Puertos

Primeros 4 bytes:

```text
Puerto origen
Puerto destino
```

Implementación:

```python
src_port
dst_port
```

---

# Fase 7: Construcción de la 5-tupla

## Implementación

```python
flow_key = (
    src_ip,
    dst_ip,
    proto_text,
    src_port,
    dst_port
)
```

## Teoría

La 5-tupla identifica de forma única un flujo.

Importante:

```text
A → B
```

y

```text
B → A
```

son flujos distintos.

NetFlow trabaja con flujos direccionales.

---

# Fase 8: Tabla de flujos

## Objetivo

Agrupar paquetes por flujo.

## Implementación

```python
flows = {}
```

Estructura:

```python
flows = {
    flow_key: {
        ...
    }
}
```

## Teoría

La tabla almacena:

```text
5-tupla
→ estadísticas asociadas
```

Es una versión simplificada de una tabla NetFlow real.

---

# Fase 9: Estadísticas del flujo

## Campos almacenados

```text
start_time
last_time
packets
bytes
acks
```

## Tiempo de inicio

Primer paquete observado:

```python
start_time
```

## Tiempo final

Último paquete observado:

```python
last_time
```

## Paquetes

```python
packets += 1
```

## Bytes

```python
bytes += pkt_header.len
```

## Importante

El enunciado pide:

```text
Bytes a nivel Ethernet
```

Por ello usamos:

```python
pkt_header.len
```

NO:

```python
pkt_header.caplen
```

NO:

```python
len(pkt_data)
```

---

# Fase 9.5: Contador ACK

## Flags TCP

TCP contiene:

```text
FIN
SYN
RST
PSH
ACK
URG
...
```

## Posición

```python
transport_start + 13
```

## ACK

Valor:

```text
0x10
```

Implementación:

```python
if tcp_flags & 0x10:
    ack = 1
```

Acumulación:

```python
flow["acks"] += ack
```

---

# Fase 10: Expiración de flujos

## Teoría

Los flujos no pueden permanecer activos indefinidamente.

Regla:

```text
Si pasan T segundos sin tráfico
→ expirar flujo
```

## Implementación

```python
if timestamp - flow["last_time"] > timeout:
```

Ejemplo:

```text
Timeout = 10
Último paquete = 100
Nuevo paquete = 112

112 - 100 = 12 > 10
```

Resultado:

```text
El flujo expira
```

---

# Fase 11: Generación de flows.txt

## Duración

```python
duracion = last_time - start_time
```

## Paquetes por segundo

```python
pps = packets / duracion
```

## Bits por segundo

Conversión:

```text
bytes × 8 = bits
```

Implementación:

```python
(bytes * 8) / duracion
```

Conversión a kb/s:

```python
/ 1000
```

## Formato de salida

Campos obligatorios:

```text
Inicio
Fin
IP origen
IP destino
Puerto origen
Puerto destino
TCP/UDP
Bytes
Paquetes
pps
kbps
ACKs
```

Separados por:

```text
\t
```

---

# Estructura completa del programa

```text
Abrir PCAP
        ↓
Leer paquete
        ↓
Ethernet
        ↓
IPv4
        ↓
TCP/UDP
        ↓
Extraer 5-tupla
        ↓
Buscar flujo
        ↓
Crear o actualizar
        ↓
¿Timeout?
        ↓
Expirar si procede
        ↓
Seguir leyendo
        ↓
Fin de traza
        ↓
Expirar flujos restantes
        ↓
Generar flows.txt
```

---

# Conceptos clave para examen

## EtherType IPv4

```text
0x0800
```

## Protocolos IP

```text
TCP = 6
UDP = 17
```

## Tamaños mínimos

```text
Ethernet = 14 bytes
IPv4 = 20 bytes
TCP = 20 bytes
UDP = 8 bytes
```

## ACK TCP

```text
0x10
```

## Flujo

```text
(IP origen,
 IP destino,
 protocolo,
 puerto origen,
 puerto destino)
```

## Expiración

```python
timestamp - last_time > timeout
```

## Bytes Ethernet

```python
pkt_header.len
```

## Lectura de paquetes

```python
pcap_loop()
```

## Apertura PCAP

```python
pcap_open_offline()
```

