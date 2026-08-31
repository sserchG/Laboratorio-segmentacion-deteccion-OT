# Segmentación OT con modelo Purdue, Modbus/TCP y monitorización pasiva (Suricata)

**Autor:** sserch

---

## Objetivo

Montar un entorno de laboratorio que reproduzca una arquitectura industrial simplificada según el modelo Purdue, con el fin de demostrar de forma práctica algunos de los aspectos fundamentales de la ciberseguridad OT.

- Validar la ausencia de seguridad en Modbus/TCP
- Aplicar microsegmentación estricta entre IT / iDMZ / OT mediante dos FortiGate
- Monitorización pasiva sin latencia usando Suricata IDS sobre un puerto espejo

---

## Contexto

Los entornos industriales presentan una particularidad que los diferencia de los entornos IT tradicionales. Mientras que en IT prima la confidencialidad, en OT la disponibilidad y la seguridad de las personas están por encima de cualquier otra consideración. Esta diferencia condiciona por completo el diseño de los controles de seguridad.

A ello se suma que los protocolos industriales más extendidos —Modbus, PROFINET, DNP3— fueron diseñados en un momento en que las redes de control estaban físicamente aisladas, por lo que carecen de mecanismos de autenticación y cifrado. La convergencia IT/OT ha expuesto estos protocolos a un escenario de amenazas para el que nunca fueron concebidos.

---

## Entorno

El laboratorio se despliega sobre **GNS3**, empleando:

| Componente | Software | Función |
|---|---|---|
| PLC | OpenPLC v3 (Ubuntu 22.04) | Controlador de proceso, servidor Modbus/TCP (Nivel 1) |
| HMI | Ubuntu 22.04 + mbpoll | Estación de operación local, cliente Modbus (Nivel 2) |
| Switch Celda | Cisco IOSvL2 | Conmutación de planta y réplica de tráfico vía SPAN |
| Firewall Perimetral | FortiGate-VM64-KVM (FGT2) | Punto de control de acceso y microsegmentación iDMZ/OT |
| IDS Pasivo | Ubuntu 22.04 + Suricata | Detección pasiva de anomalías y escrituras SCADA |
| Estación IT | Ubuntu 22.04 | Cliente en zona corporativa no confiable (Nivel 4/5) |

---

## Arquitectura

La topología implementa un esquema de microsegmentación por zonas alineado con **ISA/IEC 62443**:

- **Nivel 4/5 (IT / Corporativa):** estación de trabajo Ubuntu (`192.168.10.0/24`), zona no confiable respecto al proceso.
- **Zona de Gestión (`192.168.1.0/24`):** red de administración de infraestructura.
- **Frontera e iDMZ (Nivel 3.5 · `192.168.20.0/24`):**
  - FortiGate principales (`FGT` y `FGT2`): control de acceso perimetral e inter-zona.
  - IDMZBastion: bastión obligado para salto RDP/SSH desde IT.
  - Historian Replica: servidor para exposición segura de telemetría a la red corporativa.
- **Nivel 2/1 (Celda OT · `192.168.40.0/24`):**
  - Switch de celda (SW-CELDA / Cisco IOSvL2): conmutación de planta con puerto SPAN configurado hacia el IDS.
  - PLC (OpenPLC v3): controlador de proceso con IP `192.168.40.30` (servidor Modbus/TCP en puerto 502, DNP3 y Snap7).
  - HMI (`192.168.40.20`): estación de operación local (cliente Modbus).
  - IDS (Suricata): sensor pasivo conectado al puerto espejo para inspección profunda de paquetes (DPI).

---

## Alcance y limitaciones

Entorno virtualizado con fines exclusivamente formativos. No reproduce las restricciones de tiempo real de una red industrial productiva, ni contempla dispositivos físicos, sistemas instrumentados de seguridad (SIS) ni procesos con impacto físico. Todo el direccionamiento y los datos empleados son ficticios.

---

## Evidencia de comandos y pruebas ejecutadas

### 1. Despliegue de OpenPLC v3 (Dashboard Web)

Verificación en la interfaz de OpenPLC (`localhost:8080`) de la carga del programa `blank_program.st` y el arranque de los servicios de escucha industrial:

- Modbus/TCP: puerto `502`
- Ethernet/IP: puerto `44818`
- Snap7: servidor activo

---

### 2. Fase inicial: acceso directo y falta de seguridad en Modbus/TCP

Demostración de conectividad directa desde la estación IT hacia el PLC y captura de tráfico en texto claro con Wireshark.

```bash
# Prueba de conectividad ICMP exitosa desde IT antes de segmentar
ping 192.168.40.30

# Prueba de apertura de socket TCP directo al puerto Modbus (502)
telnet 192.168.40.30 502
# Resultado: Connected to 192.168.40.30

# Lectura de 10 registros manteniendo la dirección 0x00 desde IT
mbpoll -a 1 -r 1 -c 10 -t 4 -1 192.168.122.76

# Inyección arbitraria de valores en memoria del PLC desde IT
mbpoll -a 1 -r 2 -t 4 192.168.122.76 500
mbpoll -a 1 -r 3 -t 4 192.168.122.76 750
mbpoll -a 1 -r 1 -t 4 192.168.40.30 9999
mbpoll -a 1 -r 1 -t 4 -1 192.168.40.30 7777
```

---

## Comandos ejecutados por fases

### 1. Simulación y explotación Modbus/TCP (HMI / IT)

Comandos para verificar la falta de cifrado/autenticación y la inyección de registros en OpenPLC.

```bash
# Lectura legítima de 10 registros manteniendo la dirección 0x00
mbpoll -m tcp -a 1 -r 0 -c 10 192.168.40.X

# Escritura arbitraria (ataque/modificación de proceso)
# Escribe el valor '1' en el registro 0 del PLC desde una zona no autorizada
mbpoll -m tcp -a 1 -r 0 -t 4 192.168.40.X 1
```

### 2. Configuración de microsegmentación en FortiGate (`FGT2`)

Aplicación de políticas de control de acceso estricto y tabla de enrutamiento hacia WAN.

```bash
# Revisar la tabla de políticas activas y límites de VDOM
show firewall policy

# Regla 10: permitir acceso a OT ÚNICAMENTE desde el bastión de la iDMZ
config firewall policy
    edit 10
        set name "iDMZ_Bastion_to_OT"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "HOST_IDMZ_BASTION"
        set dstaddr "NET_OT"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end

# Regla 20: permitir salida de telemetría desde OT a la réplica del Historian en iDMZ
config firewall policy
    edit 20
        set name "OT_to_Historian_Replica"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "NET_OT"
        set dstaddr "HOST_HISTORIAN_REPLICA"
        set action accept
        set schedule "always"
        set service "HTTP" "HTTPS"
        set logtraffic all
    next
end

# Enrutamiento estático para la interfaz de gestión / WAN
config router static
    edit 30
        set dst 0.0.0.0 0.0.0.0
        set gateway 192.168.122.1
        set device "port10"
    next
end
```

---

### 3. Fase de aplicación de controles y segmentación (FortiGate & ACL)

Aplicación de políticas de control de acceso estricto en los firewalls y verificación del bloqueo de tráfico directo desde IT hacia OT.

**Bloqueo y verificación de ausencia de conectividad:**

```bash
# Intento de ping tras aplicar la regla de segmentación
ping 192.168.40.30
# Resultado: From 192.168.10.1 icmp_seq=1 Packet filtered

# Intento de conexión Modbus por Telnet
telnet 192.168.40.30 502
# Resultado: telnet: Unable to connect to remote host: No route to host
```

---

### 4. Configuración del puerto espejo / SPAN (Cisco Switch)

Replicación bidireccional del tráfico de celda hacia la interfaz del IDS.

```bash
configure terminal

! Configurar interfaz origen (tráfico entre PLC y HMI)
monitor session 1 source interface GigabitEthernet 0/0 both

! Configurar interfaz destino (conectada al sensor Suricata)
monitor session 1 destination interface GigabitEthernet 3/3
end

! Verificar estado de la sesión SPAN
show monitor session 1
```

### 5. Despliegue del sensor pasivo con Suricata (IDS)

Puesta en modo promiscuo de la NIC y análisis de firmas en tiempo real.

```bash
# 1. Habilitar modo promiscuo en la interfaz conectada al puerto SPAN
sudo ip link set dev eth0 promisc on

# 2. Firma personalizada añadida en /etc/suricata/rules/scada.rules
# Detecta comandos de escritura Modbus (Function Code 06 / 16)
alert tcp any any -> 192.168.40.0/24 502 (msg:"OT-ALERT: Modbus TCP Write Command Detected"; content:"|00 00|"; offset:2; depth:2; content:"|06|"; offset:7; depth:1; sid:1000001; rev:1;)

# 3. Lanzar motor de Suricata en modo pasivo
sudo suricata -c /etc/suricata/suricata.yaml -i ens3

# 4. Monitorización de alertas generadas en logs
sudo tail -f /var/log/suricata/fast.log

# Filtrado avanzado de eventos JSON con jq
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
```

---

### 6. Diagnóstico de red y gestión de FortiOS CLI

Renovación de leases DHCP y comprobación de servicios.

```bash
# Renovar IP en la interfaz conectada al objeto NAT
execute dhcp lease-renew port10

# Test de conectividad ICMP y resolución DNS
execute ping 8.8.8.8
```

---

## Resultados obtenidos

1. **Falta de seguridad en protocolo legacy:** se comprobó que el protocolo Modbus/TCP no valida la autenticidad del emisor ni cifra la carga útil.
2. **Aislamiento por microsegmentación:** al cerrar las reglas en `FGT1` y `FGT2`, los accesos directos desde la zona IT rebotaron por *Implicit Deny*, obligando a pasar por el bastión de la iDMZ.
3. **Visibilidad pasiva sin impacto:** Suricata alertó correctamente de todas las operaciones de escritura sobre OpenPLC a través del puerto SPAN, sin añadir latencia ni alterar los ciclos de scan de la planta.
