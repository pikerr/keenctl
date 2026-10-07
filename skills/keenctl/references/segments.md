# Network Segments & VLAN Isolation

Creating isolated networks (Guest Wi-Fi, IoT, VPN-bound subnets) in KeeneticOS.

## Contents
1. [The "Invisible Bridge" UI Trap](#the-invisible-bridge-ui-trap)
2. [KeeneticOS Requirements for UI Segments](#keeneticos-requirements-for-ui-segments)
3. [Pre-Flight Inspection (Free IDs)](#pre-flight-inspection-free-ids)
4. [Step-by-Step Segment Runbook](#step-by-step-segment-runbook)

---

## The "Invisible Bridge" UI Trap

Configuring a bridge with only an IP address, DHCP, and Wi-Fi SSID works at the network layer, but **the Keenetic Web UI will not list it as a segment**. It will be invisible under Segments and Wireless Access Points.

---

## KeeneticOS Requirements for UI Segments

For the Web UI to recognize a bridge as a segment and populate internal `iseg` metadata, three components are required:
1. **Dedicated VLAN Subinterface**: `GigabitEthernet0/VlanN`
2. **VLAN Trunking**: That VLAN trunked across internal switch ports.
3. **Bridge Inheritance**: The VLAN subinterface added into `BridgeN` via `inherit`.

---

## Pre-Flight Inspection (Free IDs)

Before configuring, discover unallocated bridge numbers, VLAN IDs, and subnets:

```bash
# Check existing bridges
keen get show/interface | jq 'to_entries[] | select(.key | startswith("Bridge")) | {name: .key, ip: .value.address}'

# Check existing VLAN subinterfaces
keen get show/interface | jq 'to_entries[] | select(.key | contains("Vlan")) | .key'

# Check existing DHCP pools
keen get show/rc/ip/dhcp
```

### Conventions:
- `Bridge0` + `VLAN 1`: Default Home segment (`192.168.1.0/24`).
- `Bridge1` + `VLAN 2`: Default Guest segment (`192.168.2.0/24`).
- New custom segments start at `Bridge2`, `VLAN 3` (or next free ID), and subnet `192.168.3.0/24`.

---

## Step-by-Step Segment Runbook

Example creating UI-visible segment `Bridge2` (VLAN 3, `192.168.3.0/24`, description "IoT"):

### 1. VLAN Subinterface & Switchport Trunking
```bash
keen cmd "interface GigabitEthernet0/Vlan3"
keen cmd "interface GigabitEthernet0/Vlan3 up"

# Trunk across internal switch ports (GigabitEthernet0/0..0/3 depending on model)
keen cmd "interface GigabitEthernet0/0 switchport trunk vlan 3"
keen cmd "interface GigabitEthernet0/1 switchport trunk vlan 3"
keen cmd "interface GigabitEthernet0/2 switchport trunk vlan 3"
keen cmd "interface GigabitEthernet0/3 switchport trunk vlan 3"
```

### 2. Bridge Creation & Configuration
```bash
keen cmd "interface Bridge2"
keen cmd "interface Bridge2 inherit GigabitEthernet0/Vlan3"
keen cmd "interface Bridge2 description IoT"
keen cmd "interface Bridge2 ip address 192.168.3.1 255.255.255.0"
keen cmd "interface Bridge2 up"
keen cmd "ip nat Bridge2"
```

### 3. DHCP Pool Setup
```bash
keen cmd "ip dhcp pool _WEBADMIN_Bridge2"
keen cmd "ip dhcp pool _WEBADMIN_Bridge2 range 192.168.3.33 192.168.3.100"
keen cmd "ip dhcp pool _WEBADMIN_Bridge2 lease 86400"
keen cmd "ip dhcp pool _WEBADMIN_Bridge2 bind Bridge2"
```

### 4. Read-Back Verification
```bash
keen get show/interface/Bridge2
```
Verify `state: "up"`, IP address `192.168.3.1`, and presence of members.
