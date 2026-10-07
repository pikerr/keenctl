# Network Troubleshooting Runbook

Structured fault isolation from outer symptoms inward.

## Contents
1. [Scenario A: Internet Down](#scenario-a-the-internet-is-down)
2. [Scenario B: Single Device Disconnected](#scenario-b-one-specific-device-has-no-internet)
3. [Scenario C: Unstable Wi-Fi](#scenario-c-wi-fi-is-unstable-or-dropping)

---

## Scenario A: The Internet is Down

Follow in order without skipping ahead:

### Step 1. Check Internet Status & Health Flags
```bash
keen get show/internet/status
```
Indicators:
- `internet: false`, `gateway: false`: WAN link down. Proceed to Step 2.
- `gateway: true`, `dns: false`: WAN link active, DNS broken. Proceed to Step 4.
- `captive: false`: Captive portal interception on WAN uplink.
- `internet: true`: Global WAN operational. Symptom is client-specific; see Scenario B.

### Step 2. Check WAN Interface Physical & Link State
```bash
keen info | jq .gateway
keen get show/interface/<gateway-interface>
```
- `link: "down"`: Physical cable disconnected, optical failure, or no carrier.
- `link: "up"`, `state: "down"`: Administratively down (`keen cmd "interface <name> up"`).
- `connected: false` on PPPoE/WireGuard: Tunnel authentication or handshake failed.

### Step 3. Check Default Route
```bash
keen cmd "show ip route" | grep -E "0\.0\.0\.0|default"
```
If the default route points to a stalled VPN interface, global traffic stalls even if ISP uplink is active.

### Step 4. Check DNS Proxy Health
```bash
keen get show/dns-proxy
```
Inspect upstream servers and response latencies. If VPN upstream DNS is unresponsive, test public fallbacks (`1.1.1.1`, `9.9.9.9`).

---

## Scenario B: One Specific Device Has No Internet

### Step 1. Locate Device in Hotspot State
```bash
keen hosts | jq '.[] | select(.ip == "192.168.1.X" or .mac == "aa:bb:cc:dd:ee:ff")'
```

### Step 2. Inspect Host Record
```bash
keen get show/ip/hotspot | jq '.host[] | select(.mac == "aa:bb:cc:dd:ee:ff")'
```
Evaluate fields in sequence:
1. `access`: If `"deny"`, unblock via `keen cmd "no ip hotspot host aa:bb:cc:dd:ee:ff access"`.
2. `policy`: Check assigned policy. If the policy's primary uplink is down, device loses connectivity.
3. `rxbytes` / `txbytes`: Check whether traffic counters are incrementing or frozen.
4. `schedule`: Verify if parental control schedule blocks access during current time window.

---

## Scenario C: Wi-Fi is Unstable or Dropping

```bash
keen get show/associations
```
Check client wireless metrics:
- `rssi`: Signal strength in dBm (values worse than `-75 dBm` indicate insufficient coverage).
- `txss` / `rxss`: MCS stream rates (rapid fluctuations indicate heavy RF interference or distance).
- `txerror`: High packet retry/error counters confirm channel congestion.

---

## Scenario D: System Log & Event Diagnostics

Use `keen log` directly to inspect kernel and daemon activity without manually parsing raw RCI structures.

### Step 1. Filter System Errors & Critical Events
```bash
# Check errors across the entire buffer
keen log -l error

# Check warnings and errors (last 30)
keen log -l warning -n 30
```

### Step 2. Inspect Specific Subsystems / Services
```bash
# DHCP issues (lease rejections, IP pool exhaustion)
keen log -s ndhcps -n 25

# Core NDM process & interface state transitions
keen log -s ndm -n 25

# Wi-Fi client association, authentication & roaming (FT roam)
keen log -s ndm -g "WifiMonitor" -n 20

# DNS proxy lookups & upstream query failures
keen log -s ndnproxy -l warning
```

### Step 3. Target Specific Router
If inspecting a specific router, pass `-H`:
```bash
keen -H 192.168.1.1 log -l error
```
