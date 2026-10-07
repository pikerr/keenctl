---
name: keenctl
description: Control, inspect, and configure Keenetic routers via keenctl CLI (RCI HTTP API) on-demand. Use for router status, logs, diagnostic runbooks, VLAN segment isolation, or raw RCI mutations without background daemon overhead.
---

# Keenetic Router Control with `keenctl`

Use `keenctl` (alias `keen`) to inspect router status, logs, clients, interfaces, and execute configuration changes over KeeneticOS RCI HTTP API without persistent background daemons.

## Authentication & Credentials

Reads automatically from environment, local `.env`, or `~/.config/keenctl/.env`:
- `KEENETIC_HOST`: Router IP, domain, or full URL (default: `192.168.1.1`)
- `KEENETIC_USER`: Username (`admin` or configured admin user)
- `KEENETIC_PASSWORD`: Password (or prompt via `-p` / `--password-stdin`)
- `KEENETIC_SSL`: Optional boolean (`true`/`false`) to force HTTPS (default: auto-detected, probing HTTP first)

Scheme (HTTP vs HTTPS) is auto-detected and cached. Use `--ssl` / `--https` flag to force HTTPS on CLI.
Session cookies cache in `~/.cache/keenctl/session_*.json` with automatic retry on 401.

## Quick CLI Reference

```bash
# Automated health audit (one-shot check: WAN, DNS, dead conns, flapping, log errors, service security)
keen doctor                        # Human-friendly diagnostic summary
keen doctor --json                 # Compact structured JSON (low token cost for AI agents)
keen diagnose                      # Alias for doctor

# Status & health summary (model, firmware, uptime, WAN gateway, active mgmt services)
keen info

# Management daemons & network services (SSH, Telnet, Web UI, SSTP, FTP, Torrent, SMB)
keen services                      # Human-friendly table of active/disabled services & ports
keen services -m                   # Only remote management daemons (HTTP, SSH, Telnet, SSTP)
keen services -a                   # All services including network daemons (DHCP, DNS, NTP, etc.)
keen services --json               # Machine-readable services JSON

# Connected devices / hotspot hosts (filter by active, interface, subnet)
keen hosts
keen hosts --active
keen hosts -i Bridge2              # Filter by interface
keen hosts -s 192.168.1.0/24        # Filter by subnet

# Associated Wi-Fi stations & signal metrics
keen wifi


# Network interfaces summary (flattened without 32KB JSON bloat)
keen interfaces
keen interfaces --active

# Routing table summary
keen routes

# Connection tracking & dead connections analysis
keen conntrack --unreplied         # List unreplied connections (packets-out == 0)
keen conntrack --unreplied --group # Group dead attempts by target (dst:port)
keen conntrack --proto tcp         # Filter by protocol

# Router system event logs (buffer up to 4000 entries)
keen log                           # Recent 50 log entries (colored on TTY)
keen log -n 20                     # Last 20 entries
keen log -l error                  # Filter by minimum severity (warning, error, crit)
keen log -s ndhcps                 # Filter by daemon/service (ndm, ndhcps, wpa_supplicant)
keen log -g "Bridge0"              # Grep text in messages
keen log --json                    # Machine-parsable JSON array

# Router capabilities & firmware features (AmneziaWG version, FQDN routing, OPKG)
keen capabilities                  # Human-friendly capabilities audit
keen capabilities --json           # Machine-readable capabilities JSON

# System components management (WireGuard, OpenVPN, Tor, etc.)
keen components list               # Catalog of components (shows AmneziaWG compatibility for wireguard)
keen components list --installed   # Only installed components
keen components search wireguard   # Search components
keen components install <name>     # Queue component for installation
keen components commit             # Apply changes (cloud firmware build + reboot with prompt)

# Backup running-config to ~/.local/state/keenctl/backups/
keen backup

# Execute native CLI command directly
keen cmd "show ip hotspot"

# Commit running-config to flash (requires user confirmation)
keen save

# Safe reboot (prompts on TTY, or bypass with -y)
keen reboot
```

## Golden Safety Rule

1. **Running-Config Only (RAM)**: All mutations via `cmd` or `post` are applied to volatile RAM. A reboot reverts changes.
2. **Never commit without human confirmation**: Do **NOT** run `keen save` unless explicitly instructed by the user.
3. **Verify every write**: Keenetic RCI returns `{}` on silent syntax errors. Always verify writes with a read-back `keen get <path>`.
4. **Component changes trigger reboot**: `components commit` requests a cloud firmware build and reboots the router (~2-3 min network downtime). Never commit component changes without explicit human confirmation.

---

## Detailed Task References

Follow these context pointers for specific tasks (Progressive Disclosure):

- **Executing Any Configuration Changes**: Read [`references/safe-changes.md`](references/safe-changes.md) for the mandatory 5-step checklist (backup -> inspect -> apply -> read-back -> report).
- **RCI Syntax & Commands**: Read [`references/rci.md`](references/rci.md) for RCI command tree mapping, syntax discovery via running-config, deletion with `no`, and silent failure traps.
- **VLAN & Network Segments**: Read [`references/segments.md`](references/segments.md) for creating UI-visible isolated segments (Guest Wi-Fi, IoT) with dedicated VLAN subinterfaces and switchport trunking.
- **Network Troubleshooting**: Read [`references/troubleshoot.md`](references/troubleshoot.md) for structured diagnostic runbooks covering WAN drops, disconnected devices, Wi-Fi degradation, and log diagnostics.
