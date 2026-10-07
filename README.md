# keenctl (`keen`)

> Lightweight, zero-daemon CLI control plane and cascaded agent skill for KeeneticOS routers (RCI HTTP API).

---

## Why `keenctl`?

Traditional MCP (Model Context Protocol) servers for Keenetic (such as `salatmaster/keenetic-mcp`) run as persistent background daemon processes. While functional, they introduce specific trade-offs for local agentic workflows:
- **Zero Daemon Overhead**: No long-running background processes consuming RAM and idle CPU. `keenctl` executes on-demand in milliseconds and exits.
- **Context Window Protection**: Traditional stdio MCP servers inject their entire tool schemas into the AI model's context window on *every conversation turn*, wasting thousands of tokens. `keenctl` operates as a CLI tool with a single, cascaded agent skill.
- **Strict Security**: Plaintext passwords in command-line arguments are rejected by design (preventing leaks into `ps`, `bash_history`, and process monitors). Passwords can only be provided via interactive prompt (`-p`) or standard input (`-p -` / `--password-stdin`).
- **Resilient Authentication & Protocol Auto-Detection**: Accepts bare domains or IP addresses without URL schemes, automatically detecting and caching HTTP vs HTTPS with zero-overhead sliding session caching in `~/.cache/keenctl/` (280s window).
- **Clean Actionable Diagnostics**: Never dumps raw multi-line HTML error pages or low-level socket traces. Outputs clear, colorized errors with troubleshooting hints in TTY mode, and compact structured JSON for machine agents (`--json`).
- **Safe-by-Construction Changes**: All configuration changes apply exclusively to volatile RAM (`running-config`). Permanent flash storage writes (`save`) and reboots (`reboot`) require explicit confirmation.

---

## Inspiration & Agent Skills Architecture

The domain knowledge, RCI traps, network segment patterns, and diagnostic workflows in `keenctl` were heavily inspired by and adapted from [`salatmaster/keenetic-mcp`](https://github.com/salatmaster/keenetic-mcp).

However, instead of exposing multiple flat top-level skills that bloat the global prompt registry, `keenctl` structures this knowledge as a **single cascaded skill** using **Progressive Disclosure**:
- **Single Entrypoint**: `skills/keenctl/SKILL.md` (<70 lines) provides high-level commands and pointers.
- **Modular References**: Detailed domain runbooks live in `skills/keenctl/references/`:
  - `safe-changes.md` — RAM-only rule, automated backups, 5-step checklist.
  - `rci.md` — RCI command tree, syntax discovery via running-config, deletion with `no`.
  - `segments.md` — VLAN subinterfaces, switchport trunking, avoiding web UI invisible bridge traps.
  - `troubleshoot.md` — Structured fault trees (WAN drop, DNS proxy, client policy, Wi-Fi RF).
- **Modern Standards**: Conforms to Anthropic, Matt Pocock, and Simon Scrapes best practices: all documents are strictly under 100 lines (solving the "Head -100" attention problem), with calibrated Degrees of Freedom and read-back self-correction loops.

---

## Installation

Using [uv](https://github.com/astral-sh/uv):

```bash
cd /path/to/keenctl
uv tool install --editable .
```

This installs two convenient executable aliases in `~/.local/bin/`:
- `keen`
- `keenctl`

---

## Configuration

Credentials can be passed via environment variables, a local `.env` file, or global `~/.config/keenctl/.env`:

```bash
KEENETIC_HOST=your-router.keenetic.pro  # clean domain, IP (192.168.1.1), or full URL
KEENETIC_USER=admin
KEENETIC_PASSWORD=your_secure_password
KEENETIC_SSL=false                      # optional: force HTTPS (default: auto-detect HTTP then HTTPS)
```

The CLI automatically detects whether the router uses HTTP or HTTPS by probing HTTP first. You can also force HTTPS explicitly using `--ssl` / `--https`.


---

## Usage

```bash
# Automated health & connectivity audit (one-shot diagnostic report)
keen doctor                            # Human-friendly report: WAN, DNS, dead conns, flapping, log errors
keen doctor --json                     # Compact structured JSON (low token cost for AI agents)
keen diagnose                          # Alias for doctor

# General router health and hardware status
keen info

# Management daemons & network services (SSH, Telnet, Web UI, SSTP, FTP, Torrent, SMB)
keen services                          # Human-friendly table of management & app services
keen services -m                       # Management only (HTTP, SSH, Telnet, SSTP)
keen services -a                       # All services including network daemons (DHCP, DNS, NTP, etc.)
keen services --json                   # Machine-readable JSON output

# List connected hotspot clients (filter by active, interface, subnet)
keen hosts
keen hosts --active
keen hosts -i Bridge2                  # Filter by interface
keen hosts -s 192.168.1.0/24            # Filter by subnet

# Wi-Fi stations & wireless metrics (RSSI, speeds, uptime)
keen wifi

# List network interfaces without 32KB JSON payload bloat
keen interfaces
keen interfaces --active

# Show active routing table
keen routes

# Connection tracking (conntrack / NAT) analysis (enriched with routing policy)
keen conntrack                         # Show active connections table
keen conntrack --unreplied             # Show dead/unresponsive connections (packets-out == 0)
keen conntrack --unreplied --group     # Group unreplied attempts by destination host/port
keen conntrack --unreplied --proto udp # Filter by protocol (tcp, udp, icmp)
keen conntrack --unreplied --json      # Structured JSON for agent automation


# Router hardware & feature capabilities (AmneziaWG version, FQDN routing, OPKG)
keen capabilities                      # Human-friendly capabilities audit
keen capabilities --json               # Machine-readable capabilities JSON

# Inspect and manage KeeneticOS system components (WireGuard, OpenVPN, Tor, etc.)
keen components list                   # Catalog of components (shows AmneziaWG compatibility for wireguard)
keen components list --installed       # Only installed components
keen components list --available       # Only components available to install
keen components search wireguard       # Search components by keyword
keen components install <name>         # Queue component for installation
keen components commit                 # Apply changes (cloud firmware build + reboot with prompt)

# Query any branch in the RCI tree
keen get show/system
keen get show/internet/status

# Execute native Keenetic CLI command directly
keen cmd "show ip hotspot"
keen cmd "interface Wireguard0 up"

# Mutate configuration via JSON
keen post ip/hotspot '{"host": {"mac": "aa:bb:cc:dd:ee:ff", "access": "permit"}}'

# Backup running-config to ~/.local/state/keenctl/backups/
keen backup

# Commit running-config to flash (prompts for confirmation)
keen save
keen save -y

# Query system event logs (colored on TTY, structured JSON with --json)
keen log
keen log -n 20                     # Last 20 entries
keen log -l error                  # Filter errors & critical events
keen log -s ndhcps                 # Filter by daemon/service (ndhcps, ndm, etc.)
keen log -g "Bridge0"              # Search text in log messages
keen log --json                    # Compact machine-parsable JSON

# Reboot router (prompts for confirmation)
keen reboot
keen reboot -y
```

---

## Testing

Run tests with `pytest`:

```bash
uv run pytest
```

---

## License

MIT
