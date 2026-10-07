from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from .client import KeeneticClient, KeeneticError, group_unreplied_conntrack


def _parse_env_file(path: Path) -> None:
    if not path.is_file():
        return
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip("'\"")
            if key not in os.environ:
                os.environ[key] = val
    except Exception:
        pass


def _load_env_file() -> None:
    """Load .env from cwd/parents, falling back to ~/.config/keenctl/.env."""
    cwd = Path.cwd()
    for directory in [cwd, *cwd.parents]:
        env_path = directory / ".env"
        if env_path.is_file():
            _parse_env_file(env_path)
            break

    xdg_config = Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config"))
    global_env = xdg_config / "keenctl" / ".env"
    _parse_env_file(global_env)


def _output(data: Any, raw_json: bool = False) -> None:
    """Output data, adapting to TTY vs pipe/agent."""
    is_tty = sys.stdout.isatty() and not raw_json

    if isinstance(data, (dict, list)):
        indent = 2 if is_tty else None
        text = json.dumps(data, indent=indent, ensure_ascii=False)
        print(text)
    else:
        print(str(data))


def _format_log_line(entry: dict[str, Any], is_tty: bool = True) -> str:
    timestamp = entry.get("timestamp", "")
    ident = entry.get("ident", "")
    level = entry.get("level", "Info")
    label = entry.get("label") or (level[0].upper() if level else "I")
    message = entry.get("message", "")

    if is_tty:
        dim = "\033[2m"
        bold = "\033[1m"
        reset = "\033[0m"
        lvl_color = reset
        lvl_low = level.lower()
        if any(x in lvl_low for x in ("err", "crit", "alert", "emerg")):
            lvl_color = "\033[1;31m"
        elif "warn" in lvl_low:
            lvl_color = "\033[33m"
        elif "notice" in lvl_low:
            lvl_color = "\033[36m"

        return f"{dim}{timestamp}{reset} {dim}[{reset}{bold}{ident}{reset}{dim}]{reset} {lvl_color}[{label}]{reset} {message}"
    else:
        return f"{timestamp} [{ident}] [{label}] {message}"


def _format_conntrack_table(conns: list[dict[str, Any]], unreplied_only: bool = False, is_tty: bool = True) -> None:
    if not conns:
        if unreplied_only:
            print("No unreplied connections found (all tracked connections received responses).")
        else:
            print("No connection tracking entries found.")
        return

    title = f"Unreplied Connections ({len(conns)} found):" if unreplied_only else f"Connection Tracking Table ({len(conns)} entries):"
    if is_tty:
        bold = "\033[1m"
        reset = "\033[0m"
        print(f"{bold}{title}{reset}\n")
    else:
        print(f"{title}\n")

    hdr_fmt = "{:<5}  {:<32}  {:<26}  {:<14}  {:>9}  {:>9}"
    row_fmt = "{:<5}  {:<32}  {:<26}  {:<14}  {:>9}  {:>9}"

    header = hdr_fmt.format("PROTO", "SOURCE", "DESTINATION", "SERVICE", "SENT PKT", "RECV PKT")
    if is_tty:
        print(f"\033[4m{header}\033[0m")
    else:
        print(header)
        print("-" * len(header))

    for c in conns:
        proto = c.get("protocol", "")
        src = c.get("src", "")
        sport = c.get("sport")
        src_name = c.get("src_name")
        dst = c.get("dst", "")
        dport = c.get("dport")
        dst_name = c.get("dst_name")
        service = c.get("service", "")
        pkts_sent = c.get("packets", 0)
        pkts_recv = c.get("packets_recv", 0)

        src_str = f"{src}:{sport}" if sport else src
        if src_name:
            src_str = f"{src_str} ({src_name})"
        if len(src_str) > 32:
            src_str = src_str[:29] + "..."

        dst_str = f"{dst}:{dport}" if dport else dst
        if dst_name:
            dst_str = f"{dst_str} ({dst_name})"
        if len(dst_str) > 26:
            dst_str = dst_str[:23] + "..."

        line = row_fmt.format(proto, src_str, dst_str, service or "-", str(pkts_sent), str(pkts_recv))
        if is_tty and unreplied_only:
            print(f"\033[33m{line}\033[0m")
        else:
            print(line)


def _format_conntrack_grouped(grouped: list[dict[str, Any]], is_tty: bool = True) -> None:
    if not grouped:
        print("No unreplied connections found (all tracked connections received responses).")
        return

    total_conns = sum(g["conns_count"] for g in grouped)
    title = f"Unreplied Connections (Grouped by Target: {len(grouped)} targets, {total_conns} total connections):"
    if is_tty:
        bold = "\033[1m"
        reset = "\033[0m"
        print(f"{bold}{title}{reset}\n")
    else:
        print(f"{title}\n")

    hdr_fmt = "{:<24}  {:<5}  {:<14}  {:>6}  {:>9}  {}"
    row_fmt = "{:<24}  {:<5}  {:<14}  {:>6}  {:>9}  {}"

    header = hdr_fmt.format("TARGET", "PROTO", "SERVICE", "CONNS", "SENT PKT", "SOURCES")
    if is_tty:
        print(f"\033[4m{header}\033[0m")
    else:
        print(header)
        print("-" * len(header))

    for g in grouped:
        target = f"{g['dst']}:{g['dport']}" if g.get("dport") else g["dst"]
        if g.get("dst_name"):
            target = f"{target} ({g['dst_name']})"
        if len(target) > 24:
            target = target[:21] + "..."

        proto = g.get("protocol", "")
        service = g.get("service") or "-"
        conns_cnt = str(g.get("conns_count", 0))
        pkts = str(g.get("packets", 0))
        sources_str = ", ".join(g.get("sources", []))

        line = row_fmt.format(target, proto, service, conns_cnt, pkts, sources_str)
        if is_tty:
            print(f"\033[33m{line}\033[0m")
        else:
            print(line)


def _format_hosts_table(hosts: list[dict[str, Any]], is_tty: bool = True) -> None:
    if not hosts:
        print("No connected hosts found matching criteria.")
        return

    title = f"Connected Clients ({len(hosts)} found):"
    if is_tty:
        print(f"\033[1m{title}\033[0m\n")
    else:
        print(f"{title}\n")

    hdr_fmt = "{:<16}  {:<24}  {:<17}  {:<12}  {:<10}  {:>6}"
    row_fmt = "{:<16}  {:<24}  {:<17}  {:<12}  {:<10}  {:>6}"

    header = hdr_fmt.format("IP", "NAME", "MAC", "INTERFACE", "POLICY", "ACTIVE")
    if is_tty:
        print(f"\033[4m{header}\033[0m")
    else:
        print(header)
        print("-" * len(header))

    for h in hosts:
        ip = h.get("ip") or "-"
        name = h.get("name") or "Unknown"
        if len(name) > 24:
            name = name[:21] + "..."
        mac = h.get("mac") or "-"
        iface = h.get("interface") or "-"
        pol = h.get("policy") or "Main"
        act = "yes" if h.get("active") else "no"

        line = row_fmt.format(ip, name, mac, iface, pol, act)
        if is_tty and not h.get("active"):
            print(f"\033[2m{line}\033[0m")
        else:
            print(line)


def _format_wifi_table(stations: list[dict[str, Any]], is_tty: bool = True) -> None:
    if not stations:
        print("No associated Wi-Fi stations found.")
        return

    title = f"Wi-Fi Associated Stations ({len(stations)} connected):"
    if is_tty:
        print(f"\033[1m{title}\033[0m\n")
    else:
        print(f"{title}\n")

    hdr_fmt = "{:<16}  {:<22}  {:<17}  {:>7}  {:>7}  {:>7}  {:>7}  {}"
    row_fmt = "{:<16}  {:<22}  {:<17}  {:>7}  {:>7}  {:>7}  {:>7}  {}"

    header = hdr_fmt.format("IP", "NAME", "MAC", "RSSI", "TX", "RX", "UPTIME", "AP")
    if is_tty:
        print(f"\033[4m{header}\033[0m")
    else:
        print(header)
        print("-" * len(header))

    for s in stations:
        ip = s.get("ip") or "-"
        name = s.get("name") or "Unknown"
        if len(name) > 22:
            name = name[:19] + "..."
        mac = s.get("mac") or "-"
        rssi_val = s.get("rssi")
        rssi_str = f"{rssi_val}dBm" if rssi_val is not None else "-"
        tx_str = f"{s.get('txrate')}M" if s.get("txrate") is not None else "-"
        rx_str = f"{s.get('rxrate')}M" if s.get("rxrate") is not None else "-"
        try:
            up_s = int(s.get("uptime", 0))
        except (ValueError, TypeError):
            up_s = 0
        up_str = f"{up_s // 60}m" if up_s >= 60 else f"{up_s}s"
        ap = s.get("ap") or "-"



        line = row_fmt.format(ip, name, mac, rssi_str, tx_str, rx_str, up_str, ap)
        if is_tty and rssi_val is not None and rssi_val < -80:
            print(f"\033[33m{line}\033[0m")
        else:
            print(line)


def _format_doctor_report(diag: dict[str, Any], is_tty: bool = True) -> None:
    status = diag.get("status", "ok")
    system = diag.get("system", {})
    checks = diag.get("checks", {})
    issues = diag.get("issues", [])

    bold = "\033[1m" if is_tty else ""
    dim = "\033[2m" if is_tty else ""
    reset = "\033[0m" if is_tty else ""
    green = "\033[32m" if is_tty else ""
    yellow = "\033[33m" if is_tty else ""
    red = "\033[1;31m" if is_tty else ""

    status_tag = (
        f"{green}[OK]{reset}"
        if status == "ok"
        else f"{yellow}[WARNING]{reset}"
        if status == "warning"
        else f"{red}[CRITICAL]{reset}"
    )

    model = system.get("model", "Keenetic")
    release = system.get("release", "")
    dev_name = system.get("device_name", "")
    try:
        uptime_s = int(system.get("uptime", 0))
    except (ValueError, TypeError):
        uptime_s = 0
    uptime_hrs = f"{uptime_s // 3600}h {(uptime_s % 3600) // 60}m"


    print(f"{bold}=== Keenetic Diagnostic Report ==={reset}")
    print(f"Device: {bold}{dev_name or model}{reset} ({model}, KeeneticOS {release})  Uptime: {uptime_hrs}")
    print(f"Overall Health: {status_tag}\n")

    print(f"{bold}--- Subsystem Checks ---{reset}")
    for name, chk in checks.items():
        st = chk.get("status", "ok")
        tag = (
            f"{green}PASS{reset}"
            if st == "ok"
            else f"{yellow}WARN{reset}"
            if st == "warn"
            else f"{red}FAIL{reset}"
        )
        details_list = [f"{k}={v}" for k, v in chk.items() if k != "status" and v is not None]
        details_str = f" ({', '.join(details_list)})" if details_list else ""
        print(f"  [{tag}] {name:<12}{dim}{details_str}{reset}")
    print()

    if not issues:
        print(f"{green}{bold}No network anomalies or stability issues detected.{reset}")
        return

    print(f"{bold}--- Detected Issues & Anomalies ({len(issues)}) ---{reset}")
    for i, issue in enumerate(issues, 1):
        sev = issue.get("severity", "info")
        sev_color = red if sev == "critical" else yellow if sev == "warning" else dim
        sev_label = f"[{sev.upper()}]"
        title = issue.get("title", "")
        desc = issue.get("description", "")
        rec = issue.get("recommendation", "")

        print(f"{i}. {sev_color}{sev_label}{reset} {bold}{title}{reset}")
        print(f"   {dim}Details:{reset}        {desc}")
        if rec:
            print(f"   {dim}Recommendation:{reset} {rec}")
        print()


def _format_size(size_bytes: int) -> str:
    if size_bytes <= 0:
        return "-"
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.0f} KB"
    return f"{size_bytes / (1024 * 1024):.1f} MB"


def _format_components_table(comps: list[dict[str, Any]], is_tty: bool = True) -> None:
    if not comps:
        print("No components found matching criteria.")
        return

    bold = "\033[1m" if is_tty else ""
    dim = "\033[2m" if is_tty else ""
    green = "\033[32m" if is_tty else ""
    cyan = "\033[36m" if is_tty else ""
    reset = "\033[0m" if is_tty else ""

    installed_count = sum(1 for c in comps if c.get("installed"))
    title = f"KeeneticOS Components ({installed_count} installed, {len(comps)} listed):"
    print(f"{bold}{title}{reset}\n")

    hdr_fmt = "{:<24}  {:<12}  {:>8}  {:<15}  {}"
    header = hdr_fmt.format("NAME", "STATUS", "SIZE", "GROUP", "DESCRIPTION")
    print(f"{bold}{header}{reset}")
    print(f"{dim}{'-' * 95}{reset}")

    for c in comps:
        name = c.get("name", "")
        is_inst = c.get("installed", False)
        status_str = "installed" if is_inst else "available"
        status_colored = f"{green}{status_str}{reset}" if is_inst else f"{dim}{status_str}{reset}"
        size_str = _format_size(c.get("size", 0))
        grp = c.get("group", "")
        desc = c.get("description", "")

        amnezia = c.get("amnezia")
        if amnezia and amnezia.get("supported"):
            proto = amnezia.get("protocol", "AWG")
            st = amnezia.get("status", "")
            badge = f"[{cyan}AmneziaWG: {proto} {st}{reset}]"
            desc = f"{desc} {badge}" if desc else badge

        print(hdr_fmt.format(name, status_colored, size_str, grp, desc))


def _format_capabilities_report(caps: dict[str, Any], is_tty: bool = True) -> None:
    bold = "\033[1m" if is_tty else ""
    dim = "\033[2m" if is_tty else ""
    green = "\033[32m" if is_tty else ""
    yellow = "\033[33m" if is_tty else ""
    red = "\033[31m" if is_tty else ""
    reset = "\033[0m" if is_tty else ""

    dev = caps.get("device", {})
    vpn = caps.get("vpn", {})
    routing = caps.get("routing", {})
    ext = caps.get("extensions", {})

    print(f"{bold}=== Keenetic Router Capabilities ==={reset}")
    model = dev.get("model") or "Keenetic"
    release = dev.get("release") or ""
    title = dev.get("title") or release
    arch = dev.get("arch") or ""
    print(f"Device:        {bold}{model}{reset}, KeeneticOS {bold}{title}{reset} ({release}) [{arch}]")
    print(f"Components:    {caps.get('installed_components_count', 0)} installed\n")

    print(f"{bold}--- VPN & Tunneling Capabilities ---{reset}")
    wg = vpn.get("wireguard", {})
    if wg.get("installed"):
        wg_status = f"{green}[INSTALLED]{reset}"
    else:
        wg_status = f"{yellow}[AVAILABLE - NOT INSTALLED]{reset}"
    print(f"  WireGuard:     {wg_status} (component: wireguard)")

    awg = vpn.get("amnezia", {})
    if awg.get("supported"):
        awg_proto = awg.get("protocol")
        awg_st = awg.get("status")
        st_color = green if awg_st == "ready" else yellow
        print(f"  AmneziaWG:     {green}[SUPPORTED: {awg_proto}]{reset} {st_color}[STATUS: {awg_st.upper()}]{reset}")
        print(f"                 {dim}Details: {awg.get('details')}{reset}")
    else:
        print(f"  AmneziaWG:     {red}[NOT SUPPORTED]{reset} (KeeneticOS < 4.2)")

    ovpn = vpn.get("openvpn", {})
    ovpn_st = f"{green}[INSTALLED]{reset}" if ovpn.get("installed") else f"{dim}[available]{reset}"
    print(f"  OpenVPN:       {ovpn_st}")

    zt = vpn.get("zerotier", {})
    zt_st = f"{green}[INSTALLED]{reset}" if zt.get("installed") else f"{dim}[available]{reset}"
    print(f"  ZeroTier:      {zt_st}")

    sstp = vpn.get("sstp", {})
    sstp_st = f"{green}[INSTALLED]{reset}" if sstp.get("installed") else f"{dim}[available]{reset}"
    if sstp.get("server_installed"):
        sstp_st += " (server)"
    print(f"  SSTP:          {sstp_st}\n")

    print(f"{bold}--- Traffic Routing & Split Tunneling ---{reset}")
    fqdn = routing.get("fqdn_domain_routing", {})
    if fqdn.get("supported"):
        print(f"  FQDN Routing:  {green}[SUPPORTED]{reset} ({fqdn.get('method')})")
    else:
        print(f"  FQDN Routing:  {yellow}[NOT NATIVE]{reset} (Requires KeeneticOS 5.0+ or OPKG/ipset)")
    print()

    print(f"{bold}--- System Extensions ---{reset}")
    opkg_st = f"{green}[INSTALLED]{reset}" if ext.get("opkg") else f"{dim}[available]{reset}"
    print(f"  OPKG/Entware:  {opkg_st}")
    print()


def _format_services_table(services: list[dict[str, Any]], is_tty: bool = True) -> None:
    if not services:
        print("No services found.")
        return

    title = f"Router Services & Management Daemons ({len(services)} found):"
    bold = "\033[1m" if is_tty else ""
    dim = "\033[2m" if is_tty else ""
    green = "\033[32m" if is_tty else ""
    red = "\033[31m" if is_tty else ""
    yellow = "\033[33m" if is_tty else ""
    reset = "\033[0m" if is_tty else ""

    if is_tty:
        print(f"{bold}{title}{reset}\n")
    else:
        print(f"{title}\n")

    hdr_fmt = "{:<24}  {:<10}  {:<12}  {:<16}  {}"
    row_fmt = "{:<24}  {:<10}  {:<12}  {:<16}  {}"

    header = hdr_fmt.format("SERVICE", "STATUS", "PORTS", "ACCESS", "DETAILS")
    if is_tty:
        print(f"\033[4m{header}\033[0m")
    else:
        print(header)
        print("-" * len(header))

    for s in services:
        title_str = s.get("title") or s.get("name") or "Unknown"
        if len(title_str) > 24:
            title_str = title_str[:21] + "..."
        enabled = s.get("enabled", False)
        status_str = "active" if enabled else "disabled"
        status_colored = f"{green}{status_str}{reset}" if enabled else f"{dim}{status_str}{reset}"
        ports = s.get("ports", [])
        port_str = ", ".join(str(p) for p in ports) if ports else "-"
        access = s.get("security_level") or "-"
        access_colored = access
        if is_tty:
            if "public" in access and "ssl" not in access and s.get("name") in ("telnet", "http"):
                access_colored = f"{red}{access}{reset}"
            elif "public" in access:
                access_colored = f"{yellow}{access}{reset}"
            else:
                access_colored = f"{dim}{access}{reset}"

        details = s.get("details") or "-"
        line = row_fmt.format(title_str, status_colored, port_str, access_colored, details)
        if is_tty and not enabled:
            print(f"{dim}{line}{reset}")
        else:
            print(line)


def _format_error(err: KeeneticError, raw_json: bool = False) -> None:

    """Format and print KeeneticError nicely for TTY or machine consumers."""
    if raw_json:
        payload = {
            "error": True,
            "type": err.error_type,
            "message": err.message,
            "hint": err.hint,
            **err.details,
        }
        clean_payload = {k: v for k, v in payload.items() if v is not None}
        print(json.dumps(clean_payload, ensure_ascii=False), file=sys.stderr)
    else:
        is_tty = sys.stderr.isatty()
        if is_tty:
            bold_red = "\033[1;31m"
            dim = "\033[2m"
            cyan = "\033[36m"
            reset = "\033[0m"
            print(f"{bold_red}Error:{reset} {err.message}", file=sys.stderr)
            if err.hint:
                print(f"{cyan}Hint:{reset}  {dim}{err.hint}{reset}", file=sys.stderr)
        else:
            print(f"Error: {err.message}", file=sys.stderr)
            if err.hint:
                print(f"Hint:  {err.hint}", file=sys.stderr)


def _normalize_argv(argv: list[str]) -> list[str]:
    """Normalize -p - to --password-stdin, and hoist global flags (like --json) so they can appear anywhere."""
    pass_norm = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-p", "--password", "--ask-pass") and i + 1 < len(argv) and argv[i + 1] == "-":
            pass_norm.append("--password-stdin")
            i += 2
            continue
        pass_norm.append(arg)
        i += 1

    global_args = []
    other_args = []
    i = 0
    while i < len(pass_norm):
        arg = pass_norm[i]
        if arg in ("--json", "--password-stdin", "--ssl", "--https"):
            global_args.append(arg)
            i += 1
        elif arg in ("-H", "--host", "-u", "--user", "--timeout") and i + 1 < len(pass_norm):
            global_args.extend([arg, pass_norm[i + 1]])
            i += 2
        elif arg in ("-p", "--ask-pass", "--password"):
            global_args.append(arg)
            i += 1
        else:
            if arg == "diagnose":
                arg = "doctor"
            other_args.append(arg)
            i += 1

    return [*global_args, *other_args]



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keenctl",
        description="Lightweight RCI control plane for Keenetic routers",
    )
    parser.add_argument(
        "--host",
        "-H",
        default=os.getenv("KEENETIC_HOST", "192.168.1.1"),
        help="Router IP, domain, or full URL (default: $KEENETIC_HOST or 192.168.1.1)",
    )
    parser.add_argument(
        "--ssl",
        "--https",
        dest="ssl",
        action="store_true",
        default=os.getenv("KEENETIC_SSL", "").lower() in ("1", "true", "yes")
        or os.getenv("KEENETIC_HTTPS", "").lower() in ("1", "true", "yes"),
        help="Force HTTPS connection (default: auto-detect HTTP then HTTPS)",
    )
    parser.add_argument(
        "--user",
        "-u",
        default=os.getenv("KEENETIC_USER", "admin"),
        help="Router admin username (default: $KEENETIC_USER or admin)",
    )
    parser.add_argument(
        "-p",
        "--ask-pass",
        "--password",
        dest="ask_pass",
        action="store_true",
        help="Prompt interactively for password (safe getpass, no terminal echo)",
    )
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read password from standard input (stdin)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Force compact machine-parsable JSON output",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP request timeout in seconds (default: 10.0)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. RCI GET
    get_p = subparsers.add_parser("get", help="Query RCI GET path (e.g. show/system, show/ip/hotspot)")
    get_p.add_argument("path", help="RCI tree path (e.g. show/system, show/interface, ip/hotspot)")

    # 2. RCI POST
    post_p = subparsers.add_parser("post", help="Mutate RCI configuration branch via POST")
    post_p.add_argument("path", nargs="?", default="", help="RCI tree path (leave empty for root)")
    post_p.add_argument("data", nargs="?", help="JSON payload string (or pass via stdin)")

    # 3. RCI CLI command
    cmd_p = subparsers.add_parser("cmd", help="Execute native Keenetic CLI command via RCI parser")
    cmd_p.add_argument("cli_command", nargs="+", help="CLI command string (e.g. 'show ip hotspot')")

    # 4. High-level shortcuts
    subparsers.add_parser("info", help="Summary of router status and system details")

    hosts_p = subparsers.add_parser("hosts", help="List connected hotspot clients")
    hosts_p.add_argument("--active", "-a", action="store_true", help="Filter active devices only")
    hosts_p.add_argument("--interface", "-i", help="Filter by network interface (e.g. Bridge0, Bridge2)")
    hosts_p.add_argument("--subnet", "-s", help="Filter by IP subnet or prefix (e.g. 192.168.1.0/24 or 192.168.1.)")

    wifi_p = subparsers.add_parser("wifi", help="Inspect connected Wi-Fi stations and signal metrics")

    doctor_p = subparsers.add_parser(
        "doctor",
        aliases=["diagnose"],
        help="Run comprehensive automated network health check",
    )

    backup_p = subparsers.add_parser("backup", help="Download current running-config to file")
    backup_p.add_argument("-o", "--output", help="Destination file path")

    save_p = subparsers.add_parser("save", help="Commit running-config to flash (system configuration save)")
    save_p.add_argument("--yes", "-y", action="store_true", help="Bypass confirmation prompt")

    ifaces_p = subparsers.add_parser("interfaces", help="List network interfaces and their status")
    ifaces_p.add_argument("--active", "-a", action="store_true", help="Filter active / up interfaces only")

    subparsers.add_parser("routes", help="Show active routing table")


    conntrack_p = subparsers.add_parser(
        "conntrack",
        help="Inspect connection tracking (NAT/conntrack) table and dead connections",
    )
    conntrack_p.add_argument(
        "--unreplied",
        "-U",
        action="store_true",
        help="Filter connections that received no response (packets-out == 0)",
    )
    conntrack_p.add_argument(
        "--group",
        "-g",
        action="store_true",
        help="Group unreplied connections by destination target",
    )
    conntrack_p.add_argument(
        "--proto",
        "-P",
        choices=["all", "tcp", "udp", "icmp"],
        default="all",
        help="Filter by protocol (default: all)",
    )
    conntrack_p.add_argument(
        "--src",
        "-s",
        help="Filter by source IP address",
    )
    conntrack_p.add_argument(
        "--dst",
        "-d",
        help="Filter by destination IP address",
    )
    conntrack_p.add_argument(
        "--include-broadcast",
        "-b",
        action="store_true",
        help="Include multicast and broadcast packets in unreplied output",
    )
    conntrack_p.add_argument(
        "--no-resolve",
        action="store_true",
        help="Disable resolving IP addresses to device hostnames",
    )
    conntrack_p.add_argument(
        "-n",
        "--limit",
        type=int,
        default=100,
        help="Maximum number of connections to display (default: 100, 0 for unlimited)",
    )

    log_p = subparsers.add_parser("log", help="Display router system event log")
    log_p.add_argument("-n", "--lines", type=int, default=50, help="Number of log entries to show (default: 50, 0 for all)")
    log_p.add_argument("-l", "--level", help="Filter by minimum severity (debug, info, notice, warning, error, critical)")
    log_p.add_argument("-s", "--service", "--ident", dest="service", help="Filter by service / daemon (e.g. ndm, ndhcps, wpa_supplicant)")
    log_p.add_argument("-g", "--grep", help="Filter log messages containing text")

    reboot_p = subparsers.add_parser("reboot", help="Reboot the router (system reboot)")
    reboot_p.add_argument("--yes", "-y", action="store_true", help="Bypass confirmation prompt")

    # services
    services_p = subparsers.add_parser(
        "services",
        help="Inspect router management daemons and network services (SSH, Telnet, Web, SSTP, etc.)",
    )
    services_p.add_argument(
        "--all", "-a",
        action="store_true",
        help="Include low-level background network daemons (DHCP, DNS proxy, NTP, mDNS, UPnP)",
    )
    services_p.add_argument(
        "--management", "-m",
        action="store_true",
        help="Show only remote management and access daemons (HTTP, SSH, Telnet, SSTP)",
    )

    # capabilities
    subparsers.add_parser("capabilities", help="Inspect router capabilities (AmneziaWG, routing, OPKG)")

    # components
    comp_p = subparsers.add_parser("components", help="Inspect and manage KeeneticOS system components")
    comp_p.add_argument("--installed", "-i", action="store_true", help="Show only installed components")
    comp_p.add_argument("--available", "-a", action="store_true", help="Show only available components to install")
    comp_p.add_argument("--group", "-g", help="Filter by component group (e.g. Networking, Storage)")
    comp_p.add_argument("--channel", "-c", default="", help="Update channel (e.g. stable, preview, draft)")

    comp_sub = comp_p.add_subparsers(dest="components_action", required=False)

    comp_list_p = comp_sub.add_parser("list", help="List system components")
    comp_list_p.add_argument("--installed", "-i", action="store_true", help="Show only installed components")
    comp_list_p.add_argument("--available", "-a", action="store_true", help="Show only available components to install")
    comp_list_p.add_argument("--group", "-g", help="Filter by component group (e.g. Networking, Storage)")
    comp_list_p.add_argument("--channel", "-c", default="", help="Update channel (e.g. stable, preview, draft)")

    comp_search_p = comp_sub.add_parser("search", help="Search components by name or description")
    comp_search_p.add_argument("query", help="Search keyword")
    comp_search_p.add_argument("--channel", "-c", default="", help="Update channel (e.g. stable, preview, draft)")

    comp_inst_p = comp_sub.add_parser("install", help="Queue component for installation")
    comp_inst_p.add_argument("component_name", help="Component name (e.g. wireguard, zerotier)")
    comp_inst_p.add_argument("--commit", action="store_true", help="Apply changes immediately (triggers router reboot)")
    comp_inst_p.add_argument("-y", "--yes", action="store_true", help="Bypass reboot confirmation prompt")

    comp_rem_p = comp_sub.add_parser("remove", help="Queue component for removal")
    comp_rem_p.add_argument("component_name", help="Component name (e.g. tor, dlna)")
    comp_rem_p.add_argument("--commit", action="store_true", help="Apply changes immediately (triggers router reboot)")
    comp_rem_p.add_argument("-y", "--yes", action="store_true", help="Bypass reboot confirmation prompt")

    comp_commit_p = comp_sub.add_parser("commit", help="Commit component changes (rebuilds firmware and reboots)")
    comp_commit_p.add_argument("-y", "--yes", action="store_true", help="Bypass reboot confirmation prompt")

    return parser


def main() -> None:
    _load_env_file()
    parser = build_parser()
    normalized_argv = _normalize_argv(sys.argv[1:])
    args = parser.parse_args(normalized_argv)

    if args.password_stdin:
        password = sys.stdin.readline().strip()
    elif args.ask_pass:
        import getpass

        if sys.stdin.isatty():
            password = getpass.getpass(f"Password for {args.user}@{args.host}: ")
        else:
            print("Error: -p/--ask-pass requires an interactive terminal", file=sys.stderr)
            sys.exit(1)
    else:
        password = os.getenv("KEENETIC_PASSWORD", "")

    client = KeeneticClient(
        host=args.host,
        user=args.user,
        password=password,
        ssl=args.ssl,
        timeout=args.timeout,
    )

    try:
        if args.command == "get":
            res = client.get(args.path)
            _output(res, raw_json=args.json)

        elif args.command == "post":
            raw_payload = args.data
            if raw_payload is None and not sys.stdin.isatty():
                raw_payload = sys.stdin.read().strip()

            if not raw_payload:
                print("Error: POST requires a JSON payload", file=sys.stderr)
                sys.exit(1)

            try:
                payload = json.loads(raw_payload)
            except json.JSONDecodeError as err:
                print(f"Error: Invalid JSON payload: {err}", file=sys.stderr)
                sys.exit(1)

            res = client.post(args.path, data=payload)
            _output(res, raw_json=args.json)

        elif args.command == "cmd":
            full_cmd = " ".join(args.cli_command)
            res = client.cmd(full_cmd)
            _output(res, raw_json=args.json)

        elif args.command == "info":
            sys_info = client.get("show/system")
            ver_info = client.get("show/version")
            net_info = client.get("show/internet/status")
            mgmt_active: list[str] = []
            try:
                svcs = client.get_services()
                mgmt_active = [
                    s["name"] for s in svcs
                    if s.get("enabled") and s.get("category") in ("management", "vpn")
                ]
            except Exception:
                pass
            summary = {
                "model": ver_info.get("model"),
                "release": ver_info.get("release"),
                "device_name": ver_info.get("device"),
                "uptime": sys_info.get("uptime"),
                "cpuload": sys_info.get("cpuload"),
                "memory": sys_info.get("memory"),
                "internet": net_info.get("internet", False),
                "gateway": net_info.get("gateway", {}).get("interface"),
                "mgmt_services": mgmt_active,
            }
            _output(summary, raw_json=args.json)

        elif args.command == "hosts":
            hosts = client.get_hosts(
                active_only=args.active,
                interface=args.interface,
                subnet=args.subnet,
            )
            if args.json or not sys.stdout.isatty():
                _output(hosts, raw_json=True)
            else:
                _format_hosts_table(hosts, is_tty=True)

        elif args.command == "wifi":
            stations = client.get_wifi_associations()
            if args.json or not sys.stdout.isatty():
                _output(stations, raw_json=True)
            else:
                _format_wifi_table(stations, is_tty=True)

        elif args.command == "doctor":
            diag = client.diagnose()
            if args.json or not sys.stdout.isatty():
                _output(diag, raw_json=True)
            else:
                _format_doctor_report(diag, is_tty=True)


        elif args.command == "backup":
            path = client.backup(destination=args.output)
            if args.json:
                _output({"backup_file": str(path)}, raw_json=True)
            else:
                print(f"Backup saved to: {path}")

        elif args.command == "save":
            if not args.yes and sys.stdin.isatty():
                ans = input("Save running configuration to router flash? [y/N]: ").strip().lower()
                if ans not in ("y", "yes"):
                    print("Aborted.")
                    sys.exit(0)

            res = client.save_config()
            _output(res, raw_json=args.json)

        elif args.command == "interfaces":
            res = client.get_interfaces(active_only=args.active)
            _output(res, raw_json=args.json)

        elif args.command == "routes":
            res = client.get_routes()
            _output(res, raw_json=args.json)

        elif args.command == "conntrack":
            conns = client.get_conntrack(
                unreplied_only=args.unreplied,
                proto=args.proto,
                include_broadcast=args.include_broadcast,
                resolve_names=not args.no_resolve,
                src=args.src,
                dst=args.dst,
                limit=args.limit,
            )
            if args.group:
                grouped = group_unreplied_conntrack(conns)
                if args.json:
                    _output(grouped, raw_json=True)
                else:
                    _format_conntrack_grouped(grouped, is_tty=sys.stdout.isatty())
            else:
                if args.json:
                    _output(conns, raw_json=True)
                else:
                    _format_conntrack_table(conns, unreplied_only=args.unreplied, is_tty=sys.stdout.isatty())

        elif args.command == "log":
            logs = client.get_log(
                lines=args.lines,
                level=args.level,
                service=args.service,
                grep=args.grep,
            )
            if args.json:
                _output(logs, raw_json=True)
            else:
                is_tty = sys.stdout.isatty()
                for entry in logs:
                    print(_format_log_line(entry, is_tty=is_tty))

        elif args.command == "reboot":
            if not args.yes and sys.stdin.isatty():
                ans = input("Are you sure you want to REBOOT the router? [y/N]: ").strip().lower()
                if ans not in ("y", "yes"):
                    print("Aborted.")
                    sys.exit(0)

            client.reboot()
            _output({"status": "rebooting", "message": "Router is rebooting..."}, raw_json=args.json)

        elif args.command == "capabilities":
            caps = client.get_capabilities()
            if args.json or not sys.stdout.isatty():
                _output(caps, raw_json=True)
            else:
                _format_capabilities_report(caps, is_tty=True)

        elif args.command == "services":
            svcs = client.get_services(
                management_only=args.management,
                all_services=args.all,
            )
            if args.json or not sys.stdout.isatty():
                _output(svcs, raw_json=True)
            else:
                _format_services_table(svcs, is_tty=True)

        elif args.command == "components":
            action = getattr(args, "components_action", None) or "list"

            if action == "list":
                installed = getattr(args, "installed", False)
                available = getattr(args, "available", False)
                grp = getattr(args, "group", None)
                chn = getattr(args, "channel", "")
                comps = client.get_components(
                    channel=chn,
                    installed_only=installed,
                    available_only=available,
                    group=grp,
                )
                if args.json or not sys.stdout.isatty():
                    _output(comps, raw_json=True)
                else:
                    _format_components_table(comps, is_tty=True)

            elif action == "search":
                chn = getattr(args, "channel", "")
                comps = client.get_components(
                    channel=chn,
                    search_query=args.query,
                )
                if args.json or not sys.stdout.isatty():
                    _output(comps, raw_json=True)
                else:
                    _format_components_table(comps, is_tty=True)

            elif action == "install":
                client.install_component(args.component_name)
                if not args.commit:
                    if args.json:
                        _output({"status": "queued", "action": "install", "component": args.component_name}, raw_json=True)
                    else:
                        print(f"Component '{args.component_name}' queued for installation.")
                        print("Run 'keen components commit' to build firmware and apply (warning: router will reboot).")
                else:
                    if not args.yes and sys.stdin.isatty():
                        ans = input(f"Warning: installing '{args.component_name}' and committing will REBOOT the router (~2-3 min downtime). Proceed? [y/N]: ").strip().lower()
                        if ans not in ("y", "yes"):
                            print("Aborted commit. Component remains queued.")
                            sys.exit(0)
                    commit_res = client.commit_components()
                    if args.json:
                        _output({"status": "committing", "component": args.component_name, "result": commit_res}, raw_json=True)
                    else:
                        print(f"Component '{args.component_name}' committed. Router is rebuilding firmware and will reboot.")

            elif action == "remove":
                client.remove_component(args.component_name)
                if not args.commit:
                    if args.json:
                        _output({"status": "queued", "action": "remove", "component": args.component_name}, raw_json=True)
                    else:
                        print(f"Component '{args.component_name}' queued for removal.")
                        print("Run 'keen components commit' to build firmware and apply (warning: router will reboot).")
                else:
                    if not args.yes and sys.stdin.isatty():
                        ans = input(f"Warning: removing '{args.component_name}' and committing will REBOOT the router (~2-3 min downtime). Proceed? [y/N]: ").strip().lower()
                        if ans not in ("y", "yes"):
                            print("Aborted commit. Component remains queued.")
                            sys.exit(0)
                    commit_res = client.commit_components()
                    if args.json:
                        _output({"status": "committing", "component": args.component_name, "result": commit_res}, raw_json=True)
                    else:
                        print(f"Component '{args.component_name}' committed for removal. Router is rebuilding firmware and will reboot.")

            elif action == "commit":
                if not args.yes and sys.stdin.isatty():
                    ans = input("Warning: committing components will request a cloud firmware build and REBOOT the router (~2-3 min downtime). Proceed? [y/N]: ").strip().lower()
                    if ans not in ("y", "yes"):
                        print("Aborted.")
                        sys.exit(0)
                commit_res = client.commit_components()
                if args.json:
                    _output({"status": "committing", "result": commit_res}, raw_json=True)
                else:
                    print("Component changes committed. Router is rebuilding firmware and will reboot.")

    except KeeneticError as err:
        _format_error(err, raw_json=args.json)
        sys.exit(1)
    finally:
        client.close()


if __name__ == "__main__":
    main()
