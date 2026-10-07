from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx


class KeeneticError(Exception):
    """Base exception for keenctl errors."""

    def __init__(
        self,
        message: str,
        hint: str | None = None,
        error_type: str = "general_error",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint
        self.error_type = error_type
        self.details = details or {}


class KeeneticConnectionError(KeeneticError):
    """Raised when network connection or transport fails."""

    def __init__(
        self,
        message: str,
        hint: str | None = None,
        host: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            hint=hint or "Check your network connection, VPN status, or KEENETIC_HOST.",
            error_type="connection_error",
            details={"host": host, **(details or {})},
        )
        self.host = host


class KeeneticAuthError(KeeneticError):
    """Raised when authentication with the router fails."""

    def __init__(
        self,
        message: str,
        hint: str | None = None,
        user: str | None = None,
        host: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            hint=hint or "Verify KEENETIC_USER and KEENETIC_PASSWORD credentials.",
            error_type="auth_error",
            details={"user": user, "host": host, **(details or {})},
        )
        self.user = user
        self.host = host


class KeeneticCommandError(KeeneticError):
    """Raised when an RCI command returns an error status."""

    def __init__(
        self,
        message: str,
        command: str | None = None,
        hint: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            hint=hint or "Verify command syntax against router CLI (try 'show running-config').",
            error_type="command_error",
            details={"command": command, **(details or {})},
        )
        self.command = command


class KeeneticHttpError(KeeneticError):
    """Raised when router or proxy returns an unexpected HTTP status."""

    def __init__(
        self,
        status_code: int,
        path: str,
        message: str,
        hint: str | None = None,
        host: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            hint=hint,
            error_type="http_error",
            details={"status_code": status_code, "path": path, "host": host, **(details or {})},
        )
        self.status_code = status_code
        self.path = path
        self.host = host


@dataclass
class SessionCache:
    cookies: dict[str, str]
    expires_at: float


class KeeneticClient:
    """Lightweight, resilient client for KeeneticOS RCI API."""

    def __init__(
        self,
        host: str | None = None,
        user: str | None = None,
        password: str | None = None,
        ssl: bool = False,
        timeout: float = 10.0,
        verify: bool = False,
        cache_dir: Path | None = None,
    ) -> None:
        self.cache_dir = (
            cache_dir or Path.home() / ".cache" / "keenctl"
        )
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.timeout = timeout
        self.verify = verify

        ssl_env = os.getenv("KEENETIC_SSL", "").lower() in ("1", "true", "yes") or os.getenv("KEENETIC_HTTPS", "").lower() in ("1", "true", "yes")
        self.ssl = ssl or ssl_env

        raw_host = (host or os.getenv("KEENETIC_HOST") or "192.168.1.1").strip().rstrip("/")
        self.raw_host = raw_host
        self.host = self._resolve_host(raw_host, ssl=self.ssl)

        self.user = user or os.getenv("KEENETIC_USER") or "admin"
        self.password = password or os.getenv("KEENETIC_PASSWORD") or ""

        # Unique cache file per host + user
        key = hashlib.sha256(f"{self.host}:{self.user}".encode()).hexdigest()[:16]
        self.cache_file = self.cache_dir / f"session_{key}.json"

        self._client = httpx.Client(
            timeout=self.timeout,
            verify=self.verify,
            follow_redirects=True,
        )
        self._load_cached_session()

    def _resolve_host(self, raw_host: str, ssl: bool = False) -> str:
        """Resolve router URL: support bare domain/IP, auto-detect HTTP vs HTTPS, or force SSL."""
        clean = raw_host.strip().rstrip("/")
        if not clean:
            clean = "192.168.1.1"

        # Explicit scheme given
        if clean.startswith("http://") or clean.startswith("https://"):
            if ssl and clean.startswith("http://"):
                return "https://" + clean[len("http://"):]
            return clean

        # Forced SSL flag
        if ssl:
            return f"https://{clean}"

        # Check cached scheme if available
        schemes_cache_file = self.cache_dir / "schemes.json"
        cached_schemes: dict[str, str] = {}
        if schemes_cache_file.exists():
            try:
                cached_schemes = json.loads(schemes_cache_file.read_text(encoding="utf-8"))
                if clean in cached_schemes:
                    return f"{cached_schemes[clean]}://{clean}"
            except Exception:
                pass

        # Auto-detect: probe HTTP first
        detected_scheme = "http"
        http_url = f"http://{clean}"
        probe_timeout = min(self.timeout, 2.0)
        try:
            with httpx.Client(timeout=probe_timeout, verify=self.verify, follow_redirects=False) as probe:
                resp = probe.get(f"{http_url}/auth")
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("Location", "")
                    if loc.startswith("https://"):
                        detected_scheme = "https"
                else:
                    detected_scheme = "http"
        except Exception:
            # HTTP failed, probe HTTPS
            try:
                with httpx.Client(timeout=probe_timeout, verify=self.verify, follow_redirects=False) as probe:
                    probe.get(f"https://{clean}/auth")
                    detected_scheme = "https"
            except Exception:
                detected_scheme = "http"

        # Cache detected scheme
        try:
            cached_schemes[clean] = detected_scheme
            schemes_cache_file.write_text(json.dumps(cached_schemes), encoding="utf-8")
        except Exception:
            pass

        return f"{detected_scheme}://{clean}"

    def _load_cached_session(self) -> None:
        if not self.cache_file.exists():
            return
        try:
            data = json.loads(self.cache_file.read_text(encoding="utf-8"))
            if time.time() < data.get("expires_at", 0):
                self._client.cookies.update(data.get("cookies", {}))
        except Exception:
            # Corrupted cache file: drop silently
            self.cache_file.unlink(missing_ok=True)

    def _save_cached_session(self) -> None:
        try:
            # 280 seconds window (Keenetic sliding window is 300s)
            cache = SessionCache(
                cookies=dict(self._client.cookies),
                expires_at=time.time() + 280.0,
            )
            self.cache_file.write_text(
                json.dumps({"cookies": cache.cookies, "expires_at": cache.expires_at}),
                encoding="utf-8",
            )
        except Exception:
            pass

    def _parse_transport_error(self, exc: httpx.RequestError) -> KeeneticConnectionError:
        err_str = str(exc)
        if isinstance(exc, (httpx.ConnectTimeout, httpx.TimeoutException)):
            msg = f"Connection to {self.host} timed out ({self.timeout}s)"
            hint = f"Router at {self.host} did not respond within {self.timeout}s. Check if host is online."
        elif "No route to host" in err_str or "113" in err_str:
            msg = f"No route to host {self.host}"
            hint = "Network routing failed. If accessing via VPN/tunnel (e.g. WireGuard/SSTP), ensure tunnel is active. Check KEENETIC_HOST."
        elif "Connection refused" in err_str or "111" in err_str:
            msg = f"Connection refused by {self.host}"
            hint = f"Host {self.host} is reachable, but port is closed. Check port and scheme (http vs https) in KEENETIC_HOST."
        elif "Name or service not known" in err_str or "gaierror" in err_str or "Temporary failure in name resolution" in err_str:
            msg = f"Could not resolve router hostname '{self.host}'"
            hint = "DNS resolution failed. Check your DNS resolver, internet access, or router domain name."
        # Invalidate scheme cache on transport failure so fresh probe can occur next time
        try:
            schemes_file = self.cache_dir / "schemes.json"
            if schemes_file.exists():
                schemes = json.loads(schemes_file.read_text(encoding="utf-8"))
                clean_host = self.raw_host.replace("https://", "").replace("http://", "").split("/")[0]
                if clean_host in schemes:
                    del schemes[clean_host]
                    schemes_file.write_text(json.dumps(schemes), encoding="utf-8")
        except Exception:
            pass

        return KeeneticConnectionError(message=msg, hint=hint, host=self.host, details={"raw_error": err_str})

    def _parse_http_error(self, exc: httpx.HTTPStatusError, clean_path: str) -> KeeneticHttpError:
        code = exc.response.status_code
        body = exc.response.text.strip()
        is_html = "<html" in body.lower() or "<!doctype" in body.lower()

        if code == 404:
            if is_html:
                msg = f"HTTP 404 Not Found for endpoint '/rci/{clean_path}' at {self.host}"
                hint = f"Host {self.host} returned an HTML 404 page. It does not appear to be a Keenetic router. Check KEENETIC_HOST."
            else:
                msg = f"RCI path '/rci/{clean_path}' not found (HTTP 404)"
                hint = f"Endpoint '/rci/{clean_path}' does not exist on this KeeneticOS version."
        elif code == 403:
            msg = f"HTTP 403 Forbidden for '/rci/{clean_path}'"
            hint = "Access forbidden. User account might lack required administrative privileges."
        elif code >= 500:
            msg = f"HTTP {code} Server Error from {self.host}"
            hint = "Router web server returned internal error. Check router system logs."
        else:
            short_body = body[:200] if not is_html else "(HTML error page)"
            msg = f"HTTP {code} error for '/rci/{clean_path}': {short_body}"
            hint = f"Unexpected HTTP status {code} from router."

        return KeeneticHttpError(
            status_code=code,
            path=clean_path,
            message=msg,
            hint=hint,
            host=self.host,
        )

    def authenticate(self) -> None:
        """Authenticate using Keenetic NDM challenge-response protocol."""
        if not self.password:
            import getpass
            import sys

            if sys.stdin.isatty():
                self.password = getpass.getpass(f"Password for {self.user}@{self.host}: ")
            else:
                raise KeeneticAuthError(
                    message=f"Password is required for {self.user}@{self.host} (set $KEENETIC_PASSWORD or pass via -p)",
                    hint="Set KEENETIC_PASSWORD environment variable or pass password via -p / --password-stdin.",
                    user=self.user,
                    host=self.host,
                )

        auth_url = f"{self.host}/auth"
        try:
            resp = self._client.get(auth_url)
            if resp.status_code == 200:
                self._save_cached_session()
                return

            realm = resp.headers.get("X-NDM-Realm")
            challenge = resp.headers.get("X-NDM-Challenge")

            if not realm or not challenge:
                raise KeeneticAuthError(
                    message=f"Router at {self.host} did not provide X-NDM auth challenge headers",
                    hint=f"Target {self.host} does not behave like a Keenetic router. Verify KEENETIC_HOST.",
                    user=self.user,
                    host=self.host,
                )

            # Keenetic challenge-response hash
            md5_hash = hashlib.md5(
                f"{self.user}:{realm}:{self.password}".encode("utf-8")
            ).hexdigest()
            auth_key = hashlib.sha256(
                f"{challenge}{md5_hash}".encode("utf-8")
            ).hexdigest()

            login_resp = self._client.post(
                auth_url,
                json={"login": self.user, "password": auth_key},
            )

            if login_resp.status_code != 200:
                raise KeeneticAuthError(
                    message=f"Authentication failed for user '{self.user}' (status {login_resp.status_code})",
                    hint="Invalid credentials. Check KEENETIC_USER and KEENETIC_PASSWORD in ~/.config/keenctl/.env.",
                    user=self.user,
                    host=self.host,
                )

            self._save_cached_session()
        except httpx.RequestError as exc:
            raise self._parse_transport_error(exc) from exc

    def request(
        self,
        method: str,
        path: str,
        json_body: Any = None,
        retry_auth: bool = True,
    ) -> Any:
        """Send an authenticated request to the router's RCI endpoint."""
        clean_path = path.lstrip("/")
        url = f"{self.host}/rci/{clean_path}" if clean_path else f"{self.host}/rci/"

        try:
            resp = self._client.request(method, url, json=json_body)

            # Lazy re-authentication on expired 300s window (401 Unauthorized)
            if resp.status_code == 401 and retry_auth:
                self.authenticate()
                resp = self._client.request(method, url, json=json_body)

            if resp.status_code == 401:
                raise KeeneticAuthError(
                    message=f"Rejected credentials for user '{self.user}' at {self.host}",
                    hint="Router rejected credentials. Check KEENETIC_USER and KEENETIC_PASSWORD.",
                    user=self.user,
                    host=self.host,
                )

            resp.raise_for_status()

            if not resp.content:
                return {}

            return resp.json()
        except httpx.HTTPStatusError as exc:
            raise self._parse_http_error(exc, clean_path) from exc
        except httpx.RequestError as exc:
            raise self._parse_transport_error(exc) from exc

    def get(self, path: str) -> Any:
        """Read operational state or configuration branch via RCI GET."""
        return self.request("GET", path)

    def post(self, path: str = "", data: Any = None) -> Any:
        """Execute a configuration mutation via RCI POST."""
        return self.request("POST", path, json_body=data)

    def cmd(self, command_str: str) -> Any:
        """Execute any native Keenetic CLI command via RCI parser {"parse": "..."}."""
        payload = [{"parse": command_str}]
        result = self.request("POST", "", json_body=payload)

        # Validate command outcome against silent errors
        if isinstance(result, list) and len(result) > 0:
            first = result[0]
            if isinstance(first, dict):
                statuses = first.get("status", [])
                if isinstance(statuses, list):
                    for st in statuses:
                        if isinstance(st, dict) and st.get("error"):
                            msg = st.get("message") or "Unknown RCI command error"
                            raise KeeneticCommandError(
                                message=f"Command '{command_str}' failed: {msg}",
                                command=command_str,
                                hint=f"Keenetic CLI returned syntax or execution error: {msg}",
                            )

                # Return the inner parse payload if available
                if "parse" in first:
                    return first["parse"]

        return result

    def backup(self, destination: Path | str | None = None) -> Path:
        """Download running-config and save to a local backup file."""
        config_text = self.cmd("show running-config")
        if not isinstance(config_text, str):
            # Sometimes returned as dict with text content
            config_text = json.dumps(config_text, indent=2)

        if destination is None:
            state_dir = Path.home() / ".local" / "state" / "keenctl" / "backups"
            state_dir.mkdir(parents=True, exist_ok=True)
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            host_clean = self.host.replace("http://", "").replace("https://", "").replace(":", "_").replace("/", "")
            dest_path = state_dir / f"{host_clean}_{timestamp}.cfg"
        else:
            dest_path = Path(destination)
            dest_path.parent.mkdir(parents=True, exist_ok=True)

        dest_path.write_text(config_text, encoding="utf-8")
        return dest_path

    def save_config(self) -> Any:
        """Persist current running-config to flash (system configuration save)."""
        return self.cmd("system configuration save")

    def reboot(self) -> Any:
        """Reboot the router (system reboot)."""
        return self.cmd("system reboot")

    def get_interfaces(self, active_only: bool = False) -> list[dict[str, Any]]:
        """Query and format interface states from show/interface."""
        raw = self.get("show/interface")
        res = []
        if isinstance(raw, dict):
            for name, data in raw.items():
                if not isinstance(data, dict):
                    continue
                state = data.get("state", "down")
                link = data.get("link", "down")
                if active_only and (state != "up" and link != "up"):
                    continue
                res.append({
                    "name": name,
                    "type": data.get("type") or data.get("interface-type") or "",
                    "state": state,
                    "link": link,
                    "ip": data.get("address"),
                    "mask": data.get("mask"),
                    "description": data.get("description", ""),
                })
        return res

    def get_routes(self) -> list[dict[str, Any]]:
        """Query and format routing table from show/ip/route."""
        raw = self.get("show/ip/route")
        route_list = raw if isinstance(raw, list) else raw.get("route", []) if isinstance(raw, dict) else []
        res = []
        for r in route_list:
            if not isinstance(r, dict):
                continue
            dest = r.get("destination") or r.get("network") or r.get("dst")
            mask = r.get("mask") or r.get("prefix")
            gateway = r.get("gateway") or r.get("via") or r.get("nexthop")
            iface = r.get("interface", {}).get("name") if isinstance(r.get("interface"), dict) else r.get("interface")
            res.append({
                "destination": f"{dest}/{mask}" if dest and mask else (dest or "default"),
                "gateway": gateway,
                "interface": iface,
                "proto": r.get("proto") or r.get("protocol"),
                "metric": r.get("metric"),
                "flags": r.get("flags"),
            })
        return res

    def get_hosts(
        self,
        active_only: bool = False,
        interface: str | None = None,
        subnet: str | None = None,
    ) -> list[dict[str, Any]]:
        """Query and filter connected hosts from show/ip/hotspot."""
        hotspot = self.get("show/ip/hotspot")
        raw_hosts = hotspot.get("host", []) if isinstance(hotspot, dict) else []

        results: list[dict[str, Any]] = []
        for h in raw_hosts:
            if not isinstance(h, dict):
                continue

            active = bool(h.get("active", False))
            if active_only and not active:
                continue

            iface_val = h.get("interface")
            iface_name = (
                iface_val.get("name") or iface_val.get("id")
                if isinstance(iface_val, dict)
                else str(iface_val) if iface_val else None
            )

            if interface:
                target_if = interface.lower()
                matches = False
                if iface_name and target_if in iface_name.lower():
                    matches = True
                elif isinstance(iface_val, dict):
                    if iface_val.get("id") and target_if in str(iface_val.get("id")).lower():
                        matches = True
                    elif iface_val.get("description") and target_if in str(iface_val.get("description")).lower():
                        matches = True
                if not matches:
                    continue

            ip = h.get("ip")
            if subnet and ip:
                if not is_ip_in_subnet(ip, subnet):
                    continue

            results.append({
                "name": h.get("name") or h.get("hostname") or "Unknown",
                "ip": ip,
                "mac": h.get("mac"),
                "interface": iface_name,
                "policy": h.get("policy"),
                "active": active,
                "rxbytes": h.get("rxbytes", 0),
                "txbytes": h.get("txbytes", 0),
                "uptime": h.get("uptime"),
                "last_seen": h.get("last-seen"),
            })

        return results

    def get_wifi_associations(self) -> list[dict[str, Any]]:
        """Query connected Wi-Fi stations from show/associations safely."""
        try:
            raw = self.get("show/associations")
        except Exception:
            return []

        stations = raw.get("station", []) if isinstance(raw, dict) else []
        if not isinstance(stations, list):
            return []

        mac_info: dict[str, dict[str, str]] = {}
        try:
            hotspot = self.get("show/ip/hotspot")
            raw_hosts = hotspot.get("host", []) if isinstance(hotspot, dict) else []
            for h in raw_hosts:
                if isinstance(h, dict) and h.get("mac"):
                    mac_info[h["mac"].lower()] = {
                        "name": h.get("name") or h.get("hostname") or "",
                        "ip": h.get("ip") or "",
                    }
        except Exception:
            pass

        results: list[dict[str, Any]] = []
        for st in stations:
            if not isinstance(st, dict):
                continue
            mac = st.get("mac", "")
            meta = mac_info.get(mac.lower(), {})
            results.append({
                "mac": mac,
                "name": meta.get("name") or "",
                "ip": meta.get("ip") or "",
                "ap": st.get("ap") or "",
                "rssi": st.get("rssi"),
                "txrate": st.get("txrate"),
                "rxrate": st.get("rxrate"),
                "uptime": st.get("uptime", 0),
            })
        return results

    def diagnose(self) -> dict[str, Any]:
        """Perform comprehensive network and router health inspection."""
        issues: list[dict[str, Any]] = []

        # 1. System info
        sys_info: dict[str, Any] = {}
        ver_info: dict[str, Any] = {}
        try:
            sys_info = self.get("show/system")
        except Exception:
            pass
        try:
            ver_info = self.get("show/version")
        except Exception:
            pass

        raw_up = sys_info.get("uptime", 0)
        try:
            up_int = int(raw_up)
        except (ValueError, TypeError):
            up_int = 0

        system_summary = {
            "model": ver_info.get("model") or "Keenetic",
            "release": ver_info.get("release") or "",
            "device_name": ver_info.get("device") or "",
            "uptime": up_int,
            "cpuload": sys_info.get("cpuload") or 0,
            "memory": sys_info.get("memory") or "",
        }


        # 2. Internet and Gateway
        net_info: dict[str, Any] = {}
        try:
            net_info = self.get("show/internet/status")
        except Exception:
            pass

        internet_ok = net_info.get("internet", False) if isinstance(net_info, dict) else False
        gw_accessible = net_info.get("gateway-accessible", True) if isinstance(net_info, dict) else True
        dns_accessible = net_info.get("dns-accessible", True) if isinstance(net_info, dict) else True

        if not internet_ok:
            gw_iface = net_info.get("gateway", {}).get("interface", "WAN") if isinstance(net_info, dict) else "WAN"
            issues.append({
                "category": "internet",
                "severity": "critical",
                "title": "Internet connectivity is down",
                "description": f"Global internet reachability check failed on gateway interface '{gw_iface}'.",
                "recommendation": "Check WAN link, optical carrier, or ISP authentication.",
                "entities": [gw_iface],
            })
        elif not gw_accessible:
            gw_addr = net_info.get("gateway", {}).get("address", "gateway") if isinstance(net_info, dict) else "gateway"
            issues.append({
                "category": "internet",
                "severity": "critical",
                "title": "Default gateway is unreachable",
                "description": f"Gateway check failed on address '{gw_addr}'.",
                "recommendation": "Verify ISP uplink gateway or modem connection.",
                "entities": [gw_addr],
            })

        if not dns_accessible:
            issues.append({
                "category": "dns",
                "severity": "warning",
                "title": "DNS probe failed on WAN uplink",
                "description": "Router probe failed to resolve internet test domains.",
                "recommendation": "Check upstream DNS servers or DoT/DoH configuration.",
                "entities": [],
            })

        # 3. Dead / Unreplied Conntrack entries
        grouped_unreplied: list[dict[str, Any]] = []
        try:
            unreplied = self.get_conntrack(unreplied_only=True)
            grouped_unreplied = group_unreplied_conntrack(unreplied)
            for g in grouped_unreplied:
                pkts = g.get("packets", 0)
                conns = g.get("conns_count", 0)
                proto = g.get("protocol", "")
                if pkts >= 10 or (conns >= 2 and proto == "TCP") or (pkts >= 5 and proto == "TCP"):
                    sev = "critical" if pkts >= 1000 else "warning"
                    svc = f" ({g['service']})" if g.get("service") else ""
                    sources_str = ", ".join(g["sources"][:5])
                    desc = f"{conns} dead connection(s) ({pkts} unreplied packets) to {g['dst']}:{g.get('dport')}{svc} from {sources_str}"
                    rec = "Check destination reachability or firewall/routing policy."
                    if any("[" in s for s in g.get("sources", [])):
                        rec = "Device is routed via a custom policy (e.g. VPN). Verify if target port is blocked by the tunnel, or assign device to Main policy."
                    issues.append({
                        "category": "conntrack",
                        "severity": sev,
                        "title": f"Unreplied traffic to {g['dst']}:{g.get('dport')}{svc}",
                        "description": desc,
                        "recommendation": rec,
                        "entities": [g["dst"], *[s.split()[0] for s in g["sources"]]],
                    })
        except Exception:
            pass

        # 4. Client stability & Flapping heuristics from recent logs
        recent_logs: list[dict[str, Any]] = []
        try:
            recent_logs = self.get_log(lines=150)
        except Exception:
            pass

        mac_events: dict[str, int] = {}
        for log_entry in recent_logs:
            msg = log_entry.get("message", "")
            if "deauthenticated by STA" in msg:
                for part in msg.split():
                    if "STA(" in part:
                        mac = part.replace("STA(", "").replace(")", "").strip(":").lower()
                        mac_events[mac] = mac_events.get(mac, 0) + 1
            elif "DHCPRELEASE" in msg or "DHCPDISCOVER" in msg:
                for part in msg.split():
                    if part.count(":") == 5:
                        mac = part.strip(".,;:\"'()").lower()
                        mac_events[mac] = mac_events.get(mac, 0) + 1

        all_hosts = self.get_hosts()
        hosts_map = {h["mac"].lower(): h for h in all_hosts if h.get("mac")}

        for mac, cnt in mac_events.items():
            if cnt >= 3:
                h_info = hosts_map.get(mac, {})
                name = h_info.get("name") or "Unknown"
                ip = h_info.get("ip") or mac
                issues.append({
                    "category": "clients",
                    "severity": "warning",
                    "title": f"Client flapping detected: {name} ({mac})",
                    "description": f"Host {ip} ({name}) recorded {cnt} deauth/DHCP reconnect events in recent logs.",
                    "recommendation": "Device may be rebooting due to cloud disconnects, power issues, or unstable Wi-Fi signal.",
                    "entities": [mac, ip],
                })

        # 5. Wi-Fi signal issues
        try:
            stations = self.get_wifi_associations()
            for st in stations:
                rssi = st.get("rssi")
                if rssi is not None and rssi < -82:
                    issues.append({
                        "category": "clients",
                        "severity": "info",
                        "title": f"Weak Wi-Fi signal: {st.get('name') or st.get('mac')} ({rssi} dBm)",
                        "description": f"Station {st.get('ip') or st.get('mac')} has low signal ({rssi} dBm) on {st.get('ap')}.",
                        "recommendation": "Move client closer to router or add an extender.",
                        "entities": [st.get("mac", "")],
                    })
        except Exception:
            pass

        # 6. System Log Errors
        err_entries = [
            e for e in recent_logs
            if any(x in (e.get("level") or "").lower() for x in ("err", "crit", "alert", "emerg"))
        ]
        if err_entries:
            services = sorted({e.get("ident", "unknown") for e in err_entries})
            issues.append({
                "category": "log",
                "severity": "warning",
                "title": f"{len(err_entries)} system error(s) logged in recent events",
                "description": f"Services reporting errors: {', '.join(services)}. Latest: {err_entries[-1].get('message', '')}",
                "recommendation": "Inspect system log via 'keen log -l error' for troubleshooting.",
                "entities": services,
            })

        # 7. Management and network service security checks
        service_list: list[dict[str, Any]] = []
        try:
            service_list = self.get_services(all_services=True)
            for svc in service_list:
                if not svc.get("enabled"):
                    continue
                sname = svc.get("name")
                sec = svc.get("security_level", "")
                ports = svc.get("ports", [])
                port_str = ", ".join(str(p) for p in ports) if ports else "default"

                # Check 1: Unencrypted Telnet
                if sname == "telnet":
                    if "public" in sec:
                        issues.append({
                            "category": "services",
                            "severity": "critical",
                            "title": "Unencrypted Telnet daemon exposed to WAN",
                            "description": "Telnet service is accessible from the public internet without encryption. Passwords and commands are sent in plaintext.",
                            "recommendation": "Disable public Telnet access ('no ip telnet public' or 'no service telnet'). Use SSH instead.",
                            "entities": ["telnet", f"port {port_str}"],
                        })
                    else:
                        issues.append({
                            "category": "services",
                            "severity": "info",
                            "title": "Unencrypted Telnet daemon is active",
                            "description": "Telnet service is active on local network (port 23). Traffic and authentication are unencrypted.",
                            "recommendation": "Use SSH for secure administration and consider disabling Telnet ('no service telnet').",
                            "entities": ["telnet", f"port {port_str}"],
                        })

                # Check 2: SSH exposed to WAN
                elif sname == "ssh" and "public" in sec:
                    issues.append({
                        "category": "services",
                        "severity": "warning",
                        "title": "SSH management daemon exposed to public WAN",
                        "description": "SSH daemon is accessible from the public internet, potentially exposed to brute-force attempts.",
                        "recommendation": "Ensure strong credentials, verify lockout policy ('ip ssh lockout-policy'), or restrict SSH to LAN/VPN ('no ip ssh public').",
                        "entities": ["ssh", f"port {port_str}"],
                    })

                # Check 3: Web UI without SSL exposed to public WAN
                elif sname == "http" and sec == "public":
                    issues.append({
                        "category": "services",
                        "severity": "critical",
                        "title": "Web UI / RCI exposed to WAN without SSL encryption",
                        "description": "Router web management interface is exposed to the internet over unencrypted HTTP.",
                        "recommendation": "Enable SSL and force HTTPS redirect ('ip http ssl enable' and 'ip http ssl redirect').",
                        "entities": ["http", f"port {port_str}"],
                    })
        except Exception:
            pass

        # Determine status
        if any(i["severity"] == "critical" for i in issues):
            overall_status = "critical"
        elif any(i["severity"] == "warning" for i in issues):
            overall_status = "warning"
        else:
            overall_status = "ok"

        checks = {
            "internet": {
                "status": "ok" if internet_ok else "fail",
                "gateway": net_info.get("gateway", {}).get("address") if isinstance(net_info, dict) else None,
                "interface": net_info.get("gateway", {}).get("interface") if isinstance(net_info, dict) else None,
            },
            "dns": {
                "status": "ok" if dns_accessible else "warn",
            },
            "conntrack": {
                "status": "warn" if any(i["category"] == "conntrack" for i in issues) else "ok",
                "unreplied_groups": len(grouped_unreplied),
            },
            "clients": {
                "status": "warn" if any(i["category"] == "clients" for i in issues) else "ok",
                "active_hosts": len([h for h in all_hosts if h.get("active")]),
            },
            "system_log": {
                "status": "warn" if err_entries else "ok",
                "recent_errors": len(err_entries),
            },
            "services": {
                "status": (
                    "fail"
                    if any(i.get("category") == "services" and i.get("severity") == "critical" for i in issues)
                    else "warn"
                    if any(i.get("category") == "services" and i.get("severity") == "warning" for i in issues)
                    else "ok"
                ),
                "active_mgmt": len([
                    s for s in service_list
                    if s.get("enabled") and s.get("category") in ("management", "vpn")
                ]),
            },
        }

        return {
            "status": overall_status,
            "system": system_summary,
            "checks": checks,
            "issues": issues,
        }


    def get_log(
        self,
        lines: int = 50,
        level: str | None = None,
        service: str | None = None,
        grep: str | None = None,
    ) -> list[dict[str, Any]]:
        """Query and filter system event log entries from the router buffer."""
        raw_res = self.cmd("show log")
        entries_data: Any = []
        if isinstance(raw_res, dict):
            if "log" in raw_res:
                inner = raw_res["log"]
                entries_data = list(inner.values()) if isinstance(inner, dict) else inner
            else:
                entries_data = list(raw_res.values())
        elif isinstance(raw_res, list):
            entries_data = raw_res

        parsed_entries: list[dict[str, Any]] = []
        for item in entries_data:
            if not isinstance(item, dict):
                continue

            entry_id = item.get("id")
            try:
                entry_id_int = int(entry_id) if entry_id is not None else 0
            except (ValueError, TypeError):
                entry_id_int = 0

            timestamp = str(item.get("timestamp", ""))
            ident = str(item.get("ident", ""))

            lvl = item.get("level")
            label = item.get("label", "")
            msg_raw = item.get("message")
            if isinstance(msg_raw, dict):
                lvl = lvl or str(msg_raw.get("level", "Info"))
                label = label or str(msg_raw.get("label", ""))
                text = str(msg_raw.get("message", ""))
            elif isinstance(msg_raw, str):
                lvl = lvl or "Info"
                text = msg_raw
            else:
                lvl = lvl or "Info"
                text = str(msg_raw) if msg_raw is not None else ""


            parsed_entries.append({
                "id": entry_id_int,
                "timestamp": timestamp,
                "ident": ident,
                "level": lvl,
                "label": label or (lvl[0].upper() if lvl else "I"),
                "message": text.strip(),
            })

        parsed_entries.sort(key=lambda x: x["id"])

        level_weights = {
            "debug": 10,
            "info": 20,
            "notice": 30,
            "warning": 40,
            "warn": 40,
            "error": 50,
            "err": 50,
            "critical": 60,
            "crit": 60,
            "alert": 70,
            "emergency": 80,
        }

        filtered = parsed_entries
        if level:
            lvl_clean = level.strip().lower()
            if lvl_clean in level_weights:
                threshold = level_weights[lvl_clean]
                filtered = [
                    e for e in filtered
                    if level_weights.get(e["level"].lower(), 20) >= threshold
                ]
            else:
                filtered = [
                    e for e in filtered
                    if lvl_clean in e["level"].lower()
                ]

        if service:
            svc_clean = service.strip().lower()
            filtered = [
                e for e in filtered
                if svc_clean in e["ident"].lower()
            ]

        if grep:
            grp_clean = grep.strip().lower()
            filtered = [
                e for e in filtered
                if grp_clean in e["message"].lower() or grp_clean in e["ident"].lower()
            ]

        if lines > 0:
            filtered = filtered[-lines:]

        return filtered

    def get_conntrack(
        self,
        unreplied_only: bool = False,
        proto: str | None = None,
        include_broadcast: bool = False,
        resolve_names: bool = True,
        src: str | None = None,
        dst: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Query and format connection tracking / NAT entries."""
        raw = self.get("show/ip/nat")
        entries = raw if isinstance(raw, list) else raw.get("nat", []) if isinstance(raw, dict) else []

        host_names: dict[str, str] = {}
        host_meta: dict[str, dict[str, Any]] = {}
        if resolve_names:
            try:
                hotspot = self.get("show/ip/hotspot")
                raw_hosts = hotspot.get("host", []) if isinstance(hotspot, dict) else []
                for h in raw_hosts:
                    if isinstance(h, dict) and h.get("ip"):
                        name = h.get("name") or h.get("hostname")
                        iface_val = h.get("interface")
                        iface_name = (
                            iface_val.get("name") or iface_val.get("id")
                            if isinstance(iface_val, dict)
                            else str(iface_val) if iface_val else None
                        )
                        if name:
                            host_names[h["ip"]] = name
                        host_meta[h["ip"]] = {
                            "name": name,
                            "policy": h.get("policy"),
                            "interface": iface_name,
                        }
            except Exception:
                pass

        proto_filter = proto.upper() if proto and proto.lower() != "all" else None

        results: list[dict[str, Any]] = []
        for item in entries:
            if not isinstance(item, dict):
                continue

            entry_proto = (item.get("protocol") or "").upper()
            if proto_filter and entry_proto != proto_filter:
                continue

            src_ip = str(item.get("src", ""))
            dst_ip = str(item.get("dst", ""))
            sport = item.get("sport")
            dport = item.get("dport")

            if src and src_ip != src:
                continue
            if dst and dst_ip != dst:
                continue

            pkts_sent = item.get("packets", 0)
            bytes_sent = item.get("bytes", 0)
            pkts_recv = item.get("packets-out", 0)
            bytes_recv = item.get("bytes-out", 0)

            if unreplied_only:
                if pkts_recv > 0:
                    continue
                if not include_broadcast and is_broadcast_or_multicast(dst_ip):
                    continue

            service = get_service_name(dport, entry_proto) if dport else ""
            src_m = host_meta.get(src_ip, {})
            dst_m = host_meta.get(dst_ip, {})

            results.append({
                "protocol": entry_proto,
                "src": src_ip,
                "sport": sport,
                "src_name": host_names.get(src_ip),
                "src_policy": src_m.get("policy"),
                "src_interface": src_m.get("interface"),
                "dst": dst_ip,
                "dport": dport,
                "dst_name": host_names.get(dst_ip),
                "service": service,
                "packets": pkts_sent,
                "bytes": bytes_sent,
                "packets_recv": pkts_recv,
                "bytes_recv": bytes_recv,
            })

        if limit > 0:
            results = results[:limit]

        return results

    def get_capabilities(self) -> dict[str, Any]:
        """Inspect and report router capabilities (AmneziaWG support, WireGuard, routing, OPKG)."""
        ver_info = self.get("show/version")
        if not isinstance(ver_info, dict):
            ver_info = {}

        components_str = ver_info.get("ndw", {}).get("components", "")
        installed_components = [c.strip() for c in components_str.split(",") if c.strip()]

        ver_title = ver_info.get("title") or ver_info.get("release", "")
        major, minor = parse_keenetic_version(ver_title or ver_info.get("release", ""))

        has_wg = "wireguard" in installed_components
        has_wg_server = "wireguard-server" in installed_components

        # AmneziaWG evaluation:
        # KeeneticOS < 4.2: not supported natively
        # 4.2 <= KeeneticOS < 5.2: AWG 2.0 (via wireguard asc 9 obfuscation parameters)
        # KeeneticOS >= 5.2: AWG 3.1+ (native AmneziaWG 3.x)
        if (major, minor) >= (5, 2):
            awg_supported = True
            awg_protocol = "AWG 3.1+"
            awg_details = "Native support for AmneziaWG 3.0/3.1+ protocols."
        elif (major, minor) >= (4, 2):
            awg_supported = True
            awg_protocol = "AWG 2.0"
            awg_details = "Supported via 'wireguard asc' (9 obfuscation parameters: Jc, Jmin, Jmax, S1, S2, H1-H4). Note: AWG 3.1+ requires KeeneticOS 5.2+."
        else:
            awg_supported = False
            awg_protocol = None
            awg_details = f"AmneziaWG requires KeeneticOS 4.2+ (current version: {ver_title or 'unknown'})."

        if not awg_supported:
            awg_status = "not_supported"
        elif has_wg:
            awg_status = "ready"
        else:
            awg_status = "available_with_component"

        fqdn_supported = (major, minor) >= (5, 0)
        has_opkg = "opkg" in installed_components

        return {
            "device": {
                "model": ver_info.get("model"),
                "device_name": ver_info.get("device"),
                "release": ver_info.get("release"),
                "title": ver_info.get("title"),
                "arch": ver_info.get("arch"),
            },
            "vpn": {
                "wireguard": {
                    "installed": has_wg,
                    "server_installed": has_wg_server,
                },
                "amnezia": {
                    "supported": awg_supported,
                    "protocol": awg_protocol,
                    "status": awg_status,
                    "details": awg_details,
                },
                "openvpn": {
                    "installed": "openvpn" in installed_components,
                },
                "zerotier": {
                    "installed": "zerotier" in installed_components,
                },
                "sstp": {
                    "installed": "sstp" in installed_components or "sstp-server" in installed_components,
                    "server_installed": "sstp-server" in installed_components,
                },
            },
            "routing": {
                "fqdn_domain_routing": {
                    "supported": fqdn_supported,
                    "method": "dns-proxy route + object-group fqdn" if fqdn_supported else "opkg / ipset",
                },
            },
            "extensions": {
                "opkg": has_opkg,
            },
            "installed_components_count": len(installed_components),
        }

    def get_components(
        self,
        channel: str = "",
        installed_only: bool = False,
        available_only: bool = False,
        group: str | None = None,
        search_query: str | None = None,
    ) -> list[dict[str, Any]]:
        """List router components, enriched with AmneziaWG compatibility for wireguard."""
        caps = self.get_capabilities()
        awg_info = caps["vpn"]["amnezia"]

        cmd_str = f"components list {channel}".strip() if channel else "components list"
        res = self.cmd(cmd_str)
        if isinstance(res, list) and len(res) > 0 and isinstance(res[0], dict):
            res = res[0].get("parse", res[0])
        if isinstance(res, dict) and res.get("continued") and "component" not in res:
            for _ in range(5):
                time.sleep(0.5)
                res = self.cmd(cmd_str)
                if isinstance(res, dict) and "component" in res:
                    break

        raw_components: dict[str, Any] = {}
        if isinstance(res, dict) and "component" in res and isinstance(res["component"], dict):
            raw_components = res["component"]
        else:
            ver_info = self.get("show/version")
            components_str = ver_info.get("ndw", {}).get("components", "") if isinstance(ver_info, dict) else ""
            installed_list = [c.strip() for c in components_str.split(",") if c.strip()]
            for name in installed_list:
                raw_components[name] = {
                    "installed": "installed",
                    "version": "",
                    "size": 0,
                    "group": "Base system",
                    "description": {"RU": name, "EN": name},
                    "queued": True,
                }

        results: list[dict[str, Any]] = []
        for name, data in raw_components.items():
            if not isinstance(data, dict):
                continue

            installed_ver = data.get("installed")
            is_installed = bool(installed_ver)

            if installed_only and not is_installed:
                continue
            if available_only and is_installed:
                continue

            grp = data.get("group") or "Other"
            if group and group.lower() not in grp.lower():
                continue

            desc_dict = data.get("description")
            if isinstance(desc_dict, dict):
                desc = desc_dict.get("RU") or desc_dict.get("EN") or ""
            else:
                desc = str(desc_dict) if desc_dict else ""

            if search_query:
                q = search_query.lower()
                if q not in name.lower() and q not in desc.lower() and q not in grp.lower():
                    continue

            size_val = data.get("size")
            try:
                size_int = int(size_val) if size_val else 0
            except (ValueError, TypeError):
                size_int = 0

            entry: dict[str, Any] = {
                "name": name,
                "installed": is_installed,
                "version": installed_ver or data.get("version") or "",
                "size": size_int,
                "group": grp,
                "description": desc,
                "queued": bool(data.get("queued", False)),
            }

            if name == "wireguard":
                entry["amnezia"] = {
                    "supported": awg_info["supported"],
                    "protocol": awg_info["protocol"],
                    "status": awg_info["status"],
                    "details": awg_info["details"],
                    "badge": (
                        f"AmneziaWG: {awg_info['protocol']} [{awg_info['status']}]"
                        if awg_info["supported"]
                        else "AmneziaWG: not supported"
                    ),
                }

            results.append(entry)

        results.sort(key=lambda x: (not x["installed"], x["name"]))
        return results

    def install_component(self, name: str) -> dict[str, Any]:
        """Queue a component for installation."""
        clean_name = name.strip()
        return self.cmd(f"components install {clean_name}")

    def remove_component(self, name: str) -> dict[str, Any]:
        """Queue a component for removal."""
        clean_name = name.strip()
        return self.cmd(f"components remove {clean_name}")

    def commit_components(self) -> dict[str, Any]:
        """Commit queued component changes, triggering cloud firmware build and reboot."""
        return self.cmd("components commit")

    def get_services(
        self,
        management_only: bool = False,
        all_services: bool = False,
    ) -> list[dict[str, Any]]:
        """Inspect status, ports, and security levels of router management and network services."""
        service_flags: dict[str, Any] = {}
        try:
            raw_flags = self.get("service")
            if isinstance(raw_flags, dict):
                service_flags = raw_flags
        except Exception:
            pass

        services: list[dict[str, Any]] = []

        # 1. HTTP / Web UI / RCI
        http_info: dict[str, Any] = {}
        try:
            raw_http = self.get("ip/http")
            if isinstance(raw_http, dict):
                http_info = raw_http
        except Exception:
            pass

        http_enabled = bool(service_flags.get("http", bool(http_info)))
        http_sec_raw = http_info.get("security-level", {}) if isinstance(http_info, dict) else {}
        if isinstance(http_sec_raw, dict):
            if http_sec_raw.get("public") and http_sec_raw.get("ssl"):
                http_sec = "public (ssl)"
            elif http_sec_raw.get("public"):
                http_sec = "public"
            elif http_sec_raw.get("private"):
                http_sec = "private"
            else:
                http_sec = "private"
        else:
            http_sec = "private"

        ssl_info = http_info.get("ssl", {}) if isinstance(http_info, dict) else {}
        ssl_enabled = bool(ssl_info.get("enable", False)) if isinstance(ssl_info, dict) else False
        ssl_redirect = bool(ssl_info.get("redirect", False)) if isinstance(ssl_info, dict) else False

        http_ports: list[int] = []
        raw_port = http_info.get("port", 80) if isinstance(http_info, dict) else 80
        try:
            http_ports.append(int(raw_port))
        except (ValueError, TypeError):
            http_ports.append(80)

        if ssl_enabled:
            raw_ssl_port = ssl_info.get("port", 443) if isinstance(ssl_info, dict) else 443
            try:
                http_ports.append(int(raw_ssl_port))
            except (ValueError, TypeError):
                http_ports.append(443)

        http_details_parts: list[str] = []
        if ssl_enabled:
            http_details_parts.append("HTTPS/SSL enabled" + (" (redirect active)" if ssl_redirect else ""))
        if http_info.get("webdav"):
            http_details_parts.append("WebDAV active")

        services.append({
            "name": "http",
            "title": "Web UI / RCI",
            "category": "management",
            "enabled": http_enabled,
            "ports": http_ports,
            "security_level": http_sec,
            "details": ", ".join(http_details_parts) if http_details_parts else "Standard HTTP",
        })

        # 2. SSH Server
        ssh_info: dict[str, Any] = {}
        try:
            raw_ssh = self.get("ip/ssh")
            if isinstance(raw_ssh, dict):
                ssh_info = raw_ssh
        except Exception:
            pass

        ssh_enabled = bool(service_flags.get("ssh", bool(ssh_info)))
        ssh_sec_raw = ssh_info.get("security-level", {}) if isinstance(ssh_info, dict) else {}
        ssh_sec = "public" if isinstance(ssh_sec_raw, dict) and ssh_sec_raw.get("public") else "private"
        ssh_port_raw = ssh_info.get("port", 22) if isinstance(ssh_info, dict) else 22
        try:
            ssh_port = int(ssh_port_raw)
        except (ValueError, TypeError):
            ssh_port = 22

        ssh_lockout = ssh_info.get("lockout-policy") if isinstance(ssh_info, dict) else None
        lockout_desc = ""
        if isinstance(ssh_lockout, dict):
            lockout_desc = f"Lockout active ({ssh_lockout.get('threshold', 5)} att/{ssh_lockout.get('duration', 15)}m)"
        elif ssh_lockout:
            lockout_desc = "Lockout active"

        services.append({
            "name": "ssh",
            "title": "SSH Server",
            "category": "management",
            "enabled": ssh_enabled,
            "ports": [ssh_port],
            "security_level": ssh_sec,
            "details": lockout_desc or "Secure remote CLI shell",
        })

        # 3. Telnet Server
        telnet_info: dict[str, Any] = {}
        try:
            raw_telnet = self.get("ip/telnet")
            if isinstance(raw_telnet, dict):
                telnet_info = raw_telnet
        except Exception:
            pass

        telnet_enabled = bool(service_flags.get("telnet", bool(telnet_info)))
        telnet_sec_raw = telnet_info.get("security-level", {}) if isinstance(telnet_info, dict) else {}
        telnet_sec = "public" if isinstance(telnet_sec_raw, dict) and telnet_sec_raw.get("public") else "private"
        telnet_port_raw = telnet_info.get("port", 23) if isinstance(telnet_info, dict) else 23
        try:
            telnet_port = int(telnet_port_raw)
        except (ValueError, TypeError):
            telnet_port = 23

        services.append({
            "name": "telnet",
            "title": "Telnet Server",
            "category": "management",
            "enabled": telnet_enabled,
            "ports": [telnet_port],
            "security_level": telnet_sec,
            "details": "Unencrypted plaintext CLI",
        })

        # 4. SSTP VPN Server
        sstp_show: dict[str, Any] = {}
        sstp_cfg: dict[str, Any] = {}
        try:
            raw_sstp_show = self.get("show/sstp-server")
            if isinstance(raw_sstp_show, dict):
                sstp_show = raw_sstp_show
        except Exception:
            pass
        try:
            raw_sstp_cfg = self.get("sstp-server")
            if isinstance(raw_sstp_cfg, dict):
                sstp_cfg = raw_sstp_cfg
        except Exception:
            pass

        sstp_enabled = bool(
            sstp_show.get("enabled", False)
            or service_flags.get("sstp-server", False)
            or (isinstance(sstp_cfg.get("config"), dict) and sstp_cfg["config"].get("enable", False))
        )
        sstp_ndns = sstp_show.get("ndns-name") if isinstance(sstp_show, dict) else None
        sstp_cert = sstp_show.get("has-ndns-certificate", False) if isinstance(sstp_show, dict) else False

        sstp_details: list[str] = []
        if sstp_ndns:
            sstp_details.append(f"KeenDNS: {sstp_ndns}")
        if sstp_cert:
            sstp_details.append("SSL cert active")
        pool = sstp_cfg.get("pool-range", {}) if isinstance(sstp_cfg, dict) else {}
        if isinstance(pool, dict) and pool.get("begin"):
            sstp_details.append(f"pool {pool.get('begin')}/{pool.get('size', 10)}")

        services.append({
            "name": "sstp-server",
            "title": "SSTP VPN Server",
            "category": "vpn",
            "enabled": sstp_enabled,
            "ports": [443],
            "security_level": "public (vpn)",
            "details": ", ".join(sstp_details) if sstp_details else "SSTP remote access",
        })

        # 5. FTP Server (if present)
        ftp_info: dict[str, Any] = {}
        try:
            raw_ftp = self.get("ip/ftp")
            if isinstance(raw_ftp, dict):
                ftp_info = raw_ftp
        except Exception:
            pass

        if ftp_info or "ftp" in service_flags:
            ftp_enabled = bool(service_flags.get("ftp", False))
            ftp_sec_raw = ftp_info.get("security-level", {}) if isinstance(ftp_info, dict) else {}
            ftp_sec = "public" if isinstance(ftp_sec_raw, dict) and ftp_sec_raw.get("public") else "private"
            ftp_port_raw = ftp_info.get("port", 21) if isinstance(ftp_info, dict) else 21
            try:
                ftp_port = int(ftp_port_raw)
            except (ValueError, TypeError):
                ftp_port = 21

            services.append({
                "name": "ftp",
                "title": "FTP Server",
                "category": "filesharing",
                "enabled": ftp_enabled,
                "ports": [ftp_port],
                "security_level": ftp_sec,
                "details": "File transfer protocol",
            })

        # 6. Torrent (Transmission)
        torrent_info: dict[str, Any] = {}
        try:
            raw_torrent = self.get("torrent")
            if isinstance(raw_torrent, dict):
                torrent_info = raw_torrent
        except Exception:
            pass

        if torrent_info and isinstance(torrent_info, dict):
            rpc_cfg = torrent_info.get("rpc-port", {})
            rpc_port = rpc_cfg.get("port", 8090) if isinstance(rpc_cfg, dict) else (rpc_cfg or 8090)
            try:
                rpc_port_int = int(rpc_port)
            except (ValueError, TypeError):
                rpc_port_int = 8090
            peer_port = torrent_info.get("peer-port", 51413)
            try:
                peer_port_int = int(peer_port)
            except (ValueError, TypeError):
                peer_port_int = 51413
            torrent_sec = "public" if (isinstance(rpc_cfg, dict) and rpc_cfg.get("public")) else "private"
            services.append({
                "name": "transmission",
                "title": "Transmission BitTorrent",
                "category": "applications",
                "enabled": True,
                "ports": [rpc_port_int, peer_port_int],
                "security_level": torrent_sec,
                "details": f"RPC port {rpc_port_int}, peer port {peer_port_int}",
            })

        # 7. CIFS (SMB)
        cifs_info: dict[str, Any] = {}
        try:
            raw_cifs = self.get("cifs")
            if isinstance(raw_cifs, dict):
                cifs_info = raw_cifs
        except Exception:
            pass

        if cifs_info and isinstance(cifs_info, dict):
            services.append({
                "name": "cifs",
                "title": "SMB / Windows Sharing",
                "category": "filesharing",
                "enabled": True,
                "ports": [445],
                "security_level": "private",
                "details": "Windows network file and printer sharing",
            })

        # 8. Core network daemons
        core_daemons = [
            ("dns-proxy", "DNS Proxy / Resolver", "network", [53], "private", "DoH/DoT upstream resolver"),
            ("dhcp", "DHCP Server", "network", [67], "private", "LAN IP address assignment"),
            ("upnp", "UPnP IGD Server", "network", [1900, 2869], "private", "Automatic port forwarding"),
            ("mdns", "mDNS Responder", "network", [5353], "private", "Multicast DNS discovery"),
            ("ntp", "NTP Time Service", "network", [123], "private", "Network Time Protocol"),
        ]
        for sname, title, cat, ports, sec, det in core_daemons:
            if sname in service_flags:
                services.append({
                    "name": sname,
                    "title": title,
                    "category": cat,
                    "enabled": bool(service_flags[sname]),
                    "ports": ports,
                    "security_level": sec,
                    "details": det,
                })

        if management_only:
            return [s for s in services if s.get("category") in ("management", "vpn")]
        if not all_services:
            return [s for s in services if s.get("category") != "network"]
        return services

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> KeeneticClient:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


def parse_keenetic_version(ver_str: str) -> tuple[int, int]:
    """Parse major and minor version numbers from KeeneticOS release/title string."""
    if not ver_str:
        return 0, 0
    m = re.match(r"^(\d+)\.(\d+)", str(ver_str).strip())
    if m:
        return int(m.group(1)), int(m.group(2))
    return 0, 0


def is_broadcast_or_multicast(ip_str: str) -> bool:
    """Check if an IPv4 address is multicast, 255.255.255.255 or subnet broadcast."""
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_multicast:
            return True
        if ip_str == "255.255.255.255" or ip_str.endswith(".255"):
            return True
        return False
    except ValueError:
        return False


def is_ip_in_subnet(ip_str: str, subnet_str: str) -> bool:
    """Check if an IPv4 address belongs to a subnet (CIDR or prefix string)."""
    if not ip_str or not subnet_str:
        return False
    sub = subnet_str.strip()
    try:
        net = ipaddress.ip_network(sub, strict=False)
        ip = ipaddress.ip_address(ip_str)
        return ip in net
    except ValueError:
        return ip_str.startswith(sub)



def get_service_name(port: int | None, proto: str) -> str:
    """Resolve known network port numbers to friendly service names."""
    if not port:
        return ""
    known = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        143: "IMAP",
        443: "HTTPS",
        500: "IKE",
        1194: "OpenVPN",
        1883: "MQTT",
        1900: "SSDP",
        3518: "Keenetic-Sync",
        3702: "WS-Discovery",
        4500: "IPsec-NAT-T",
        51820: "WireGuard",
        5683: "CoAP",
        5685: "CoAP-Secure",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        8820: "Hikvision-Media",
        8883: "MQTTS",
    }
    if port in known:
        return known[port]
    try:
        return socket.getservbyport(port, proto.lower()).upper()
    except (OSError, ValueError):
        return ""


def group_unreplied_conntrack(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group unreplied connections by destination target (dst, dport, proto)."""
    groups: dict[tuple[str, int | None, str], dict[str, Any]] = {}
    for e in entries:
        key = (e["dst"], e.get("dport"), e["protocol"])
        if key not in groups:
            groups[key] = {
                "dst": e["dst"],
                "dport": e.get("dport"),
                "protocol": e["protocol"],
                "service": e.get("service", ""),
                "dst_name": e.get("dst_name"),
                "sources": [],
                "conns_count": 0,
                "packets": 0,
                "bytes": 0,
            }
        g = groups[key]
        g["conns_count"] += 1
        g["packets"] += e.get("packets", 0)
        g["bytes"] += e.get("bytes", 0)

        src_ip = e.get("src", "")
        src_name = e.get("src_name")
        src_policy = e.get("src_policy")
        policy_tag = f" [{src_policy}]" if src_policy and src_policy != "Main" else ""
        src_label = f"{src_ip} ({src_name}{policy_tag})" if src_name else f"{src_ip}{policy_tag}"
        if src_label not in g["sources"]:
            g["sources"].append(src_label)


    res = list(groups.values())
    res.sort(key=lambda x: (x["packets"], x["conns_count"]), reverse=True)
    return res
