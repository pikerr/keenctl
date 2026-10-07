import pytest
import httpx
from pathlib import Path
from keenctl.client import KeeneticClient, KeeneticAuthError

def test_client_init(tmp_path):
    client = KeeneticClient(
        host="http://192.168.1.1",
        user="testuser",
        password="testpass",
        cache_dir=tmp_path,
    )
    assert client.host == "http://192.168.1.1"
    assert client.user == "testuser"
    assert client.password == "testpass"
    assert client.cache_file.parent == tmp_path
    client.close()

def test_cache_save_and_load(tmp_path):
    client1 = KeeneticClient(
        host="http://192.168.1.1",
        user="testuser",
        password="testpass",
        cache_dir=tmp_path,
    )
    client1._client.cookies.set("dummy_session", "abc123xyz")
    client1._save_cached_session()
    client1.close()

    assert client1.cache_file.exists()

    # Client 2 should load the cookie automatically
    client2 = KeeneticClient(
        host="http://192.168.1.1",
        user="testuser",
        password="testpass",
        cache_dir=tmp_path,
    )
    assert client2._client.cookies.get("dummy_session") == "abc123xyz"
    client2.close()

def test_empty_password_non_interactive_raises(tmp_path, monkeypatch):
    import sys
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    client = KeeneticClient(
        host="http://router.local",
        user="admin",
        password="",
        cache_dir=tmp_path,
    )
    with pytest.raises(KeeneticAuthError, match="Password is required"):
        client.authenticate()
    client.close()

def test_getpass_prompt_interactive(tmp_path, monkeypatch):
    import sys
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    import getpass
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "injected_secret")

    client = KeeneticClient(
        host="http://router.local",
        user="admin",
        password="",
        cache_dir=tmp_path,
    )
    # Mock network call to succeed after password check
    client._client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200)))
    client.authenticate()
    assert client.password == "injected_secret"
    client.close()

def test_get_interfaces_and_routes_mock(tmp_path):
    client = KeeneticClient(
        host="http://router.local",
        user="admin",
        password="secret",
        cache_dir=tmp_path,
    )
    # Mock transport
    def handler(request):
        if "show/interface" in str(request.url):
            return httpx.Response(200, json={
                "Bridge0": {"state": "up", "link": "up", "address": "192.168.1.1", "mask": "255.255.255.0", "type": "Bridge"},
                "GigabitEthernet0": {"state": "down", "link": "down"},
            })
        elif "show/ip/route" in str(request.url):
            return httpx.Response(200, json=[
                {"destination": "0.0.0.0", "mask": "0.0.0.0", "gateway": "10.0.0.1", "interface": "GigabitEthernet1"}
            ])
        elif "parse" in request.read().decode():
            return httpx.Response(200, json=[{"parse": "rebooting", "status": [{"status": "ok"}]}])
        return httpx.Response(200, json={})

    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    
    # Test all interfaces
    all_ifaces = client.get_interfaces(active_only=False)
    assert len(all_ifaces) == 2
    
    # Test active only
    active_ifaces = client.get_interfaces(active_only=True)
    assert len(active_ifaces) == 1
    assert active_ifaces[0]["name"] == "Bridge0"
    assert active_ifaces[0]["ip"] == "192.168.1.1"

    # Test routes
    routes = client.get_routes()
    assert len(routes) == 1
    assert routes[0]["destination"] == "0.0.0.0/0.0.0.0"
    assert routes[0]["gateway"] == "10.0.0.1"

    # Test reboot
    reboot_res = client.reboot()
    assert reboot_res == "rebooting"

    client.close()


def test_transport_error_parsing_with_hints(tmp_path):
    from keenctl.client import KeeneticConnectionError

    client = KeeneticClient(host="http://10.122.1.1", user="admin", password="p", cache_dir=tmp_path)

    # Simulate "No route to host"
    def no_route_handler(req):
        raise httpx.ConnectError("[Errno 113] No route to host")

    client._client = httpx.Client(transport=httpx.MockTransport(no_route_handler))

    with pytest.raises(KeeneticConnectionError) as exc_info:
        client.get("show/system")

    err = exc_info.value
    assert "No route to host" in err.message
    assert "VPN" in err.hint or "tunnel" in err.hint
    assert err.error_type == "connection_error"
    assert err.host == "http://10.122.1.1"
    client.close()


def test_http_404_html_parsing_with_hints(tmp_path):
    from keenctl.client import KeeneticHttpError

    client = KeeneticClient(host="http://192.168.1.1", user="admin", password="p", cache_dir=tmp_path)

    # Simulate 404 with HTML body (e.g. ZTE router)
    def html_404_handler(req):
        return httpx.Response(404, text="<html><body>404 Not Found ZTE</body></html>")

    client._client = httpx.Client(transport=httpx.MockTransport(html_404_handler))

    with pytest.raises(KeeneticHttpError) as exc_info:
        client.get("show/system")

    err = exc_info.value
    assert "HTTP 404 Not Found" in err.message
    assert "does not appear to be a Keenetic" in err.hint
    assert err.status_code == 404
    client.close()


def test_resolve_host_explicit_schemes(tmp_path):
    c1 = KeeneticClient(host="https://router.local", user="a", password="b", cache_dir=tmp_path)
    assert c1.host == "https://router.local"
    c1.close()

    c2 = KeeneticClient(host="http://router.local", user="a", password="b", cache_dir=tmp_path)
    assert c2.host == "http://router.local"
    c2.close()

    # Forced ssl upgrades explicit http
    c3 = KeeneticClient(host="http://router.local", user="a", password="b", ssl=True, cache_dir=tmp_path)
    assert c3.host == "https://router.local"
    c3.close()


def test_resolve_host_bare_forced_ssl(tmp_path):
    c = KeeneticClient(host="myrouter.net", user="a", password="b", ssl=True, cache_dir=tmp_path)
    assert c.host == "https://myrouter.net"
    c.close()


def test_resolve_host_bare_auto_detect_redirect(tmp_path, monkeypatch):
    # Mock httpx.Client inside _resolve_host to simulate 302 redirect from http to https
    orig_client = httpx.Client

    def mock_probe_client(*args, **kwargs):
        if kwargs.get("follow_redirects") is False:
            def handler(req):
                if str(req.url) == "http://auto-router.net/auth":
                    return httpx.Response(302, headers={"Location": "https://auto-router.net/"})
                return httpx.Response(200)
            return orig_client(transport=httpx.MockTransport(handler))
        return orig_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", mock_probe_client)

    c = KeeneticClient(host="auto-router.net", user="a", password="b", cache_dir=tmp_path)
    assert c.host == "https://auto-router.net"
    c.close()

    # Verify scheme was cached in schemes.json
    import json
    schemes_file = tmp_path / "schemes.json"
    assert schemes_file.exists()
    cached = json.loads(schemes_file.read_text(encoding="utf-8"))
    assert cached["auto-router.net"] == "https"


def test_get_log_parsing_and_filtering(tmp_path):
    mock_log_response = {
        "log": {
            "100": {
                "id": 100,
                "timestamp": "Oct  6 12:00:00",
                "ident": "ndm",
                "message": {"level": "Info", "label": "I", "message": "System booted successfully"},
            },
            "101": {
                "id": 101,
                "timestamp": "Oct  6 12:01:00",
                "ident": "ndhcps",
                "message": {"level": "Notice", "label": "N", "message": "DHCP lease granted to client"},
            },
            "102": {
                "id": 102,
                "timestamp": "Oct  6 12:02:00",
                "ident": "ndm",
                "message": {"level": "Warning", "label": "W", "message": "High memory consumption detected"},
            },
            "103": {
                "id": 103,
                "timestamp": "Oct  6 12:03:00",
                "ident": "wpa_supplicant",
                "message": {"level": "Error", "label": "E", "message": "Authentication failed for AP"},
            },
        }
    }

    client = KeeneticClient(host="http://router.local", user="admin", password="pw", cache_dir=tmp_path)

    def handler(request):
        return httpx.Response(200, json=[{"parse": mock_log_response, "status": [{"status": "ok"}]}])

    client._client = httpx.Client(transport=httpx.MockTransport(handler))

    # All logs (default 50)
    all_logs = client.get_log(lines=0)
    assert len(all_logs) == 4
    assert [x["id"] for x in all_logs] == [100, 101, 102, 103]

    # Level filter: Warning (should include Warning and Error)
    warn_logs = client.get_log(lines=0, level="warning")
    assert len(warn_logs) == 2
    assert [x["id"] for x in warn_logs] == [102, 103]

    # Level filter: Error only
    err_logs = client.get_log(lines=0, level="error")
    assert len(err_logs) == 1
    assert err_logs[0]["id"] == 103

    # Service filter: ndm
    ndm_logs = client.get_log(lines=0, service="ndm")
    assert len(ndm_logs) == 2
    assert [x["id"] for x in ndm_logs] == [100, 102]

    # Grep filter
    grep_logs = client.get_log(lines=0, grep="memory")
    assert len(grep_logs) == 1
    assert grep_logs[0]["id"] == 102

    # Lines limit: tail 2
    tail_logs = client.get_log(lines=2)
    assert len(tail_logs) == 2
    assert [x["id"] for x in tail_logs] == [102, 103]

    client.close()


def test_get_conntrack_and_grouping(tmp_path):
    from keenctl.client import group_unreplied_conntrack

    mock_nat = [
        # Normal active connection
        {
            "protocol": "TCP",
            "src": "192.168.1.100",
            "sport": 50000,
            "dst": "1.1.1.1",
            "dport": 443,
            "packets": 10,
            "bytes": 1000,
            "packets-out": 8,
            "bytes-out": 2000,
        },
        # Unreplied unicast NTP
        {
            "protocol": "UDP",
            "src": "192.168.1.120",
            "sport": 40001,
            "dst": "198.51.100.44",
            "dport": 123,
            "packets": 5,
            "bytes": 380,
            "packets-out": 0,
            "bytes-out": 0,
        },
        # Another unreplied to same NTP from different host
        {
            "protocol": "UDP",
            "src": "192.168.1.121",
            "sport": 40002,
            "dst": "198.51.100.44",
            "dport": 123,
            "packets": 7,
            "bytes": 532,
            "packets-out": 0,
            "bytes-out": 0,
        },
        # Multicast unreplied (should be filtered out by default in unreplied mode)
        {
            "protocol": "UDP",
            "src": "192.168.1.1",
            "sport": 5683,
            "dst": "224.0.0.187",
            "dport": 5683,
            "packets": 1,
            "bytes": 45,
            "packets-out": 0,
            "bytes-out": 0,
        },
    ]

    mock_hotspot = {
        "host": [
            {"ip": "192.168.1.100", "name": "Laptop"},
            {"ip": "192.168.1.120", "name": "Device 1"},
            {"ip": "192.168.1.121", "name": "Device 2"},
        ]
    }

    client = KeeneticClient(host="http://router.local", user="admin", password="pw", cache_dir=tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/rci/show/ip/nat":
            return httpx.Response(200, json=mock_nat)
        elif request.url.path == "/rci/show/ip/hotspot":
            return httpx.Response(200, json=mock_hotspot)
        return httpx.Response(404)

    client._client = httpx.Client(transport=httpx.MockTransport(handler))

    # 1. Full conntrack table
    all_conns = client.get_conntrack()
    assert len(all_conns) == 4
    assert all_conns[0]["src_name"] == "Laptop"
    assert all_conns[0]["service"] == "HTTPS"

    # 2. Unreplied only (multicast filtered by default)
    unreplied = client.get_conntrack(unreplied_only=True)
    assert len(unreplied) == 2
    assert all(c["packets_recv"] == 0 for c in unreplied)
    assert {c["src_name"] for c in unreplied} == {"Device 1", "Device 2"}
    assert unreplied[0]["service"] == "NTP"

    # 3. Unreplied with broadcast included
    unreplied_with_mcast = client.get_conntrack(unreplied_only=True, include_broadcast=True)
    assert len(unreplied_with_mcast) == 3

    # 4. Filter by protocol
    tcp_conns = client.get_conntrack(proto="tcp")
    assert len(tcp_conns) == 1
    assert tcp_conns[0]["protocol"] == "TCP"

    # 5. Grouping unreplied
    grouped = group_unreplied_conntrack(unreplied)
    assert len(grouped) == 1
    assert grouped[0]["dst"] == "198.51.100.44"
    assert grouped[0]["dport"] == 123
    assert grouped[0]["conns_count"] == 2
    assert grouped[0]["packets"] == 12
    assert "192.168.1.120 (Device 1)" in grouped[0]["sources"]
    assert "192.168.1.121 (Device 2)" in grouped[0]["sources"]

    client.close()


def test_get_hosts_and_filtering(tmp_path):
    mock_hotspot = {
        "host": [
            {
                "ip": "192.168.1.10",
                "mac": "aa:bb:cc:11:22:33",
                "name": "Workstation",
                "active": True,
                "interface": {"name": "Bridge0", "id": "Bridge0"},
                "policy": "Policy1",
                "rxbytes": 100,
                "txbytes": 200,
            },
            {
                "ip": "192.168.2.20",
                "mac": "aa:bb:cc:11:22:44",
                "name": "Office Printer",
                "active": True,
                "interface": {"name": "Bridge2", "id": "Bridge2"},
                "policy": "Policy1",
                "rxbytes": 500,
                "txbytes": 600,
            },
            {
                "ip": "192.168.2.30",
                "mac": "aa:bb:cc:11:22:55",
                "name": "Storage Server",
                "active": False,
                "interface": {"name": "Bridge2", "id": "Bridge2"},
                "policy": "Main",
                "rxbytes": 0,
                "txbytes": 0,
            },
        ]
    }
    client = KeeneticClient(host="http://router.local", user="admin", password="pw", cache_dir=tmp_path)
    client._client = httpx.Client(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=mock_hotspot))
    )

    # All hosts
    all_hosts = client.get_hosts()
    assert len(all_hosts) == 3

    # Active only
    active_hosts = client.get_hosts(active_only=True)
    assert len(active_hosts) == 2

    # Filter by interface
    bridge2_hosts = client.get_hosts(interface="Bridge2")
    assert len(bridge2_hosts) == 2
    assert all(h["interface"] == "Bridge2" for h in bridge2_hosts)

    # Filter by subnet CIDR
    sub_hosts = client.get_hosts(subnet="192.168.2.0/24")
    assert len(sub_hosts) == 2
    assert {h["ip"] for h in sub_hosts} == {"192.168.2.20", "192.168.2.30"}

    # Filter by subnet prefix
    prefix_hosts = client.get_hosts(subnet="192.168.1.")
    assert len(prefix_hosts) == 1
    assert prefix_hosts[0]["ip"] == "192.168.1.10"

    client.close()


def test_get_wifi_associations(tmp_path):
    mock_assoc = {
        "station": [
            {
                "mac": "aa:bb:cc:dd:ee:22",
                "rssi": -53,
                "txrate": 65,
                "rxrate": 72,
                "uptime": 240,
                "ap": "WifiMaster0/AccessPoint0",
            }
        ]
    }
    mock_hotspot = {
        "host": [
            {
                "mac": "aa:bb:cc:dd:ee:22",
                "ip": "192.168.1.150",
                "name": "Smart Plug",
            }
        ]
    }

    client = KeeneticClient(host="http://router.local", user="admin", password="pw", cache_dir=tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        if "show/associations" in str(request.url):
            return httpx.Response(200, json=mock_assoc)
        elif "show/ip/hotspot" in str(request.url):
            return httpx.Response(200, json=mock_hotspot)
        return httpx.Response(404)

    client._client = httpx.Client(transport=httpx.MockTransport(handler))

    st_list = client.get_wifi_associations()
    assert len(st_list) == 1
    assert st_list[0]["mac"] == "aa:bb:cc:dd:ee:22"
    assert st_list[0]["name"] == "Smart Plug"
    assert st_list[0]["ip"] == "192.168.1.150"
    assert st_list[0]["rssi"] == -53

    client.close()


def test_diagnose_healthy_and_issues(tmp_path):
    client = KeeneticClient(host="http://router.local", user="admin", password="pw", cache_dir=tmp_path)

    # 1. Healthy state
    def healthy_handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "show/system" in path:
            return httpx.Response(200, json={"uptime": 10000, "cpuload": 10, "memory": "100/500"})
        elif "show/version" in path:
            return httpx.Response(200, json={"model": "Peak", "release": "5.01", "device": "Peak"})
        elif "show/internet/status" in path:
            return httpx.Response(200, json={"internet": True, "gateway-accessible": True, "dns-accessible": True})
        elif "show/ip/nat" in path:
            return httpx.Response(200, json=[])
        elif "show/ip/hotspot" in path:
            return httpx.Response(200, json={"host": []})
        elif "show/associations" in path:
            return httpx.Response(200, json={"station": []})
        elif "parse" in request.read().decode():
            return httpx.Response(200, json=[{"parse": {"log": []}}])
        return httpx.Response(200, json={})

    client._client = httpx.Client(transport=httpx.MockTransport(healthy_handler))
    res_healthy = client.diagnose()
    assert res_healthy["status"] == "ok"
    assert len(res_healthy["issues"]) == 0
    assert res_healthy["checks"]["internet"]["status"] == "ok"

    # 2. Issues state (dead connections + flapping in logs + WAN down)
    mock_log_flapping = [
        {"id": 1, "timestamp": "Oct 6 21:00:01", "ident": "ndm", "level": "Info", "message": "WifiMonitor: STA(aa:bb:cc:dd:ee:01) had deauthenticated by STA"},
        {"id": 2, "timestamp": "Oct 6 21:00:02", "ident": "ndm", "level": "Info", "message": "WifiMonitor: STA(aa:bb:cc:dd:ee:01) had associated"},
        {"id": 3, "timestamp": "Oct 6 21:00:03", "ident": "ndm", "level": "Info", "message": "WifiMonitor: STA(aa:bb:cc:dd:ee:01) had deauthenticated by STA"},
        {"id": 4, "timestamp": "Oct 6 21:00:04", "ident": "ndm", "level": "Info", "message": "WifiMonitor: STA(aa:bb:cc:dd:ee:01) had associated"},
        {"id": 5, "timestamp": "Oct 6 21:00:05", "ident": "ndm", "level": "Info", "message": "WifiMonitor: STA(aa:bb:cc:dd:ee:01) had deauthenticated by STA"},
        {"id": 6, "timestamp": "Oct 6 21:00:06", "ident": "ndm", "level": "Info", "message": "WifiMonitor: STA(aa:bb:cc:dd:ee:01) had associated"},
        {"id": 7, "timestamp": "Oct 6 21:00:07", "ident": "ndhcps", "level": "Error", "message": "failed to bind pool"},
    ]
    mock_nat_unreplied = [
        {
            "protocol": "TCP",
            "src": "192.168.1.50",
            "sport": 50000,
            "dst": "1.2.3.4",
            "dport": 8883,
            "packets": 25,
            "bytes": 1000,
            "packets-out": 0,
            "bytes-out": 0,
        }
    ]
    mock_hotspot_issues = {
        "host": [
            {
                "ip": "192.168.1.50",
                "mac": "aa:bb:cc:dd:ee:01",
                "name": "Smart Plug",
                "policy": "Policy1",
                "interface": {"name": "Bridge0"},
            }
        ]
    }

    def issues_handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "show/system" in path:
            return httpx.Response(200, json={"uptime": 10000, "cpuload": 10, "memory": "100/500"})
        elif "show/version" in path:
            return httpx.Response(200, json={"model": "Peak", "release": "5.01", "device": "Peak"})
        elif "show/internet/status" in path:
            return httpx.Response(200, json={"internet": False, "gateway-accessible": False, "dns-accessible": False})
        elif "show/ip/nat" in path:
            return httpx.Response(200, json=mock_nat_unreplied)
        elif "show/ip/hotspot" in path:
            return httpx.Response(200, json=mock_hotspot_issues)
        elif "show/associations" in path:
            return httpx.Response(200, json={"station": []})
        elif "parse" in request.read().decode():
            return httpx.Response(200, json=[{"parse": {"log": mock_log_flapping}}])
        return httpx.Response(200, json={})

    client._client = httpx.Client(transport=httpx.MockTransport(issues_handler))
    res_issues = client.diagnose()
    assert res_issues["status"] in ("warning", "critical")
    categories = {iss["category"] for iss in res_issues["issues"]}
    assert "internet" in categories
    assert "conntrack" in categories
    assert "clients" in categories
    assert "log" in categories

    client.close()


def test_parse_keenetic_version():
    from keenctl.client import parse_keenetic_version
    assert parse_keenetic_version("5.1.7") == (5, 1)
    assert parse_keenetic_version("5.01.C.7.0-4") == (5, 1)
    assert parse_keenetic_version("4.02.B.1.0-1") == (4, 2)
    assert parse_keenetic_version("5.2.0") == (5, 2)
    assert parse_keenetic_version("3.09.C.4.0-0") == (3, 9)
    assert parse_keenetic_version("") == (0, 0)
    assert parse_keenetic_version(None) == (0, 0)


def test_capabilities_awg2(tmp_path):
    client = KeeneticClient(host="http://router.local", user="admin", password="p", cache_dir=tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "show/version" in path:
            return httpx.Response(200, json={
                "model": "Peak (KN-2710)",
                "release": "5.01.C.7.0-4",
                "title": "5.1.7",
                "arch": "aarch64",
                "ndw": {"components": "wireguard,wireguard-server,opkg,base"}
            })
        return httpx.Response(200, json={})

    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    caps = client.get_capabilities()

    assert caps["device"]["model"] == "Peak (KN-2710)"
    assert caps["vpn"]["wireguard"]["installed"] is True
    assert caps["vpn"]["amnezia"]["supported"] is True
    assert caps["vpn"]["amnezia"]["protocol"] == "AWG 2.0"
    assert caps["vpn"]["amnezia"]["status"] == "ready"
    assert caps["routing"]["fqdn_domain_routing"]["supported"] is True
    assert caps["extensions"]["opkg"] is True
    client.close()


def test_capabilities_awg3(tmp_path):
    client = KeeneticClient(host="http://router.local", user="admin", password="p", cache_dir=tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "show/version" in path:
            return httpx.Response(200, json={
                "model": "Hero",
                "release": "5.02.A.11.0-1",
                "title": "5.2.0",
                "arch": "aarch64",
                "ndw": {"components": "wireguard,base"}
            })
        return httpx.Response(200, json={})

    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    caps = client.get_capabilities()

    assert caps["vpn"]["amnezia"]["supported"] is True
    assert caps["vpn"]["amnezia"]["protocol"] == "AWG 3.1+"
    assert caps["vpn"]["amnezia"]["status"] == "ready"
    client.close()


def test_capabilities_no_wireguard(tmp_path):
    client = KeeneticClient(host="http://router.local", user="admin", password="p", cache_dir=tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "show/version" in path:
            return httpx.Response(200, json={
                "model": "Speedster",
                "release": "4.02.C.3.0",
                "title": "4.2.3",
                "ndw": {"components": "base,dhcpd"}
            })
        return httpx.Response(200, json={})

    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    caps = client.get_capabilities()

    assert caps["vpn"]["wireguard"]["installed"] is False
    assert caps["vpn"]["amnezia"]["supported"] is True
    assert caps["vpn"]["amnezia"]["protocol"] == "AWG 2.0"
    assert caps["vpn"]["amnezia"]["status"] == "available_with_component"
    client.close()


def test_capabilities_old_keeneticos(tmp_path):
    client = KeeneticClient(host="http://router.local", user="admin", password="p", cache_dir=tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "show/version" in path:
            return httpx.Response(200, json={
                "model": "Giga",
                "release": "3.09.C.4.0",
                "title": "3.9.4",
                "ndw": {"components": "wireguard,base"}
            })
        return httpx.Response(200, json={})

    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    caps = client.get_capabilities()

    assert caps["vpn"]["amnezia"]["supported"] is False
    assert caps["vpn"]["amnezia"]["status"] == "not_supported"
    assert caps["routing"]["fqdn_domain_routing"]["supported"] is False
    client.close()


def test_get_components_and_amnezia_enrichment(tmp_path):
    client = KeeneticClient(host="http://router.local", user="admin", password="p", cache_dir=tmp_path)

    mock_components_data = {
        "component": {
            "wireguard": {
                "installed": "4.9+1.0",
                "version": "4.9+1.0",
                "size": 200000,
                "group": "Networking",
                "description": {"RU": "Служба WireGuard VPN", "EN": "WireGuard VPN service"},
                "queued": True,
            },
            "zerotier": {
                "installed": None,
                "version": "1.14.0",
                "size": 1200000,
                "group": "Networking",
                "description": {"RU": "ZeroTier клиент", "EN": "ZeroTier client"},
                "queued": False,
            },
        }
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "show/version" in path:
            return httpx.Response(200, json={
                "model": "Peak",
                "release": "5.01",
                "title": "5.1.7",
                "ndw": {"components": "wireguard,base"}
            })
        elif "parse" in request.read().decode():
            return httpx.Response(200, json=[{"parse": mock_components_data}])
        return httpx.Response(200, json={})

    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    comps = client.get_components()

    assert len(comps) == 2
    wg = next(c for c in comps if c["name"] == "wireguard")
    assert wg["installed"] is True
    assert "amnezia" in wg
    assert wg["amnezia"]["supported"] is True
    assert wg["amnezia"]["protocol"] == "AWG 2.0"
    assert "AWG 2.0" in wg["amnezia"]["badge"]

    zt = next(c for c in comps if c["name"] == "zerotier")
    assert zt["installed"] is False
    assert "amnezia" not in zt

    # Filter installed only
    installed_only = client.get_components(installed_only=True)
    assert len(installed_only) == 1
    assert installed_only[0]["name"] == "wireguard"

    # Search query
    search_res = client.get_components(search_query="zerotier")
    assert len(search_res) == 1
    assert search_res[0]["name"] == "zerotier"

    client.close()


def test_components_actions(tmp_path):
    client = KeeneticClient(host="http://router.local", user="admin", password="p", cache_dir=tmp_path)
    recorded_commands = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = request.read().decode()
        recorded_commands.append(body)
        return httpx.Response(200, json=[{"prompt": "(config)"}])

    client._client = httpx.Client(transport=httpx.MockTransport(handler))

    client.install_component("wireguard")
    assert any("components install wireguard" in cmd for cmd in recorded_commands)

    client.remove_component("tor")
    assert any("components remove tor" in cmd for cmd in recorded_commands)

    client.commit_components()
    assert any("components commit" in cmd for cmd in recorded_commands)

    client.close()


def test_get_services_and_filtering(tmp_path):
    client = KeeneticClient(host="http://router.local", user="admin", password="p", cache_dir=tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "service" in path:
            return httpx.Response(200, json={
                "http": True, "ssh": True, "telnet": True, "sstp-server": True,
                "dns-proxy": True, "dhcp": True,
            })
        elif "ip/http" in path:
            return httpx.Response(200, json={
                "security-level": {"public": True, "ssl": True},
                "ssl": {"enable": True, "redirect": True, "port": 443},
                "port": 80,
                "webdav": True,
            })
        elif "ip/ssh" in path:
            return httpx.Response(200, json={
                "security-level": {"private": True},
                "port": 22,
                "lockout-policy": {"threshold": 5, "duration": 15},
            })
        elif "ip/telnet" in path:
            return httpx.Response(200, json={
                "security-level": {"private": True},
                "port": 23,
            })
        elif "show/sstp-server" in path:
            return httpx.Response(200, json={
                "enabled": True,
                "ndns-name": "test.keenetic.pro",
                "has-ndns-certificate": True,
            })
        elif "sstp-server" in path:
            return httpx.Response(200, json={
                "pool-range": {"begin": "172.16.1.10", "size": 10},
            })
        elif "torrent" in path:
            return httpx.Response(200, json={
                "rpc-port": {"port": 8090, "public": False},
                "peer-port": 51413,
            })
        elif "cifs" in path:
            return httpx.Response(200, json={"automount": True})
        return httpx.Response(404)

    client._client = httpx.Client(transport=httpx.MockTransport(handler))

    # 1. Default (management + apps + filesharing, without network daemons)
    default_svcs = client.get_services()
    names = [s["name"] for s in default_svcs]
    assert "http" in names
    assert "ssh" in names
    assert "telnet" in names
    assert "sstp-server" in names
    assert "transmission" in names
    assert "cifs" in names
    assert "dns-proxy" not in names

    http_svc = next(s for s in default_svcs if s["name"] == "http")
    assert http_svc["ports"] == [80, 443]
    assert http_svc["security_level"] == "public (ssl)"
    assert "HTTPS/SSL enabled" in http_svc["details"]

    ssh_svc = next(s for s in default_svcs if s["name"] == "ssh")
    assert ssh_svc["ports"] == [22]
    assert ssh_svc["security_level"] == "private"
    assert "Lockout active" in ssh_svc["details"]

    sstp_svc = next(s for s in default_svcs if s["name"] == "sstp-server")
    assert sstp_svc["ports"] == [443]
    assert "test.keenetic.pro" in sstp_svc["details"]

    # 2. Management only
    mgmt_svcs = client.get_services(management_only=True)
    mgmt_names = [s["name"] for s in mgmt_svcs]
    assert set(mgmt_names) == {"http", "ssh", "telnet", "sstp-server"}

    # 3. All services (includes network daemons)
    all_svcs = client.get_services(all_services=True)
    all_names = [s["name"] for s in all_svcs]
    assert "dns-proxy" in all_names
    assert "dhcp" in all_names

    client.close()


def test_diagnose_services_security_audit(tmp_path):
    client = KeeneticClient(host="http://router.local", user="admin", password="p", cache_dir=tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "show/system" in path:
            return httpx.Response(200, json={"uptime": 5000, "cpuload": 5, "memory": "100/500"})
        elif "show/version" in path:
            return httpx.Response(200, json={"model": "Peak", "release": "5.01"})
        elif "show/internet/status" in path:
            return httpx.Response(200, json={"internet": True, "gateway-accessible": True, "dns-accessible": True})
        elif "show/ip/nat" in path or "show/ip/hotspot" in path or "show/associations" in path:
            return httpx.Response(200, json={})
        elif "service" in path:
            return httpx.Response(200, json={"http": True, "ssh": True, "telnet": True})
        elif "ip/http" in path:
            # Web UI exposed to WAN without SSL
            return httpx.Response(200, json={"security-level": {"public": True}, "ssl": {"enable": False}})
        elif "ip/ssh" in path:
            # SSH exposed to public WAN
            return httpx.Response(200, json={"security-level": {"public": True}, "port": 22})
        elif "ip/telnet" in path:
            # Telnet exposed to public WAN
            return httpx.Response(200, json={"security-level": {"public": True}, "port": 23})
        elif "parse" in request.read().decode():
            return httpx.Response(200, json=[{"parse": {"log": []}}])
        return httpx.Response(200, json={})

    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    diag = client.diagnose()

    assert diag["status"] == "critical"
    assert diag["checks"]["services"]["status"] == "fail"

    issue_titles = [i["title"] for i in diag["issues"]]
    assert any("Unencrypted Telnet daemon exposed to WAN" in t for t in issue_titles)
    assert any("SSH management daemon exposed to public WAN" in t for t in issue_titles)
    assert any("Web UI / RCI exposed to WAN without SSL encryption" in t for t in issue_titles)

    client.close()


def test_capabilities_sstp(tmp_path):
    client = KeeneticClient(host="http://router.local", user="admin", password="p", cache_dir=tmp_path)

    mock_ver = {
        "model": "Peak",
        "release": "5.01.C.7.0-4",
        "title": "5.1.7",
        "ndw": {"components": "base,wireguard,sstp,sstp-server,opkg"},
    }
    client._client = httpx.Client(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=mock_ver))
    )

    caps = client.get_capabilities()
    assert caps["vpn"]["sstp"]["installed"] is True
    assert caps["vpn"]["sstp"]["server_installed"] is True
    client.close()



