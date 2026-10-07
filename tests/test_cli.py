import pytest
import sys
from keenctl.cli import build_parser, _normalize_argv

def test_normalize_argv_flags():
    # Test -p info -> -p is a boolean flag, info is subcmd
    argv1 = ["--host", "http://10.200.1.1", "-p", "info"]
    norm1 = _normalize_argv(argv1)
    args1 = build_parser().parse_args(norm1)
    assert args1.ask_pass is True
    assert args1.password_stdin is False
    assert args1.command == "info"

    # Test --ask-pass info
    argv2 = ["--host", "http://10.200.1.1", "--ask-pass", "info"]
    norm2 = _normalize_argv(argv2)
    args2 = build_parser().parse_args(norm2)
    assert args2.ask_pass is True
    assert args2.command == "info"

    # Test -p - info -> normalized to --password-stdin
    argv3 = ["--host", "http://10.200.1.1", "-p", "-", "info"]
    norm3 = _normalize_argv(argv3)
    args3 = build_parser().parse_args(norm3)
    assert args3.ask_pass is False
    assert args3.password_stdin is True
    assert args3.command == "info"

    # Test --password-stdin
    argv4 = ["--password-stdin", "get", "show/system"]
    norm4 = _normalize_argv(argv4)
    args4 = build_parser().parse_args(norm4)
    assert args4.password_stdin is True
    assert args4.command == "get"
    assert args4.path == "show/system"

    # Test interfaces
    argv_if = ["interfaces", "-a"]
    args_if = build_parser().parse_args(argv_if)
    assert args_if.command == "interfaces"
    assert args_if.active is True

    # Test routes
    argv_rt = ["routes"]
    args_rt = build_parser().parse_args(argv_rt)
    assert args_rt.command == "routes"

    # Test reboot
    argv_rb = ["reboot", "-y"]
    args_rb = build_parser().parse_args(argv_rb)
    assert args_rb.command == "reboot"
    assert args_rb.yes is True

    # Test trailing global flags like info --json or hosts -a --host ...
    argv_trail = ["hosts", "-a", "--json", "--host", "https://router.local", "--ssl"]
    norm_trail = _normalize_argv(argv_trail)
    args_trail = build_parser().parse_args(norm_trail)
    assert args_trail.command == "hosts"
    assert args_trail.active is True
    assert args_trail.json is True
    assert args_trail.ssl is True
    assert args_trail.host == "https://router.local"

    # Test --https alias
    argv_https = ["--https", "info"]
    norm_https = _normalize_argv(argv_https)
    args_https = build_parser().parse_args(norm_https)
    assert args_https.ssl is True

    # Test conntrack subcommands and flags
    argv_ct = ["conntrack", "--unreplied", "-g", "--proto", "udp"]
    norm_ct = _normalize_argv(argv_ct)
    args_ct = build_parser().parse_args(norm_ct)
    assert args_ct.command == "conntrack"
    assert args_ct.unreplied is True
    assert args_ct.group is True
    assert args_ct.proto == "udp"


def test_load_env_file_priority_and_fallback(tmp_path, monkeypatch):
    import os
    from keenctl.cli import _load_env_file

    monkeypatch.delenv("KEENETIC_HOST", raising=False)
    monkeypatch.delenv("KEENETIC_USER", raising=False)
    monkeypatch.delenv("KEENETIC_PASSWORD", raising=False)

    global_cfg_dir = tmp_path / "global_config" / "keenctl"
    global_cfg_dir.mkdir(parents=True)
    (global_cfg_dir / ".env").write_text(
        "KEENETIC_HOST=https://global.router.local\nKEENETIC_USER=global_user\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "global_config"))

    local_dir = tmp_path / "work"
    local_dir.mkdir()
    (local_dir / ".env").write_text("KEENETIC_HOST=https://local.router.local\n", encoding="utf-8")

    monkeypatch.chdir(local_dir)
    _load_env_file()

    # Local overrides global
    assert os.environ.get("KEENETIC_HOST") == "https://local.router.local"
    # Fallback populates missing keys from global
    assert os.environ.get("KEENETIC_USER") == "global_user"


def test_format_error_json(capsys):
    import json
    from keenctl.cli import _format_error
    from keenctl.client import KeeneticConnectionError

    err = KeeneticConnectionError(
        message="No route to host http://10.122.1.1",
        hint="Ensure VPN is connected",
        host="http://10.122.1.1",
    )
    _format_error(err, raw_json=True)
    captured = capsys.readouterr()
    data = json.loads(captured.err)
    assert data["error"] is True
    assert data["type"] == "connection_error"
    assert "No route to host" in data["message"]
    assert "Ensure VPN" in data["hint"]
    assert data["host"] == "http://10.122.1.1"


def test_format_error_text(capsys):
    from keenctl.cli import _format_error
    from keenctl.client import KeeneticAuthError

    err = KeeneticAuthError(
        message="Authentication failed for user 'admin'",
        hint="Check your password",
    )
    _format_error(err, raw_json=False)
    captured = capsys.readouterr()
    assert "Error: Authentication failed for user 'admin'" in captured.err
    assert "Hint:  Check your password" in captured.err


def test_log_cli_parser():
    argv = ["log", "-n", "25", "-l", "warning", "-s", "ndm", "-g", "fail"]
    norm = _normalize_argv(argv)
    args = build_parser().parse_args(norm)
    assert args.command == "log"
    assert args.lines == 25
    assert args.level == "warning"
    assert args.service == "ndm"
    assert args.grep == "fail"


def test_format_log_line():
    from keenctl.cli import _format_log_line

    entry = {
        "id": 105,
        "timestamp": "Oct  6 20:10:42",
        "ident": "ndhcps",
        "level": "Error",
        "label": "E",
        "message": "failed to allocate lease",
    }
    # Plain text format (non-tty)
    plain = _format_log_line(entry, is_tty=False)
    assert plain == "Oct  6 20:10:42 [ndhcps] [E] failed to allocate lease"

    # Colored format (tty)
    tty_str = _format_log_line(entry, is_tty=True)
    assert "\033[1;31m" in tty_str
    assert "failed to allocate lease" in tty_str


def test_hosts_cli_parser_filters():
    argv = ["hosts", "-a", "-i", "Bridge2", "-s", "192.168.1.0/24"]
    norm = _normalize_argv(argv)
    args = build_parser().parse_args(norm)
    assert args.command == "hosts"
    assert args.active is True
    assert args.interface == "Bridge2"
    assert args.subnet == "192.168.1.0/24"


def test_doctor_and_wifi_cli_parser():
    argv_doc = ["doctor"]
    norm_doc = _normalize_argv(argv_doc)
    args_doc = build_parser().parse_args(norm_doc)
    assert args_doc.command == "doctor"

    argv_diag = ["diagnose"]
    norm_diag = _normalize_argv(argv_diag)
    args_diag = build_parser().parse_args(norm_diag)
    assert args_diag.command == "doctor"

    argv_wifi = ["wifi"]
    norm_wifi = _normalize_argv(argv_wifi)
    args_wifi = build_parser().parse_args(norm_wifi)
    assert args_wifi.command == "wifi"


def test_capabilities_cli_parser():
    argv = ["capabilities", "--json"]
    norm = _normalize_argv(argv)
    args = build_parser().parse_args(norm)
    assert args.command == "capabilities"
    assert args.json is True


def test_components_cli_parser():
    # components list
    argv1 = ["components", "list", "-i", "-g", "Networking"]
    norm1 = _normalize_argv(argv1)
    args1 = build_parser().parse_args(norm1)
    assert args1.command == "components"
    assert args1.components_action == "list"
    assert args1.installed is True
    assert args1.group == "Networking"

    # components search
    argv2 = ["components", "search", "wireguard"]
    norm2 = _normalize_argv(argv2)
    args2 = build_parser().parse_args(norm2)
    assert args2.command == "components"
    assert args2.components_action == "search"
    assert args2.query == "wireguard"

    # components install with commit
    argv3 = ["components", "install", "wireguard", "--commit", "-y"]
    norm3 = _normalize_argv(argv3)
    args3 = build_parser().parse_args(norm3)
    assert args3.command == "components"
    assert args3.components_action == "install"
    assert args3.component_name == "wireguard"
    assert args3.commit is True
    assert args3.yes is True

    # components commit
    argv4 = ["components", "commit", "-y"]
    norm4 = _normalize_argv(argv4)
    args4 = build_parser().parse_args(norm4)
    assert args4.command == "components"
    assert args4.components_action == "commit"
    assert args4.yes is True


def test_services_cli_parser():
    # default services
    argv1 = ["services"]
    norm1 = _normalize_argv(argv1)
    args1 = build_parser().parse_args(norm1)
    assert args1.command == "services"
    assert args1.all is False
    assert args1.management is False

    # services with --all and --json
    argv2 = ["services", "--all", "--json"]
    norm2 = _normalize_argv(argv2)
    args2 = build_parser().parse_args(norm2)
    assert args2.command == "services"
    assert args2.all is True
    assert args2.json is True

    # services with -m
    argv3 = ["services", "-m"]
    norm3 = _normalize_argv(argv3)
    args3 = build_parser().parse_args(norm3)
    assert args3.command == "services"
    assert args3.management is True



