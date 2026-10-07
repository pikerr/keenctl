import pytest
import httpx
import json
from keenctl.client import KeeneticClient, KeeneticCommandError

def test_mock_rci_flow(tmp_path):
    # Mock transport simulating Keenetic Challenge-Response and RCI
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth":
            if request.method == "GET":
                return httpx.Response(
                    401,
                    headers={
                        "X-NDM-Realm": "Keenetic Extra",
                        "X-NDM-Challenge": "0123456789abcdef0123456789abcdef",
                        "Set-Cookie": "custom_cookie_name=session_val; Path=/",
                    },
                )
            elif request.method == "POST":
                return httpx.Response(200, json={"status": "authenticated"})
        elif request.url.path == "/rci/show/system":
            return httpx.Response(200, json={"uptime": 12345, "cpuload": 12})
        elif request.url.path == "/rci/":
            # Command execution payload
            data = json.loads(request.content)
            if isinstance(data, list) and data[0].get("parse") == "bad_command":
                return httpx.Response(
                    200,
                    json=[{"status": [{"error": True, "message": "parse error: bad_command"}]}],
                )
            return httpx.Response(
                200,
                json=[{"status": [{"message": "done"}], "parse": {"success": True}}],
            )
        return httpx.Response(404)

    client = KeeneticClient(
        host="http://router.local",
        user="admin",
        password="secret",
        cache_dir=tmp_path,
    )
    client._client = httpx.Client(transport=httpx.MockTransport(handler))

    # Test GET
    res = client.get("show/system")
    assert res == {"uptime": 12345, "cpuload": 12}

    # Test valid CMD
    cmd_res = client.cmd("good_command")
    assert cmd_res == {"success": True}

    # Test invalid CMD raises KeeneticCommandError
    with pytest.raises(KeeneticCommandError, match="bad_command"):
        client.cmd("bad_command")

    client.close()
