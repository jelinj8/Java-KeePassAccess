import asyncio
import sys

import pytest

from keepass_access import KeePassAccess, NotRunning, mcp_server
from conftest import PASSWORD, FakeTransport


@pytest.fixture
def server(monkeypatch):
    transport = FakeTransport()
    monkeypatch.setattr(mcp_server, "connect", lambda: KeePassAccess(transport))
    return transport


def test_tools_are_registered():
    tools = {t.name: t for t in asyncio.run(mcp_server.server.list_tools())}
    assert set(tools) == {"keepass_status", "list_entries", "list_fields", "run_with_secrets"}
    for name in ("keepass_status", "list_entries", "list_fields"):
        assert tools[name].annotations.read_only_hint
    assert not tools["run_with_secrets"].annotations.read_only_hint


def test_status(server):
    assert "1 unlocked" in mcp_server.keepass_status()


def test_status_locked(monkeypatch):
    monkeypatch.setattr(mcp_server, "connect", lambda: KeePassAccess(FakeTransport({"PING\n": "OK 0\n\n"})))
    assert "locked" in mcp_server.keepass_status()


def test_status_not_running(monkeypatch):
    class Down:
        def exchange(self, request):
            raise NotRunning("not running")

    monkeypatch.setattr(mcp_server, "connect", lambda: KeePassAccess(Down()))
    assert "not running" in mcp_server.keepass_status()


def test_list_entries(server):
    text = mcp_server.list_entries()
    assert "3f2504e04f8911d39a0c0305e82c3301\tDB\tapp-db-user, team" in text


def test_list_fields_has_no_values(server):
    text = mcp_server.list_fields("app-db-user")
    assert "Password\tset" in text and "HOST\tset" in text
    assert PASSWORD not in text and "db.example.org" not in text


@pytest.mark.skipif(sys.platform != "win32", reason="Windows shells")
def test_run_with_secrets(server):
    text = mcp_server.run_with_secrets("Write-Output \"$env:DB_HOST $env:PGPASSWORD\"",
                                       {"PGPASSWORD": "app-db-user", "DB_HOST": "app-db-user#HOST"})
    assert "exit code: 0" in text
    assert "injected and masked in output: DB_HOST, PGPASSWORD" in text
    assert "***DB_HOST*** ***PGPASSWORD***" in text
    assert PASSWORD not in text and "db.example.org" not in text


def test_run_with_secrets_locked_does_not_run(server, tmp_path):
    marker = tmp_path / "ran"
    text = mcp_server.run_with_secrets(f"New-Item '{marker}'", {"P": "locked"})
    assert text.startswith("Not run") and not marker.exists()


def test_run_via_mcp_protocol(server):
    """Through the server's call_tool, as a client would."""
    result = asyncio.run(mcp_server.server.call_tool("list_fields", {"ref": "app-db-user"}))
    assert PASSWORD not in str(result)
