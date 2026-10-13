import subprocess
import sys
import textwrap
import time

import pytest

from keepass_access import (AccessDenied, Ambiguous, EntryInfo, EntryNotFound, FieldNotFound, KeePassAccess,
                            KeePassAccessError, Locked, NotRunning, PipeTransport)
from conftest import PASSWORD, UUID, FakeTransport, b64


def test_ping(transport):
    assert KeePassAccess(transport).ping() == 1


def test_list(transport):
    assert KeePassAccess(transport).list() == [
        EntryInfo(UUID.lower(), "DB", ["app-db-user", "team"]),
        EntryInfo("0" * 32, "Old", []),
    ]


@pytest.mark.parametrize("ref", [UUID, "3f2504e0-4f89-11d3-9a0c-0305e82c3301", "{3F2504E0-4F89-11D3-9A0C-0305E82C3301}"])
def test_get_by_uuid(transport, ref):
    assert KeePassAccess(transport).password(ref) == PASSWORD
    assert transport.requests == [f"GET {UUID}\n"]


def test_find_by_name_and_cache(transport):
    kp = KeePassAccess(transport)
    assert kp.password(" app-db-user ") == PASSWORD
    assert kp.field("app-db-user", "UserName") == "app"
    assert transport.requests == ["FIND app-db-user\n"]


def test_field_exact_then_case_insensitive(transport):
    kp = KeePassAccess(transport)
    assert kp.field("app-db-user", "HOST") == "db.example.org"
    assert kp.field("app-db-user", "host") == "lower"
    assert kp.field("app-db-user", "username") == "app"
    with pytest.raises(FieldNotFound, match="has no field 'Nope'"):
        kp.field("app-db-user", "Nope")


def test_entry_returns_copy(transport):
    kp = KeePassAccess(transport)
    kp.entry("app-db-user")["Password"] = "changed"
    assert kp.password("app-db-user") == PASSWORD


@pytest.mark.parametrize("ref,error", [("locked", Locked), ("twice", Ambiguous), ("private", AccessDenied),
                                       ("missing", EntryNotFound)])
def test_errors(transport, ref, error):
    with pytest.raises(error):
        KeePassAccess(transport).password(ref)


@pytest.mark.parametrize("name", ["", "  ", "ExternalAccess", "a\nb"])
def test_invalid_names(transport, name):
    with pytest.raises(ValueError):
        KeePassAccess(transport).entry(name)


@pytest.mark.parametrize("response", ["", "HELLO\n\n", "OK\nno-tab\n\n", "OK\n!!!\t###\n\n", "ERR WEIRD x\n\n"])
def test_malformed_responses(response):
    with pytest.raises(KeePassAccessError):
        KeePassAccess(FakeTransport({"FIND x\n": response})).entry("x")


def test_error_messages_contain_no_values(transport):
    with pytest.raises(FieldNotFound) as e:
        KeePassAccess(transport).field("app-db-user", "Nope")
    assert PASSWORD not in str(e.value)


def test_not_running():
    t = PipeTransport("KeePassAccess-test-does-not-exist", wait_seconds=0.2)
    with pytest.raises(NotRunning):
        t.exchange("PING\n")


# A real named pipe served by PowerShell, answering like the plugin.
_SERVER = textwrap.dedent("""
    param($name, $reply, $count)
    for ($i = 0; $i -lt $count; $i++) {
      $s = New-Object System.IO.Pipes.NamedPipeServerStream($name, 'InOut')
      $s.WaitForConnection()
      $null = (New-Object System.IO.StreamReader($s)).ReadLine()
      $b = [Text.Encoding]::UTF8.GetBytes($reply)
      $s.Write($b, 0, $b.Length); $s.Flush(); $s.Disconnect(); $s.Dispose()
    }
""")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows named pipes")
def test_pipe_transport(tmp_path):
    script = tmp_path / "server.ps1"
    script.write_text(_SERVER, encoding="utf-8")
    name = f"KeePassAccess-pytest-{time.time_ns()}"
    reply = f"OK\n{b64('Password')}\t{b64(PASSWORD)}\n\n"
    server = subprocess.Popen(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script),
                               name, reply, "2"])
    try:
        kp = KeePassAccess(PipeTransport(name, wait_seconds=15))
        assert kp.password("first") == PASSWORD
        assert kp.password("second") == PASSWORD  # second connection: the pipe is re-created in between
    finally:
        server.wait(timeout=15)
