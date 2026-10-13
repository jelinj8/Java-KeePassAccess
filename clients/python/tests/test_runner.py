import os
import sys
import time

import pytest

from keepass_access import EntryNotFound, FieldNotFound, KeePassAccess, Locked, runner
from conftest import PASSWORD

windows = pytest.mark.skipif(sys.platform != "win32", reason="Windows shells")


@pytest.mark.parametrize("spec,expected", [
    ("app-db-user", ("app-db-user", "Password")),
    ("app-db-user#HOST", ("app-db-user", "HOST")),
    (" app-db-user # User Name ", ("app-db-user", "User Name")),
    ("app#field#with#hash", ("app", "field#with#hash")),
])
def test_parse_secret_ref(spec, expected):
    assert runner.parse_secret_ref(spec) == expected


@pytest.mark.parametrize("spec", ["", "#Password", "app#", "  #  "])
def test_parse_secret_ref_invalid(spec):
    with pytest.raises(ValueError):
        runner.parse_secret_ref(spec)


def test_resolve(transport):
    values, masked = runner.resolve(KeePassAccess(transport), {"P": "app-db-user", "H": "app-db-user#HOST",
                                                               "N": "app-db-user#notes"})
    assert values == {"P": PASSWORD, "H": "db.example.org", "N": "first line\nsecond secret line"}
    assert masked == {"P", "N"}  # notes: case-insensitive match of the protected field Notes
    assert transport.requests == ["FIND app-db-user\n"]


def test_resolve_old_plugin_masks_all(transport):
    _, masked = runner.resolve(KeePassAccess(transport), {"P": "old-plugin", "H": "old-plugin#HOST"})
    assert masked == {"P", "H"}


@pytest.mark.skipif(sys.platform != "win32", reason="Windows shells")
def test_run_masks_only_given_names():
    result = runner.run("Write-Output \"$env:H $env:P\"", {"P": PASSWORD, "H": "db.example.org"}, "powershell",
                        masked={"P"})
    assert result.stdout.strip() == "db.example.org ***P***"


def test_protected_fields_api(transport):
    kp = KeePassAccess(transport)
    assert kp.protected_fields("app-db-user") == {"Password", "Notes"}
    assert kp.protected_fields("old-plugin") is None
    assert kp.password("old-plugin") == PASSWORD  # values unchanged with either plugin


@pytest.mark.parametrize("secrets,error", [
    ({}, ValueError),
    ({"1BAD": "app-db-user"}, ValueError),
    ({"A-B": "app-db-user"}, ValueError),
    ({"P": "locked"}, Locked),
    ({"P": "missing"}, EntryNotFound),
    ({"P": "app-db-user#Nope"}, FieldNotFound),
])
def test_resolve_errors(transport, secrets, error):
    with pytest.raises(error):
        runner.resolve(KeePassAccess(transport), secrets)


def test_resolve_validates_all_names_before_reading(transport):
    with pytest.raises(ValueError):
        runner.resolve(KeePassAccess(transport), {"P": "app-db-user", "bad name": "app-db-user"})
    assert transport.requests == []


VALUES = {"P": PASSWORD, "SHORT": "ab", "NOTES": "first line\nsecond secret line"}


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le"] + (["oem", "mbcs"] if sys.platform == "win32" else []))
def test_mask_bytes_in_each_encoding(encoding):
    try:
        data = f"before {PASSWORD} after".encode(encoding)
    except UnicodeEncodeError:
        pytest.skip(f"value not representable in {encoding}")
    masked = runner.mask_bytes(data, VALUES)
    assert PASSWORD.encode(encoding) not in masked
    assert masked.decode(encoding) == "before ***P*** after"


def test_masked_output_utf8():
    text, cut = runner.masked_output(f"x {PASSWORD} y".encode("utf-8"), VALUES)
    assert text == "x ***P*** y" and not cut


def test_mask_multiline_value_line_by_line():
    out = "first line\r\nsecond secret line\r\n".encode("utf-8")
    text, _ = runner.masked_output(out, VALUES)
    assert "second secret line" not in text and "first line" not in text
    assert text.count("***NOTES***") == 2


def test_mask_short_values_too():
    text, _ = runner.masked_output(b"abc", VALUES)
    assert text == "***SHORT***c"


def test_mask_longest_first():
    text = runner.mask_text("secret-long", {"A": "secret", "B": "secret-long"})
    assert text == "***B***"


def test_output_is_cut():
    text, cut = runner.masked_output(b"x" * (runner.MAX_OUTPUT_CHARS + 10), {"P": "zzzz"})
    assert cut and len(text) == runner.MAX_OUTPUT_CHARS


@windows
@pytest.mark.parametrize("shell,command", [
    ("powershell", "Write-Output \"pw=$env:P len=$($env:P.Length)\"; exit 3"),
    ("cmd", "echo pw=%P% & exit /b 3"),
])
def test_run_masks_and_propagates_exit_code(shell, command):
    result = runner.run(command, {"P": PASSWORD}, shell)
    assert result.exit_code == 3
    assert PASSWORD not in result.stdout
    assert "pw=***P***" in result.stdout
    if shell == "powershell":
        assert f"len={len(PASSWORD)}" in result.stdout


@windows
def test_run_bash():
    try:
        runner.shell_argv("bash", "true")
    except ValueError:
        pytest.skip("Git Bash not installed")
    result = runner.run('echo "pw=$P" >&2; exit 4', {"P": PASSWORD}, "bash")
    assert result.exit_code == 4
    assert "pw=***P***" in result.stderr and PASSWORD not in result.stderr


@windows
def test_run_cwd(tmp_path):
    result = runner.run("(Get-Location).Path", {"P": "zzzz"}, "powershell", str(tmp_path))
    assert os.path.samefile(result.stdout.strip(), tmp_path)


def test_run_bad_cwd():
    with pytest.raises(ValueError, match="does not exist"):
        runner.run("echo", {"P": "x"}, "cmd", r"C:\does\not\exist\anywhere")


def test_unknown_shell():
    with pytest.raises(ValueError, match="unknown shell"):
        runner.shell_argv("zsh", "true")


@windows
def test_run_timeout_kills_tree():
    start = time.monotonic()
    # the child ping keeps the pipes open: only killing the whole tree ends communicate()
    result = runner.run("echo $env:P; ping -n 30 127.0.0.1 | Out-Null", {"P": PASSWORD}, "powershell",
                        timeout_seconds=3)
    assert result.timed_out
    assert time.monotonic() - start < 20
    assert PASSWORD not in result.stdout
