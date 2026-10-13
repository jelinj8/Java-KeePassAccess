"""Runs a command with KeePass values in environment variables and masks the secret ones in its output.

The values never leave this process except into the child's environment. In the output returned to the caller,
every value of a protected field (Password, custom fields with in-memory protection, values from a reference) is
replaced by ``***NAME***``; with a plugin that does not report protection, every injected value is. Masking guards
against accidental echo (verbose logs, error dumps); it cannot stop a command that deliberately transforms and
prints a value.
"""

import codecs
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Collection, Dict, List, Mapping, Optional, Set, Tuple

from . import KeePassAccess
from ._protocol import PASSWORD

ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
BASH_ENV = "KEEPASS_MCP_BASH"
MAX_OUTPUT_CHARS = 20000
SHELLS = ("powershell", "pwsh", "cmd", "bash")

# PowerShell writes to a redirected stdout in the console (OEM) codepage by default; switch it to UTF-8.
_PS_PREFIX = ("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
              "$OutputEncoding = [System.Text.Encoding]::UTF8; ")


def parse_secret_ref(spec: str) -> Tuple[str, str]:
    """``ref`` or ``ref#Field`` (split at the first ``#``); no field means Password."""
    ref, sep, field = spec.partition("#")
    ref, field = ref.strip(), field.strip()
    if not ref:
        raise ValueError(f"empty entry reference in '{spec}'")
    if sep and not field:
        raise ValueError(f"empty field name in '{spec}'")
    return ref, field or PASSWORD


def matched_field(fields: Mapping[str, str], name: str) -> Optional[str]:
    """The field name KeePassAccess.field() matches: exact first, then case-insensitive."""
    if name in fields:
        return name
    return next((k for k in fields if k.lower() == name.lower()), None)


def is_masked(kp: KeePassAccess, ref: str, field: str) -> bool:
    """A field is masked if it is protected, or always if the plugin does not report protection."""
    protected = kp.protected_fields(ref)
    return protected is None or matched_field(kp.entry(ref), field) in protected


def resolve(kp: KeePassAccess, secrets: Mapping[str, str]) -> Tuple[Dict[str, str], Set[str]]:
    """(environment variable name -> value, names of the variables to mask). All references are checked before
    any value is used."""
    if not secrets:
        raise ValueError("no secrets given")
    parsed = {}
    for name, spec in secrets.items():
        if not ENV_NAME.match(name):
            raise ValueError(f"invalid environment variable name '{name}'")
        parsed[name] = parse_secret_ref(spec)
    values = {name: kp.field(ref, field) for name, (ref, field) in parsed.items()}
    masked = {name for name, (ref, field) in parsed.items() if is_masked(kp, ref, field)}
    return values, masked


def _encodings() -> List[str]:
    result = ["utf-8", "utf-16-le"]
    for enc in ("oem", "mbcs"):  # console and ANSI codepage, Windows only
        try:
            codecs.lookup(enc)
            result.append(enc)
        except LookupError:
            pass
    return result


def _patterns(values: Mapping[str, str]) -> List[Tuple[str, str]]:
    """(text, variable name), longest first; a multi-line value is also masked line by line."""
    result = []
    for name, value in values.items():
        if value:
            result.append((value, name))
        lines = value.splitlines()
        if len(lines) > 1:
            result.extend((line, name) for line in lines if len(line.strip()) >= 4)
    return sorted(result, key=lambda p: len(p[0]), reverse=True)


def mask_bytes(data: bytes, values: Mapping[str, str]) -> bytes:
    """Masks the values in every encoding the output might use, with the marker in the same encoding."""
    for text, name in _patterns(values):
        for enc in _encodings():
            try:
                raw, marker = text.encode(enc), f"***{name}***".encode(enc)
            except UnicodeEncodeError:
                continue
            data = data.replace(raw, marker)
    return data


def mask_text(text: str, values: Mapping[str, str]) -> str:
    for value, name in _patterns(values):
        text = text.replace(value, f"***{name}***")
    return text


def decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        return data.decode("oem")
    except (LookupError, UnicodeDecodeError):
        return data.decode("utf-8", errors="replace")


def masked_output(data: bytes, values: Mapping[str, str]) -> Tuple[str, bool]:
    """Masked, decoded output, cut to the last MAX_OUTPUT_CHARS; second item tells whether it was cut."""
    text = mask_text(decode(mask_bytes(data, values)), values)
    if len(text) > MAX_OUTPUT_CHARS:
        return text[-MAX_OUTPUT_CHARS:], True
    return text, False


def _git_bash() -> str:
    configured = os.environ.get(BASH_ENV)
    if configured:
        return configured
    for candidate in (r"C:\Program Files\Git\bin\bash.exe", shutil.which("bash")):
        # System32\bash.exe is WSL: another machine, it would not get the variables
        if candidate and os.path.isfile(candidate) and "system32" not in candidate.lower():
            return candidate
    raise ValueError(f"Git Bash not found; set {BASH_ENV} to bash.exe")


def shell_argv(shell: str, command: str) -> List[str]:
    """Non-interactive invocation, so no shell history is written."""
    if shell == "powershell":
        return ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _PS_PREFIX + command]
    if shell == "pwsh":
        return ["pwsh", "-NoProfile", "-NonInteractive", "-Command", _PS_PREFIX + command]
    if shell == "cmd":
        return ["cmd.exe", "/d", "/s", "/c", command]
    if shell == "bash":
        return [_git_bash(), "-c", command]
    raise ValueError(f"unknown shell '{shell}', expected one of {', '.join(SHELLS)}")


@dataclass
class RunResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False


def run(command: str, values: Mapping[str, str], shell: str = "powershell", cwd: str = None,
        timeout_seconds: float = 120, masked: Optional[Collection[str]] = None) -> RunResult:
    """masked: names of the variables whose values are masked in the output; None masks all."""
    argv = shell_argv(shell, command)
    if cwd and not os.path.isdir(cwd):
        raise ValueError(f"working directory does not exist: {cwd}")
    env = dict(os.environ)
    env.update(values)
    proc = subprocess.Popen(argv, cwd=cwd or None, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        # the shell's children keep the pipes open: kill the whole tree
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        try:
            out, err = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = b"", b""
    secret = dict(values) if masked is None else {n: values[n] for n in masked}
    stdout, cut_out = masked_output(out, secret)
    stderr, cut_err = masked_output(err, secret)
    return RunResult(proc.returncode, stdout, stderr, timed_out, cut_out or cut_err)
