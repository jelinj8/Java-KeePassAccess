"""MCP server (stdio): lets an AI assistant use shared KeePass entries without seeing their secret values.

Protected fields (Password, custom fields with in-memory protection, values from a reference) are never returned;
unprotected ones (Title, UserName, URL, Notes, ...) are. run_with_secrets starts a command with values in
environment variables and returns its output with the protected values masked.

    claude mcp add -s user keepass-access -- keepass-access-mcp
"""

from importlib import metadata
import json
from typing import Callable, Dict, Optional

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from . import KeePassAccess, runner
from .errors import Locked, NotRunning

INSTRUCTIONS = """\
Access to passwords and other fields of KeePass entries that the user shared (tag ExternalAccess) in their
running KeePass. Values of protected fields (Password, fields the user protected in KeePass, values from a
reference) are never returned to you, by design: do not try to obtain, print, transform or store them. Unprotected
fields (Title, UserName, URL, Notes, ...) are not secret; list_fields shows their values.
To use a value, call run_with_secrets with the command and a mapping of environment variable names to entry
references; the command reads the variables ($env:NAME in PowerShell, %NAME% in cmd, $NAME in bash). Values of
protected fields are masked as ***NAME*** in the returned output. Entry references are an entry UUID (32 hex
digits) or a name tag of the entry, optionally followed by #FieldName (default Password). Use list_entries and
list_fields to find references. Never put a protected value into a file, a command line argument visible to other
processes, or a log, unless the user asked for exactly that."""

READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)

try:
    _VERSION = metadata.version("keepass-access")
except metadata.PackageNotFoundError:
    _VERSION = ""

server = MCPServer("keepass-access", instructions=INSTRUCTIONS, version=_VERSION)

# replaced in tests
connect: Callable[[], KeePassAccess] = KeePassAccess.local


@server.tool(annotations=READ_ONLY)
def keepass_status() -> str:
    """Whether KeePass with the KeePassAccess plugin is running and how many databases are unlocked."""
    try:
        n = connect().ping()
    except NotRunning:
        return "KeePass with the KeePassAccess plugin is not running for this user."
    if n == 0:
        return "KeePass is running, but all databases are locked; ask the user to unlock one."
    return f"KeePass is running with {n} unlocked database(s)."


@server.tool(annotations=READ_ONLY)
def list_entries() -> str:
    """Shared entries: UUID, title and name tags (usable as references). No values."""
    entries = connect().list()
    if not entries:
        return "No shared entries. The user shares an entry with 'Allow External Access' in KeePass."
    lines = ["uuid\ttitle\tnames"]
    lines += [f"{e.uuid}\t{e.title}\t{', '.join(e.names)}" for e in entries]
    return "\n".join(lines)


@server.tool(annotations=READ_ONLY)
def list_fields(ref: str) -> str:
    """Fields of a shared entry (Title, UserName, Password, URL, Notes, custom fields): the value of each
    unprotected field (as a JSON string), "protected (set)" or "protected (empty)" for protected ones.

    ref: entry UUID (32 hex digits) or name tag.
    """
    kp = connect()
    fields = kp.entry(ref)
    protected = kp.protected_fields(ref)
    if protected is None:
        lines = [f"{name}\t{'empty' if not value else 'set'}" for name, value in fields.items()]
        lines.append("(the KeePassAccess plugin is older than 1.4 and does not report protected fields, so no "
                     "values are shown and run_with_secrets masks every value; ask the user to update the plugin)")
        return "\n".join(lines)
    return "\n".join(f"{name}\tprotected ({'set' if value else 'empty'})" if name in protected
                     else f"{name}\t{json.dumps(value, ensure_ascii=False)}" for name, value in fields.items())


@server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=True))
def run_with_secrets(command: str, secrets: Dict[str, str], shell: str = "powershell", cwd: Optional[str] = None,
                     timeout_seconds: int = 120) -> str:
    """Runs a command with KeePass values in environment variables; returns exit code and output, with the values
    of protected fields masked.

    command: script text for the shell; read values from the variables, never inline them.
    secrets: environment variable name -> entry reference: "<uuid or name tag>" (Password) or
        "<uuid or name tag>#<FieldName>", e.g. {"PGPASSWORD": "app-db-user", "DB_HOST": "app-db-user#HOST"}.
    shell: powershell (default), pwsh, cmd or bash (Git Bash).
    cwd: working directory (absolute path); default is the server's working directory.
    timeout_seconds: the process tree is killed after this time.
    """
    try:
        values, masked = runner.resolve(connect(), secrets)
    except Locked:
        return "Not run: all KeePass databases are locked; ask the user to unlock one."
    except NotRunning:
        return "Not run: KeePass with the KeePassAccess plugin is not running for this user."
    result = runner.run(command, values, shell, cwd, timeout_seconds, masked)
    visible = sorted(set(values) - masked)
    parts = [f"exit code: {result.exit_code}" + (" (killed after timeout)" if result.timed_out else ""),
             "masked in output (protected): " + (", ".join(sorted(masked)) or "none")]
    if visible:
        parts.append("not masked (unprotected): " + ", ".join(visible))
    if result.truncated:
        parts.append(f"output cut to the last {runner.MAX_OUTPUT_CHARS} characters per stream")
    if result.stdout:
        parts.append("--- stdout ---\n" + result.stdout.rstrip())
    if result.stderr:
        parts.append("--- stderr ---\n" + result.stderr.rstrip())
    return "\n".join(parts)


def main():
    server.run()


if __name__ == "__main__":
    main()
