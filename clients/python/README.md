# keepass-access (Python) and MCP server

Python client for the [KeePassAccess](https://github.com/jelinj8/Java-KeePassAccess) KeePass plugin, and an MCP
server (`keepass-access-mcp`) that lets Claude and other AI assistants use shared KeePass entries in commands
**without the values entering the conversation, the transcript or a shell history**. See the
[main README](../../README.md) for the plugin, the protocol and the security model.

## Library

```
pip install "keepass-access @ git+https://github.com/jelinj8/Java-KeePassAccess#subdirectory=clients/python"
```

```python
from keepass_access import KeePassAccess

kp = KeePassAccess.local()
password = kp.password("app-db-user")           # by name tag or UUID
host = kp.field("app-db-user", "HOST")          # custom field
```

## MCP server

The assistant only names references like `app-db-user#Password`. The server reads the values, starts the command
with them as environment variables and returns the output with the value of every protected field replaced by
`***NAME***`. Protected are the fields KeePass protects (Password by default, custom fields with *Enable in-memory
protection* on the entry's Advanced tab) and values that come from a reference (`{REF:...}`). Unprotected fields
(Title, UserName, URL, Notes, ...) are treated as not secret and shown. With a plugin older than 1.4, which does not
report protection, every value is masked and none is shown.

| Tool | Does | Permission |
|---|---|---|
| `keepass_status` | is KeePass running, how many databases are unlocked | allow |
| `list_entries` | UUID, title, user name (unless protected; tells apart entries with the same title) and name tags of the shared entries | allow |
| `list_fields` | fields of an entry: value of each unprotected field, `protected (set)` / `protected (empty)` for the others | allow |
| `run_with_secrets` | runs a command (`powershell`, `pwsh`, `cmd` or Git `bash`) with `{"VAR": "<ref>[#Field]"}` as environment variables; returns exit code and masked output | **ask** |

Example call:

```json
{"command": "psql -h $env:DB_HOST -U app -c 'select 1'",
 "secrets": {"PGPASSWORD": "app-db-user", "DB_HOST": "app-db-user#HOST"}}
```

### Setup for Claude Code

These steps can be followed by Claude itself ("install the MCP server from
https://github.com/jelinj8/Java-KeePassAccess/tree/main/clients/python"). Windows only.

1. **Prerequisites.** KeePass 2.x with the KeePassAccess plugin is running and a database is unlocked; at least one
   entry is shared (entry context menu *Allow External Access*). [uv](https://docs.astral.sh/uv/) is installed
   (`uv --version`). Python itself is provided by uv.

2. **Register the server** for all projects of the user:

   ```
   claude mcp add -s user keepass-access -- uvx --from "keepass-access[mcp] @ git+https://github.com/jelinj8/Java-KeePassAccess#subdirectory=clients/python" keepass-access-mcp
   ```

   From a local checkout instead: `claude mcp add -s user keepass-access -- uv run --directory <checkout>\clients\python --extra mcp keepass-access-mcp`.
   Other MCP clients (`.mcp.json`, Claude Desktop) take the same command and arguments.

3. **Permissions.** Merge these rules into `~/.claude/settings.json` (keep all existing settings and rules; add to
   the arrays, do not replace them):

   ```json
   {
     "permissions": {
       "allow": [
         "mcp__keepass-access__keepass_status",
         "mcp__keepass-access__list_entries",
         "mcp__keepass-access__list_fields"
       ],
       "ask": [
         "mcp__keepass-access__run_with_secrets"
       ]
     }
   }
   ```

   The three read-only tools never return a value, so they run without a prompt. `run_with_secrets` runs a command
   as the user, outside Claude Code's own Bash permission rules, so it must stay on *ask*: every command is shown
   with its secret references and approved before it runs. The explicit `ask` rule matters with
   `"defaultMode": "auto"` or `acceptEdits`, which would otherwise let it run without asking. Never put
   `run_with_secrets` into `allow`.

4. **Verify.** `claude mcp list` shows `keepass-access ... Connected`. Restart Claude Code (MCP tools are loaded at
   session start), then ask it to call `keepass_status` and `list_entries`.

5. **Updating.** `uvx` caches the installed version; run the command from step 2 once by hand with `--refresh`
   after `uvx` to fetch the newest one.

### Security notes

- No tool returns the value of a protected field. Masking covers the raw output in UTF-8, UTF-16 and the
  console/ANSI codepages, and multi-line values line by line.
- **Keep secrets in protected fields.** Notes and UserName are unprotected by default in KeePass and are shown to the
  assistant. Put secrets into Password or into a custom field with *Enable in-memory protection* turned on.
- Masking protects against accidental echo such as verbose logs or error dumps. It cannot stop a command written to
  transform a value (reverse, base64, ...) before printing it, and derived data such as the length is not masked;
  that is what the approval prompt is for.
- Values are passed only through the environment of that one process tree, never on a command line. Commands run
  non-interactively, so no shell history is written.
- KeePass serves only entries tagged `ExternalAccess`, only to the same Windows user, and only while a database is
  unlocked.
