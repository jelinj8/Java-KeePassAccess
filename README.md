# KeePassAccess

Lets local programs read selected entries from a **running, unlocked KeePass 2.x** (Windows) by entry UUID or
by a name tag, so passwords do not have to live in files.

Author: Jakub Jelínek

- `plugin/`: KeePass plugin `KeePassAccess.dll` (C# 5, .NET Framework 4). It serves a named pipe.
- `java/`: client library `cz.bliksoft.java:keepass-access` (Java 11+, no dependencies) with a small diagnostic CLI.
- `clients/powershell/`: `KeePassAccess.ps1` for scripts (Windows PowerShell 5.1+, PowerShell 7).
- `clients/python/`: Python package `keepass-access` (3.10+, no dependencies) and an MCP server that lets Claude
  and other AI assistants use shared entries in commands without seeing the values.

Clients for other languages only need to speak the line protocol below over the named pipe.

Downloads: the plugin DLL, the client jar, the PowerShell script and the Python wheel are attached to each
[GitHub release](https://github.com/jelinj8/Java-KeePassAccess/releases).

## Security model

- Only entries tagged **`ExternalAccess`** are served (tag set in the entry's Properties, case-insensitive). Any
  other entry gets `DENIED`, entries in the recycle bin are `NOT_FOUND`.
- The pipe `\\.\pipe\KeePassAccess-<Windows user>` grants access to the **current Windows user only**. A
  program running as you can read your tagged entries, the same as it could read a password file of yours, but
  nothing else and nobody else.
- **Names:** besides `ExternalAccess`, an entry's other tags are its names. A program can ask for "the shared entry
  tagged `app-db-user`" instead of a UUID, so one configuration works with different databases, e.g. a team
  where everyone has their own entry with the same name tag. A name must be on exactly one shared entry over all
  unlocked databases (`AMBIGUOUS` otherwise). Entries with the name tag but without `ExternalAccess` are ignored.
- Locked databases are never read: with no unlocked database every request answers `LOCKED`.
- Placeholders in field values are resolved with field references only (`{REF:...}`), never commands.
- The Java library never logs values or puts them into exception messages.

## Install the plugin

Download `KeePassAccess.dll` from the latest release, or build it:

```
plugin\build.bat                     (KEEPASS_DIR defaults to C:\Program Files\KeePass Password Safe 2)
copy plugin\out\KeePassAccess.dll "C:\Program Files\KeePass Password Safe 2\Plugins\"   (as administrator)
```

Restart KeePass. Tools > Plugins should list *KeePassAccess*. Then share entries: select them and use
**Allow External Access** in the entry context menu. It sets the tag `ExternalAccess` (or removes it when all
selected entries have it) and marks the database as modified, so save it. Typing the tag in the entry's
Properties works as well; KeePass only suggests tags that some entry of the database already has, which is why
the menu item exists. The entry UUID is shown in the entry dialog under Properties.

## Protocol

One request line per connection; the response is a list of lines ending with an empty line.

| Request | Response |
|---|---|
| `PING` | `OK <number of unlocked databases>` |
| `LIST` | `OK`, then `<uuid hex>\t<base64 title>\t<base64 name tags, comma separated>` per tagged entry (no secret values) |
| `GET <uuid>` | `OK`, then `<base64 field name>\t<base64 value>` per string field (Title, UserName, Password, URL, Notes, custom fields) |
| `FIND <name>` | like `GET`, for the one shared entry that also has the tag `<name>` (case-insensitive); plugin 1.2+ |
| error | `ERR LOCKED\|NOT_FOUND\|DENIED\|AMBIGUOUS\|BAD_REQUEST <message>` |

The UUID is 32 hex digits; dashes, braces and spaces are ignored. Base64 is applied to UTF-8.

## Java

```xml
<dependency>
  <groupId>cz.bliksoft.java</groupId>
  <artifactId>keepass-access</artifactId>
  <version>1.2.0</version>
</dependency>
```

```java
KeePassAccess kp = KeePassAccess.local();                 // pipe of the current user
String pwd = kp.password("3F2504E04F8911D39A0C0305E82C3301");
String host = kp.field("3F2504E04F8911D39A0C0305E82C3301", "HOST");   // custom string field
Map<String, String> all = kp.entry("3F2504E0-4F89-11D3-9A0C-0305E82C3301");
String pwd2 = kp.password("app-db-user");                // by name tag (anything that is not 32 hex digits)
```

Errors are `KeePassAccessException` (an `IOException`). Its nested subclasses are `NotRunning`, `Locked`,
`EntryNotFound`, `AccessDenied`, `Ambiguous` and `FieldNotFound`. Entries are cached per `KeePassAccess` instance. The pipe
name can be overridden with the system property `keepassaccess.pipe` or the environment variable
`KEEPASS_ACCESS_PIPE`.

Diagnostics, without printing any secret:

```
java -jar keepass-access-1.2.0.jar ping           unlocked database count
java -jar keepass-access-1.2.0.jar list           UUID, title and name tags of the shared entries
java -jar keepass-access-1.2.0.jar fields <ref>   field names of an entry (UUID or name)
```

Build: `cd java && mvn clean install`.

## PowerShell

`clients/powershell/KeePassAccess.ps1` talks to the pipe directly, without Java. Dot-source it and read values into
variables:

```powershell
. .\KeePassAccess.ps1
$dbPassword = Get-KeePassField app-db-user                # by name tag, Password field
$dbHost     = Get-KeePassField app-db-user HOST           # any field
$entry      = Get-KeePassEntry 3F2504E04F8911D39A0C0305E82C3301   # all fields, ordered dictionary
Invoke-KeePassAccess PING                                 # raw request, returns the response lines
```

Errors are thrown as exceptions (`KeePassAccess: LOCKED ...`), so a script stops instead of continuing with an empty
value. Field names are matched like in Java: exactly first, then case-insensitively. `KEEPASS_ACCESS_PIPE` overrides
the pipe name. From another shell, e.g. Git Bash:

```bash
DB_PASSWORD=$(powershell -NoProfile -Command '. ./KeePassAccess.ps1; Get-KeePassField app-db-user')
```

The value then lives in the shell variable; avoid echoing it or passing it on a command line of another program,
where other processes can see it, and prefer environment variables or stdin.

## Python

```
pip install "keepass-access @ git+https://github.com/jelinj8/Java-KeePassAccess#subdirectory=clients/python"
```

```python
from keepass_access import KeePassAccess

kp = KeePassAccess.local()
password = kp.password("app-db-user")           # by name tag or UUID
host = kp.field("app-db-user", "HOST")          # custom field
```

Same API and errors as the Java client (`KeePassAccessError`, an `OSError`, with `NotRunning`, `Locked`,
`EntryNotFound`, `AccessDenied`, `Ambiguous`, `FieldNotFound`); `KEEPASS_ACCESS_PIPE` overrides the pipe name.

## Claude (MCP server)

`keepass-access-mcp` lets an AI assistant use shared entries in commands **without the values entering the
conversation, the transcript or a shell history**. The assistant only names references; the server reads the
values, starts the command with them in environment variables and returns the output with every injected value
replaced by `***NAME***`.

Register it for Claude Code (all projects of the user; needs [uv](https://docs.astral.sh/uv/)):

```
claude mcp add -s user keepass-access -- uvx --from "keepass-access[mcp] @ git+https://github.com/jelinj8/Java-KeePassAccess#subdirectory=clients/python" keepass-access-mcp
```

or from a checkout: `claude mcp add -s user keepass-access -- uv run --directory <checkout>\clients\python --extra mcp keepass-access-mcp`.
Other MCP clients (`.mcp.json`, Claude Desktop) take the same command and arguments.

| Tool | Does |
|---|---|
| `keepass_status` | is KeePass running, how many databases are unlocked |
| `list_entries` | UUID, title and name tags of the shared entries |
| `list_fields` | field names of an entry, each marked `set` or `empty` |
| `run_with_secrets` | runs a command (`powershell`, `pwsh`, `cmd` or Git `bash`) with `{"VAR": "<ref>[#Field]"}` injected as environment variables; returns exit code and masked stdout/stderr |

Example call by the assistant:

```json
{"command": "psql -h $env:DB_HOST -U app -c 'select 1'",
 "secrets": {"PGPASSWORD": "app-db-user", "DB_HOST": "app-db-user#HOST"}}
```

Security notes:

- No tool returns a value. Masking covers the raw output in UTF-8, UTF-16 and the console/ANSI codepages, multi-line
  values line by line, and every injected value (also non-secret ones like a host name). It protects against
  accidental echo such as verbose logs; it cannot stop a command written to transform a value (e.g. reverse or
  base64 it) before printing, and derived data like the length is not masked.
- `run_with_secrets` runs as the user, outside Claude Code's own Bash permissions. Allow the three read-only tools,
  but keep `run_with_secrets` on *ask*, so each command and its secret references are approved before they run.
- Commands run non-interactively, so no shell history is written. Values are passed only through the environment of
  that one process tree, never on a command line.

## License

[GNU Lesser General Public License v2.1](LICENSE).
