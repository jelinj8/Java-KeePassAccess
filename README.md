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

Requires KeePass 2.41 or newer. Download `KeePassAccess.dll` from the latest release (built against KeePass 2.41,
so it loads in every newer version), or build it. A DLL built locally references the KeePass it was compiled
against and loads only there and in newer versions, never in an older KeePass:

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
| `GET <uuid>` | `OK protected=<base64 name>,...` (plugin 1.4+; older plugins send `OK`), then `<base64 field name>\t<base64 value>` per string field (Title, UserName, Password, URL, Notes, custom fields) |
| `FIND <name>` | like `GET`, for the one shared entry that also has the tag `<name>` (case-insensitive); plugin 1.2+ |
| error | `ERR LOCKED\|NOT_FOUND\|DENIED\|AMBIGUOUS\|BAD_REQUEST <message>` |

The UUID is 32 hex digits; dashes, braces and spaces are ignored. Base64 is applied to UTF-8.

`protected=` lists the secret fields: those KeePass protects (Password by default, custom fields with *Enable
in-memory protection* on the Advanced tab) and those whose value comes from a reference (`{REF:...}`). Clients
ignore the text after `OK`, so all values are returned as before; the MCP server uses the list to decide what to mask.

## Java

```xml
<dependency>
  <groupId>cz.bliksoft.java</groupId>
  <artifactId>keepass-access</artifactId>
  <version>1.3.0</version>
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
java -jar keepass-access-1.3.0.jar ping           unlocked database count
java -jar keepass-access-1.3.0.jar list           UUID, title and name tags of the shared entries
java -jar keepass-access-1.3.0.jar fields <ref>   field names of an entry (UUID or name)
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

`keepass-access-mcp` lets Claude and other AI assistants use shared entries in commands **without the secret
values entering the conversation, the transcript or a shell history**: the assistant names references
(`app-db-user#Password`), the server runs the command with the values in environment variables and returns the
output with the values of protected fields masked as `***NAME***`. Read-only tools list entries and fields;
unprotected values (URL, UserName, ...) are shown, protected ones never.

Setup, tools, permission rules and security notes: [clients/python/README.md](clients/python/README.md). The setup
steps are written so Claude can follow them: point it to
`https://github.com/jelinj8/Java-KeePassAccess/tree/main/clients/python` and ask it to install and configure the
MCP server. In short:

```
claude mcp add -s user keepass-access -- uvx --from "keepass-access[mcp] @ git+https://github.com/jelinj8/Java-KeePassAccess#subdirectory=clients/python" keepass-access-mcp
```

plus, in `~/.claude/settings.json`, `allow` for `mcp__keepass-access__keepass_status`, `..._list_entries` and
`..._list_fields`, and `ask` for `mcp__keepass-access__run_with_secrets` (it runs commands as you; keep approving
each one).

## License

[GNU Lesser General Public License v2.1](LICENSE).
