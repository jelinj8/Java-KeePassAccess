# KeePassAccess

Lets local programs read selected entries from a **running, unlocked KeePass 2.x** (Windows) by entry UUID or
by a name tag, so passwords do not have to live in files.

Author: Jakub Jelínek

- `plugin/`: KeePass plugin `KeePassAccess.dll` (C# 5, .NET Framework 4). It serves a named pipe.
- `java/`: client library `cz.bliksoft.java:keepass-access` (Java 11+, no dependencies) with a small diagnostic CLI.

Clients for other languages only need to speak the line protocol below over the named pipe.

Downloads: the plugin DLL and the client jar are attached to each
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

## License

[GNU Lesser General Public License v2.1](LICENSE).
