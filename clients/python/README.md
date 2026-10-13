# keepass-access (Python)

Python client for the [KeePassAccess](https://github.com/jelinj8/Java-KeePassAccess) KeePass plugin, and an MCP
server (`keepass-access-mcp`, extra `[mcp]`) that lets AI assistants such as Claude use shared entries in commands
without the values entering the conversation. See the main README for setup, the protocol and the security model.

```python
from keepass_access import KeePassAccess

kp = KeePassAccess.local()
password = kp.password("app-db-user")           # by name tag
host = kp.field("app-db-user", "HOST")          # custom field
```
