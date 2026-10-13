"""Reads entries from a running, unlocked KeePass 2.x with the KeePassAccess plugin.

Only entries tagged ExternalAccess are served. An entry is referenced by its UUID or by a name: another tag of the
entry, unique among the shared entries. Entries are cached per instance, so repeated lookups cost one request.

    from keepass_access import KeePassAccess
    kp = KeePassAccess.local()
    password = kp.password("app-db-user")
    host = kp.field("3F2504E04F8911D39A0C0305E82C3301", "HOST")

Not thread-safe. Values are never logged or put into exception messages.
"""

from typing import Dict, List, Optional, Set, Tuple

from . import _protocol as protocol
from ._pipe import PipeTransport
from ._protocol import EntryInfo
from .errors import (AccessDenied, Ambiguous, EntryNotFound, FieldNotFound, KeePassAccessError, Locked,
                     NotRunning)

__all__ = ["KeePassAccess", "EntryInfo", "PipeTransport", "KeePassAccessError", "NotRunning", "Locked",
           "EntryNotFound", "AccessDenied", "Ambiguous", "FieldNotFound"]


class KeePassAccess:
    def __init__(self, transport):
        """transport: object with exchange(request: str) -> list of response lines (see PipeTransport)."""
        self._transport = transport
        self._cache: Dict[str, Tuple[Dict[str, str], Optional[Set[str]]]] = {}

    @classmethod
    def local(cls) -> "KeePassAccess":
        """KeePass of the current Windows user."""
        return cls(PipeTransport.local())

    def ping(self) -> int:
        """Number of unlocked databases (0 = KeePass runs but everything is locked)."""
        return protocol.parse_ping(self._transport.exchange(protocol.ping_request()))

    def list(self) -> List[EntryInfo]:
        """Shared entries (UUID, title, name tags), no values."""
        return protocol.parse_list(self._transport.exchange(protocol.list_request()))

    def entry(self, ref: str) -> Dict[str, str]:
        """All string fields of an entry (Title, UserName, Password, URL, Notes, custom fields).

        ref: entry UUID (32 hex digits, dashes and braces allowed) or name tag.
        """
        return dict(self._load(ref)[0])

    def protected_fields(self, ref: str) -> Optional[Set[str]]:
        """Names of the entry's protected fields: fields KeePass protects (Password by default, custom fields with
        in-memory protection) or whose value comes from a reference. entry() and field() return all values as
        usual; this only tells which ones are secret. None if the plugin does not report protection (before 1.4).
        """
        names = self._load(ref)[1]
        return None if names is None else set(names)

    def _load(self, ref: str) -> Tuple[Dict[str, str], Optional[Set[str]]]:
        by_uuid = protocol.is_uuid(ref)
        key = protocol.normalize_uuid(ref) if by_uuid else "name:" + protocol.normalize_name(ref).lower()
        e = self._cache.get(key)
        if e is None:
            request = protocol.get_request(ref) if by_uuid else protocol.find_request(ref)
            lines = self._transport.exchange(request)
            e = (protocol.parse_get(lines), protocol.parse_protected(lines))
            self._cache[key] = e
        return e

    def field(self, ref: str, name: str) -> str:
        """One field; the name is matched exactly first, then case-insensitively."""
        e = self.entry(ref)
        if name in e:
            return e[name]
        for k, v in e.items():
            if k.lower() == name.lower():
                return v
        raise FieldNotFound(f"entry {ref.strip()} has no field '{name}'")

    def password(self, ref: str) -> str:
        return self.field(ref, protocol.PASSWORD)
