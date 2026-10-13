"""Wire format of the KeePassAccess plugin, see README.md (same rules as java/.../Protocol.java).

A request is one line; a response is a sequence of lines ending with an empty line. The first line is
``OK[ <info>]`` or ``ERR <code> <message>``; for LIST and GET/FIND the following lines are tab separated,
base64 (UTF-8) except the entry UUID.
"""

import base64
import binascii
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .errors import AccessDenied, Ambiguous, EntryNotFound, KeePassAccessError, Locked

ACCESS_TAG = "ExternalAccess"

TITLE = "Title"
USER_NAME = "UserName"
PASSWORD = "Password"
URL = "URL"
NOTES = "Notes"

_HEX = set("0123456789abcdefABCDEF")


@dataclass(frozen=True)
class EntryInfo:
    """A shared entry as listed by LIST: no field values."""

    uuid: str
    title: str
    names: List[str] = field(default_factory=list)


def normalize_uuid(uuid: str) -> str:
    """32 lower-case hex digits; dashes, braces and spaces are ignored."""
    s = "".join(c for c in (uuid or "") if c not in "-{} ")
    if len(s) != 32 or not set(s) <= _HEX:
        raise ValueError(f"invalid entry UUID '{uuid}': expected 32 hex digits")
    return s.lower()


def is_uuid(ref: str) -> bool:
    """True for 32 hex digits: a reference is then a UUID, else a name tag."""
    try:
        normalize_uuid(ref)
        return True
    except ValueError:
        return False


def normalize_name(name: str) -> str:
    """A name tag: trimmed, not empty, one line, not the access tag itself."""
    n = (name or "").strip()
    if not n or "\n" in n or "\r" in n or n.lower() == ACCESS_TAG.lower():
        raise ValueError(f"invalid entry name tag '{name}'")
    return n


def ping_request() -> str:
    return "PING\n"


def list_request() -> str:
    return "LIST\n"


def get_request(uuid: str) -> str:
    return "GET " + normalize_uuid(uuid).upper() + "\n"


def find_request(name: str) -> str:
    return "FIND " + normalize_name(name) + "\n"


def parse_ping(lines: List[str]) -> int:
    """Number of unlocked databases."""
    info = _ok(lines)
    try:
        return int(info.strip())
    except ValueError:
        raise KeePassAccessError("unexpected PING response") from None


def parse_list(lines: List[str]) -> List[EntryInfo]:
    _ok(lines)
    result = []
    for uuid, rest in _pairs(lines):
        # <uuid>\t<title>[\t<name tags, comma separated>] (plugin 1.2+ sends the tags)
        title, sep, tags = rest.partition("\t")
        names = [t.strip() for t in _decode(tags).split(",") if t.strip()] if sep else []
        result.append(EntryInfo(normalize_uuid(uuid), _decode(title), names))
    return result


def parse_get(lines: List[str]) -> Dict[str, str]:
    """Field name to value, in KeePass order."""
    _ok(lines)
    return {_decode(k): _decode(v) for k, v in _pairs(lines)}


def parse_protected(lines: List[str]) -> Optional[Set[str]]:
    """Names of the protected fields of a GET/FIND response (KeePass-protected, or the value comes from a
    reference); plugin 1.4+ sends them as ``OK protected=<b64>,<b64>``. None if the plugin does not report them."""
    for attr in _ok(lines).split(" "):
        if attr.startswith("protected="):
            return {_decode(n) for n in attr[len("protected="):].split(",") if n}
    return None


_ERRORS = {"LOCKED": Locked, "NOT_FOUND": EntryNotFound, "DENIED": AccessDenied, "AMBIGUOUS": Ambiguous}


def _ok(lines: List[str]) -> str:
    """Checks the status line; returns the text after OK."""
    if not lines:
        raise KeePassAccessError("empty response from KeePass")
    first = lines[0]
    if first == "OK":
        return ""
    if first.startswith("OK "):
        return first[3:]
    if first.startswith("ERR "):
        code, sep, msg = first[4:].partition(" ")
        error = _ERRORS.get(code)
        if error:
            raise error("KeePass: " + (msg if sep else code))
        raise KeePassAccessError(f"KeePass: {code} {msg if sep else code}")
    raise KeePassAccessError("unexpected response from KeePass")


def _pairs(lines: List[str]):
    result = []
    for i, line in enumerate(lines[1:], start=2):
        if not line:
            break
        a, sep, b = line.partition("\t")
        if not sep:
            raise KeePassAccessError(f"malformed response line {i} from KeePass")
        result.append((a, b))
    return result


def _decode(b64: str) -> str:
    try:
        return base64.b64decode(b64, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        raise KeePassAccessError("malformed base64 in response from KeePass") from None
