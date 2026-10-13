"""Errors of KeePassAccess requests. Messages contain entry references and field names, never field values."""


class KeePassAccessError(OSError):
    """A request to KeePass failed."""


class NotRunning(KeePassAccessError):
    """No KeePass with the KeePassAccess plugin is running for this user (the pipe does not exist)."""


class Locked(KeePassAccessError):
    """KeePass runs, but no database is open and unlocked."""


class EntryNotFound(KeePassAccessError):
    """No such entry in the unlocked databases (or it is in the recycle bin)."""


class AccessDenied(KeePassAccessError):
    """The entry exists but is not tagged ExternalAccess."""


class Ambiguous(KeePassAccessError):
    """A name tag is on more than one shared entry."""


class FieldNotFound(KeePassAccessError):
    """The entry has no such field."""
