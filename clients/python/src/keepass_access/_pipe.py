"""Windows named pipe \\\\.\\pipe\\KeePassAccess-<user> served by the plugin, one connection per request."""

import errno
import getpass
import os
import time
from typing import List

from .errors import KeePassAccessError, NotRunning

PIPE_ENV = "KEEPASS_ACCESS_PIPE"

_ERROR_PIPE_BUSY = 231


class PipeTransport:
    """The pipe accepts only the Windows user that runs KeePass."""

    def __init__(self, pipe_name: str, wait_seconds: float = 3.0):
        self.pipe_name = pipe_name
        self.wait_seconds = wait_seconds

    @classmethod
    def local(cls) -> "PipeTransport":
        """The pipe of the current user (same name the plugin uses), unless overridden by KEEPASS_ACCESS_PIPE."""
        name = os.environ.get(PIPE_ENV, "").strip() or "KeePassAccess-" + getpass.getuser()
        return cls(name)

    def exchange(self, request: str) -> List[str]:
        with self._open() as pipe:
            pipe.write(request.encode("utf-8"))
            buf = bytearray()
            while True:
                try:
                    chunk = pipe.read(4096)
                except OSError:
                    chunk = b""  # Windows reports the server's disconnect as an error
                if not chunk:
                    break
                buf += chunk
        if not buf.endswith(b"\n\n"):
            raise KeePassAccessError(f"incomplete response from KeePass on pipe {self.pipe_name}")
        return buf.decode("utf-8").split("\n")

    def _open(self):
        """The plugin serves one client at a time; between two clients the pipe briefly does not exist or is
        busy, so opening is retried for a short while before KeePass is considered not running."""
        path = "\\\\.\\pipe\\" + self.pipe_name
        deadline = time.monotonic() + self.wait_seconds
        while True:
            try:
                return open(path, "r+b", buffering=0)
            except OSError as e:
                # open() reports a busy pipe as EINVAL without winerror
                retry = (isinstance(e, FileNotFoundError) or e.errno == errno.EINVAL
                         or getattr(e, "winerror", None) == _ERROR_PIPE_BUSY)
                if not retry:
                    raise KeePassAccessError(f"cannot open pipe {self.pipe_name}: {e.strerror}") from e
                if time.monotonic() >= deadline:
                    raise NotRunning(
                        "KeePass with the KeePassAccess plugin is not running for this user "
                        f"(pipe {self.pipe_name} not available)"
                    ) from e
                time.sleep(0.05)
