import base64

import pytest

UUID = "3F2504E04F8911D39A0C0305E82C3301"
PASSWORD = "p@ss wörd č"  # non-ASCII on purpose


def b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def entry_response(fields):
    return "OK\n" + "".join(f"{b64(k)}\t{b64(v)}\n" for k, v in fields.items()) + "\n"


ENTRY = {"Title": "DB", "UserName": "app", "Password": PASSWORD, "HOST": "db.example.org",
         "host": "lower", "Notes": "first line\nsecond secret line"}


class FakeTransport:
    """Answers like the plugin from a table request -> response text; records the requests."""

    def __init__(self, replies=None):
        self.requests = []
        self.replies = {
            "PING\n": "OK 1\n\n",
            "LIST\n": f"OK\n{UUID}\t{b64('DB')}\t{b64('app-db-user,team')}\n"
                      f"{'0' * 32}\t{b64('Old')}\n\n",
            f"GET {UUID}\n": entry_response(ENTRY),
            "FIND app-db-user\n": entry_response(ENTRY),
            "FIND locked\n": "ERR LOCKED all databases are locked\n\n",
            "FIND twice\n": "ERR AMBIGUOUS name twice is on 2 entries\n\n",
            "FIND private\n": "ERR DENIED not shared\n\n",
        }
        self.replies.update(replies or {})

    def exchange(self, request):
        self.requests.append(request)
        return self.replies.get(request, "ERR NOT_FOUND no entry\n\n").split("\n")


@pytest.fixture
def transport():
    return FakeTransport()
