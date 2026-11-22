"""Minimal IMAP client on top of ``imaplib``.

* Read-only fetches use ``BODY.PEEK[]`` so triage never marks mail as read.
* Everything is addressed by UID (sequence numbers shift when mail is moved).
* Moves use ``UID MOVE`` (RFC 6851) when the server supports it, otherwise
  ``UID COPY`` + ``\\Deleted`` + ``UID EXPUNGE`` (RFC 4315), never a bare EXPUNGE
  that would also purge messages the user deleted themselves.
* The password comes from the caller (the CLI reads an environment variable) and is
  never stored or logged.
"""

from __future__ import annotations

import imaplib
import re
import ssl
from collections.abc import Iterator

_UIDVALIDITY = re.compile(rb"UIDVALIDITY (\d+)")
_SAFE_MAILBOX = re.compile(r"^[\w ./&+-]{1,100}$")


class ImapError(RuntimeError):
    pass


def quote_mailbox(name: str) -> str:
    if not _SAFE_MAILBOX.match(name):
        raise ValueError(f"unsupported mailbox name: {name!r}")
    return '"' + name + '"'


class ImapClient:
    def __init__(self, conn: imaplib.IMAP4) -> None:
        self.conn = conn
        self._caps: set[str] | None = None

    @classmethod
    def connect(cls, host: str, port: int, user: str, password: str, *, use_ssl: bool = True, timeout: float = 30):
        if use_ssl:
            conn: imaplib.IMAP4 = imaplib.IMAP4_SSL(
                host, port, ssl_context=ssl.create_default_context(), timeout=timeout
            )
        else:
            conn = imaplib.IMAP4(host, port, timeout=timeout)
        try:
            conn.login(user, password)
        except imaplib.IMAP4.error as exc:
            raise ImapError(f"login failed for {user!r}") from exc
        return cls(conn)

    def _ok(self, typ: str, data, what: str):
        if typ != "OK":
            raise ImapError(f"{what} failed: {data!r}")
        return data

    @property
    def capabilities(self) -> set[str]:
        if self._caps is None:
            typ, data = self.conn.capability()
            raw = b" ".join(d for d in self._ok(typ, data, "CAPABILITY") if d)
            self._caps = {c.upper() for c in raw.decode().split()}
        return self._caps

    def select(self, mailbox: str, *, readonly: bool) -> int:
        typ, data = self.conn.select(quote_mailbox(mailbox), readonly=readonly)
        self._ok(typ, data, f"SELECT {mailbox}")
        typ, data = self.conn.response("UIDVALIDITY")
        value = data[0] if data and data[0] else None
        if value is None:
            typ, data = self.conn.status(quote_mailbox(mailbox), "(UIDVALIDITY)")
            match = _UIDVALIDITY.search(b" ".join(d for d in data if isinstance(d, bytes)))
            if not match:
                raise ImapError(f"server did not report UIDVALIDITY for {mailbox}")
            value = match.group(1)
        return int(value)

    def uids_after(self, last_uid: int) -> list[int]:
        typ, data = self.conn.uid("SEARCH", None, f"UID {last_uid + 1}:*")
        found = [int(x) for x in b" ".join(self._ok(typ, data, "UID SEARCH")).split()]
        # "n:*" always matches the highest UID even when it is below n, so filter.
        return sorted(u for u in found if u > last_uid)

    def fetch(self, uids: list[int]) -> Iterator[tuple[int, bytes]]:
        for uid in uids:
            typ, data = self.conn.uid("FETCH", str(uid), "(BODY.PEEK[])")
            for part in self._ok(typ, data, f"FETCH {uid}"):
                if isinstance(part, tuple) and len(part) == 2:
                    yield uid, part[1]
                    break

    def ensure_mailbox(self, name: str) -> None:
        typ, data = self.conn.list('""', quote_mailbox(name))
        if typ == "OK" and data and data[0]:
            return
        self._ok(*self.conn.create(quote_mailbox(name)), what=f"CREATE {name}")

    def flag(self, uid: int, flag: str = "\\Flagged") -> None:
        if not re.fullmatch(r"\\?[A-Za-z$]+", flag):
            raise ValueError(f"unsupported flag: {flag!r}")
        self._ok(*self.conn.uid("STORE", str(uid), "+FLAGS", f"({flag})"), what=f"STORE {uid}")

    def move(self, uid: int, target: str) -> None:
        self.ensure_mailbox(target)
        caps = self.capabilities
        if "MOVE" in caps:
            self._ok(*self.conn.uid("MOVE", str(uid), quote_mailbox(target)), what=f"MOVE {uid}")
            return
        if "UIDPLUS" not in caps:
            raise ImapError("server supports neither MOVE nor UIDPLUS; refusing an unsafe EXPUNGE")
        self._ok(*self.conn.uid("COPY", str(uid), quote_mailbox(target)), what=f"COPY {uid}")
        self._ok(*self.conn.uid("STORE", str(uid), "+FLAGS", "(\\Deleted)"), what=f"STORE {uid}")
        self._ok(*self.conn.uid("EXPUNGE", str(uid)), what=f"UID EXPUNGE {uid}")

    def logout(self) -> None:
        try:
            self.conn.logout()
        except (imaplib.IMAP4.error, OSError):
            pass
