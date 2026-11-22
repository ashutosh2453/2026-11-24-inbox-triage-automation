"""In-memory stand-in for ``imaplib.IMAP4`` with the subset of behaviour triage uses."""

from __future__ import annotations


class FakeIMAP:
    def __init__(self, messages: list[bytes], caps: str = "IMAP4rev1 MOVE UIDPLUS", uidvalidity: int = 1):
        self.boxes: dict[str, dict[int, dict]] = {"INBOX": {}}
        self.next_uid = {"INBOX": 1}
        self.caps = caps
        self.uidvalidity = uidvalidity
        self.selected = None
        self.readonly = None
        self.log: list[tuple] = []
        for raw in messages:
            self.deliver(raw)

    def deliver(self, raw: bytes, box: str = "INBOX") -> int:
        uid = self.next_uid[box]
        self.boxes[box][uid] = {"raw": raw, "flags": set()}
        self.next_uid[box] += 1
        return uid

    @staticmethod
    def _unquote(name: str) -> str:
        return name.strip('"')

    def capability(self):
        return "OK", [self.caps.encode()]

    def select(self, mailbox, readonly=False):
        name = self._unquote(mailbox)
        if name not in self.boxes:
            return "NO", [b"no such mailbox"]
        self.selected, self.readonly = name, readonly
        return "OK", [str(len(self.boxes[name])).encode()]

    def response(self, code):
        return code, [str(self.uidvalidity).encode()]

    def list(self, directory, pattern):
        name = self._unquote(pattern)
        return "OK", ([f'(\\HasNoChildren) "/" "{name}"'.encode()] if name in self.boxes else [None])

    def create(self, mailbox):
        name = self._unquote(mailbox)
        self.boxes.setdefault(name, {})
        self.next_uid.setdefault(name, 1)
        self.log.append(("CREATE", name))
        return "OK", [b"created"]

    def uid(self, command, *args):
        box = self.boxes[self.selected]
        self.log.append((command, *args))
        if command == "SEARCH":
            start = int(args[1].split()[1].split(":")[0])
            found = [u for u in box if u >= start] or ([max(box)] if box else [])  # n:* quirk
            return "OK", [" ".join(map(str, found)).encode()]
        if command == "FETCH":
            uid = int(args[0])
            if uid not in box:
                return "OK", [None]
            return "OK", [(f"{uid} (UID {uid} BODY[] {{n}}".encode(), box[uid]["raw"]), b")"]
        if self.readonly:
            return "NO", [b"mailbox is read-only"]
        uid = int(args[0])
        if command == "STORE":
            box[uid]["flags"].update(args[2].strip("()").split())
            return "OK", [b"stored"]
        if command in ("MOVE", "COPY"):
            if command == "MOVE" and "MOVE" not in self.caps:
                return "BAD", [b"unknown command"]
            target = self._unquote(args[1])
            self.deliver(box[uid]["raw"], target)
            if command == "MOVE":
                del box[uid]
            return "OK", [b"done"]
        if command == "EXPUNGE":
            if "\\Deleted" in box[uid]["flags"]:
                del box[uid]
            return "OK", [b"expunged"]
        return "BAD", [b"unsupported"]

    def logout(self):
        self.log.append(("LOGOUT",))
        return "BYE", [b"bye"]
