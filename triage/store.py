"""SQLite persistence: triaged messages, IMAP sync state, user corrections, audit log.

Sync is incremental per (mailbox, UIDVALIDITY): if the server reports a new
UIDVALIDITY, old UIDs are meaningless, so that mailbox's state is reset rather than
silently skipping or mismatching messages.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .mail import Mail, from_fields
from .pipeline import Triage

SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    mailbox TEXT NOT NULL,
    uidvalidity INTEGER NOT NULL,
    uid INTEGER NOT NULL,
    message_id TEXT,
    from_name TEXT, from_addr TEXT, subject TEXT, date TEXT, body TEXT,
    category TEXT, confidence REAL,
    phishing_score REAL, phishing_label TEXT, phishing_reasons TEXT,
    priority REAL, priority_reasons TEXT,
    actions TEXT, summary TEXT,
    applied TEXT,
    triaged_at TEXT,
    PRIMARY KEY (mailbox, uidvalidity, uid)
);
CREATE TABLE IF NOT EXISTS sync_state (
    mailbox TEXT PRIMARY KEY, uidvalidity INTEGER NOT NULL, last_uid INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS corrections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_name TEXT, from_addr TEXT, subject TEXT, body TEXT, category TEXT NOT NULL, created_at TEXT
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, mailbox TEXT, uid INTEGER, action TEXT, dry_run INTEGER
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class Store:
    def __init__(self, path: str | Path = "triage.sqlite3") -> None:
        self.db = sqlite3.connect(str(path))
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    # --- sync state -------------------------------------------------------------------
    def last_uid(self, mailbox: str, uidvalidity: int) -> int:
        row = self.db.execute("SELECT uidvalidity, last_uid FROM sync_state WHERE mailbox = ?", (mailbox,)).fetchone()
        if row is None:
            return 0
        if row["uidvalidity"] != uidvalidity:
            with self.db:
                self.db.execute(
                    "DELETE FROM messages WHERE mailbox = ? AND uidvalidity = ?", (mailbox, row["uidvalidity"])
                )
                self.db.execute("DELETE FROM sync_state WHERE mailbox = ?", (mailbox,))
            return 0
        return int(row["last_uid"])

    def set_last_uid(self, mailbox: str, uidvalidity: int, uid: int) -> None:
        with self.db:
            self.db.execute(
                "INSERT INTO sync_state(mailbox, uidvalidity, last_uid) VALUES (?, ?, ?) "
                "ON CONFLICT(mailbox) DO UPDATE SET uidvalidity = excluded.uidvalidity, "
                "last_uid = MAX(sync_state.last_uid, excluded.last_uid)",
                (mailbox, uidvalidity, uid),
            )

    # --- messages ---------------------------------------------------------------------
    def save(self, mailbox: str, uidvalidity: int, mail: Mail, result: Triage) -> None:
        r = asdict(result)
        with self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    mailbox,
                    uidvalidity,
                    mail.uid,
                    mail.message_id,
                    mail.from_name,
                    mail.from_addr,
                    mail.subject,
                    mail.date,
                    mail.text[:4000],
                    r["category"],
                    r["confidence"],
                    r["phishing_score"],
                    r["phishing_label"],
                    json.dumps(r["phishing_reasons"]),
                    r["priority"],
                    json.dumps(r["priority_reasons"]),
                    json.dumps(r["actions"]),
                    r["summary"],
                    None,
                    _now(),
                ),
            )

    def messages(self, mailbox: str | None = None, pending_only: bool = False) -> list[dict[str, Any]]:
        sql = "SELECT * FROM messages"
        clauses, args = [], []
        if mailbox:
            clauses.append("mailbox = ?")
            args.append(mailbox)
        if pending_only:
            clauses.append("applied IS NULL")
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY priority DESC, date DESC"
        rows = []
        for row in self.db.execute(sql, args):
            d = dict(row)
            for key in ("phishing_reasons", "priority_reasons", "actions"):
                d[key] = json.loads(d[key] or "[]")
            rows.append(d)
        return rows

    def mark_applied(self, mailbox: str, uidvalidity: int, uid: int, actions: list[str], dry_run: bool) -> None:
        with self.db:
            for action in actions:
                self.db.execute(
                    "INSERT INTO audit(at, mailbox, uid, action, dry_run) VALUES (?, ?, ?, ?, ?)",
                    (_now(), mailbox, uid, action, int(dry_run)),
                )
            if not dry_run:
                self.db.execute(
                    "UPDATE messages SET applied = ? WHERE mailbox = ? AND uidvalidity = ? AND uid = ?",
                    (json.dumps(actions), mailbox, uidvalidity, uid),
                )

    def audit(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.db.execute("SELECT * FROM audit ORDER BY id")]

    # --- corrections ------------------------------------------------------------------
    def add_correction(self, mailbox: str, uid: int, category: str) -> dict[str, Any]:
        row = self.db.execute(
            "SELECT * FROM messages WHERE mailbox = ? AND uid = ? ORDER BY uidvalidity DESC LIMIT 1", (mailbox, uid)
        ).fetchone()
        if row is None:
            raise KeyError(f"no triaged message {mailbox}/{uid}")
        with self.db:
            self.db.execute(
                "INSERT INTO corrections(from_name, from_addr, subject, body, category, created_at) "
                "VALUES (?,?,?,?,?,?)",
                (row["from_name"], row["from_addr"], row["subject"], row["body"], category, _now()),
            )
            self.db.execute(
                "UPDATE messages SET category = ?, confidence = 1.0 WHERE mailbox = ? AND uid = ? AND uidvalidity = ?",
                (category, mailbox, uid, row["uidvalidity"]),
            )
        return dict(row)

    def corrections(self) -> list[tuple[Mail, str]]:
        out = []
        for r in self.db.execute("SELECT * FROM corrections ORDER BY id"):
            sender = f"{r['from_name']} <{r['from_addr']}>" if r["from_name"] else r["from_addr"]
            out.append((from_fields(sender, r["subject"], r["body"]), r["category"]))
        return out
