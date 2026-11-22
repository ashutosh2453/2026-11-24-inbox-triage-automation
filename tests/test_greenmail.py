"""Integration test against a real IMAP server (GreenMail), run in CI.

Set TRIAGE_IT_HOST (and optionally TRIAGE_IT_SMTP_PORT / TRIAGE_IT_IMAP_PORT) to run it
locally, e.g. with ``docker run -p 3025:3025 -p 3143:3143 greenmail/standalone``.
"""

import io
import os
import smtplib
import time
import uuid
from pathlib import Path

import pytest

from triage import cli
from triage.imap import ImapClient

HOST = os.environ.get("TRIAGE_IT_HOST")
pytestmark = pytest.mark.skipif(not HOST, reason="set TRIAGE_IT_HOST to run against a real IMAP server")
SMTP_PORT = int(os.environ.get("TRIAGE_IT_SMTP_PORT", "3025"))
IMAP_PORT = int(os.environ.get("TRIAGE_IT_IMAP_PORT", "3143"))
EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_sync_and_apply_against_greenmail(tmp_path, monkeypatch):
    user = f"it-{uuid.uuid4().hex[:8]}@example.com"  # GreenMail creates accounts on first delivery/login
    monkeypatch.setenv(cli.PASSWORD_ENV, user)  # GreenMail's default: password == login
    with smtplib.SMTP(HOST, SMTP_PORT, timeout=10) as smtp:
        for path in sorted(EXAMPLES.glob("*.eml")):
            smtp.sendmail("sender@example.com", [user], path.read_bytes())

    def inbox_count() -> int:
        client = ImapClient.connect(HOST, IMAP_PORT, user, user, use_ssl=False)
        try:
            client.select("INBOX", readonly=True)
            return len(client.uids_after(0))
        finally:
            client.logout()

    for _ in range(50):
        if inbox_count() == 4:
            break
        time.sleep(0.2)
    assert inbox_count() == 4

    db = str(tmp_path / "it.db")
    server = ["--host", HOST, "--port", str(IMAP_PORT), "--user", user, "--no-ssl"]
    out = io.StringIO()
    assert cli.main(["--db", db, "sync", *server], out=out) == 0
    assert "synced 4 new message(s)" in out.getvalue() and "1 phishing" in out.getvalue()

    out = io.StringIO()
    assert cli.main(["--db", db, "apply", *server, "--apply"], out=out) == 0
    print(out.getvalue())

    client = ImapClient.connect(HOST, IMAP_PORT, user, user, use_ssl=False)
    try:
        client.select("Quarantine", readonly=True)
        quarantined = list(client.fetch(client.uids_after(0)))
        client.select("Later", readonly=True)
        later = client.uids_after(0)
        client.select("INBOX", readonly=True)
        remaining = client.uids_after(0)
    finally:
        client.logout()
    assert len(quarantined) == 1 and b"paypa1-support.com" in quarantined[0][1]
    assert len(later) == 1  # the newsletter
    assert len(remaining) == 2  # action + alert stay in the inbox
