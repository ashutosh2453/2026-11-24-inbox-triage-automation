import io
import json
from pathlib import Path

import pytest
from fake_imap import FakeIMAP

from triage import cli
from triage import rules as rules_mod
from triage.classify import Classifier
from triage.digest import markdown, to_html
from triage.imap import ImapClient, ImapError, quote_mailbox
from triage.mail import parse
from triage.pipeline import triage_many
from triage.store import Store

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
RAW = {p.stem: p.read_bytes() for p in sorted(EXAMPLES.glob("*.eml"))}


@pytest.fixture(scope="module")
def clf():
    return Classifier.default()


# --- IMAP client --------------------------------------------------------------------


def test_uids_after_filters_the_star_quirk():
    client = ImapClient(FakeIMAP(list(RAW.values())))
    client.select("INBOX", readonly=True)
    assert client.uids_after(0) == [1, 2, 3, 4]
    assert client.uids_after(4) == []  # "5:*" still returns 4 on real servers


def test_fetch_uses_peek_and_returns_raw():
    fake = FakeIMAP([RAW["newsletter"]])
    client = ImapClient(fake)
    client.select("INBOX", readonly=True)
    assert list(client.fetch([1])) == [(1, RAW["newsletter"])]
    assert ("FETCH", "1", "(BODY.PEEK[])") in fake.log


def test_move_prefers_move_and_creates_folder():
    fake = FakeIMAP([RAW["newsletter"]])
    client = ImapClient(fake)
    client.select("INBOX", readonly=False)
    client.move(1, "Later")
    assert fake.boxes["INBOX"] == {} and list(fake.boxes["Later"]) == [1]
    assert ("CREATE", "Later") in fake.log and any(e[0] == "MOVE" for e in fake.log)


def test_move_falls_back_to_copy_and_uid_expunge():
    fake = FakeIMAP([RAW["newsletter"], RAW["alert"]], caps="IMAP4rev1 UIDPLUS")
    fake.boxes["INBOX"][2]["flags"].add("\\Deleted")  # user's own deletion must survive
    client = ImapClient(fake)
    client.select("INBOX", readonly=False)
    client.move(1, "Later")
    assert list(fake.boxes["INBOX"]) == [2] and list(fake.boxes["Later"]) == [1]
    assert ("EXPUNGE", "1") in fake.log


def test_move_refuses_without_move_or_uidplus():
    client = ImapClient(FakeIMAP([RAW["newsletter"]], caps="IMAP4rev1"))
    client.select("INBOX", readonly=False)
    with pytest.raises(ImapError, match="refusing"):
        client.move(1, "Later")


def test_mailbox_names_and_flags_are_validated():
    assert quote_mailbox("Work/Later") == '"Work/Later"'
    for bad in ('x" DELETE "INBOX', "a\r\nb", ""):
        with pytest.raises(ValueError):
            quote_mailbox(bad)
    client = ImapClient(FakeIMAP([]))
    with pytest.raises(ValueError):
        client.flag(1, "\\Seen) (\\Deleted")


# --- store ---------------------------------------------------------------------------


def test_store_sync_state_and_uidvalidity_reset(tmp_path, clf):
    store = Store(tmp_path / "t.db")
    mail = parse(RAW["action-budget"], uid=5)
    store.save("INBOX", 100, mail, triage_many([mail], clf)[0])
    store.set_last_uid("INBOX", 100, 5)
    store.set_last_uid("INBOX", 100, 3)  # never moves backwards
    assert store.last_uid("INBOX", 100) == 5
    assert len(store.messages()) == 1
    assert store.last_uid("INBOX", 200) == 0  # server changed UIDVALIDITY
    assert store.messages() == []


def test_corrections_round_trip(tmp_path, clf):
    store = Store(tmp_path / "t.db")
    mail = parse(RAW["alert"], uid=9)
    store.save("INBOX", 1, mail, triage_many([mail], clf)[0])
    store.add_correction("INBOX", 9, "action")
    ((corrected, label),) = store.corrections()
    assert label == "action" and corrected.subject == mail.subject
    assert store.messages()[0]["category"] == "action"
    with pytest.raises(KeyError):
        store.add_correction("INBOX", 999, "action")


# --- rules ---------------------------------------------------------------------------


def test_default_rules_plan():
    rules = rules_mod.load(None)
    assert rules_mod.plan({"phishing_score": 0.9, "category": "action", "priority": 0.0}, rules) == [
        "flag",
        "move:Quarantine",
    ]
    assert rules_mod.plan({"phishing_score": 0, "category": "newsletter", "priority": 0.05}, rules) == ["move:Later"]
    assert rules_mod.plan({"phishing_score": 0, "category": "action", "priority": 0.8}, rules) == ["flag"]
    assert rules_mod.plan({"phishing_score": 0, "category": "meeting", "priority": 0.4}, rules) == []


def test_first_move_wins_and_from_domain():
    rules = rules_mod.parse(
        [
            {"when": {"from_domain": ["acme.com"]}, "do": {"move": "Work"}},
            {"when": {"category": "action"}, "do": {"move": "Todo", "flag": True}},
        ]
    )
    assert rules_mod.plan({"from_addr": "a@acme.com", "category": "action"}, rules) == ["flag", "move:Work"]


@pytest.mark.parametrize(
    "bad",
    [
        [],
        [{"when": {"colour": "red"}, "do": {"flag": True}}],
        [{"when": {"phishing": "high"}, "do": {"flag": True}}],
        [{"when": {"category": "spam"}, "do": {"flag": True}}],
        [{"when": {}, "do": {"delete": True}}],
        [{"when": {}, "do": {"move": 'x" (\\Deleted)'}}],
        [{"if": {}, "do": {"flag": True}}],
    ],
)
def test_bad_rules_are_rejected(bad):
    with pytest.raises((rules_mod.RuleError, ValueError)):
        rules_mod.parse(bad)


# --- digest --------------------------------------------------------------------------


def _rows(tmp_path, clf):
    store = Store(tmp_path / "d.db")
    mails = [parse(raw, uid=i) for i, raw in enumerate(RAW.values(), 1)]
    for m, r in zip(mails, triage_many(mails, clf), strict=True):
        store.save("INBOX", 1, m, r)
    return store.messages()


def test_digest_quarantines_phishing_and_escapes_html(tmp_path, clf):
    rows = _rows(tmp_path, clf)
    md = markdown(rows)
    assert md.index("Quarantined as phishing") < md.index("## Action")
    rows[0]["subject"] = "<img src=x onerror=alert(1)>"
    page = to_html(rows)
    assert "<img src=x" not in page and "&lt;img src=x onerror=alert(1)&gt;" in page


# --- CLI -----------------------------------------------------------------------------


def run(argv, monkeypatch=None, fake=None):
    if fake is not None:
        monkeypatch.setenv(cli.PASSWORD_ENV, "pw")
        monkeypatch.setattr(ImapClient, "connect", classmethod(lambda cls, *a, **k: cls(fake)))
    buf = io.StringIO()
    code = cli.main(argv, out=buf)
    return code, buf.getvalue()


def test_cli_eval_and_file():
    code, out = run(["eval", "--json"])
    data = json.loads(out)
    assert code == 0 and data["accuracy"] >= 0.9
    code, out = run(["file", str(EXAMPLES / "phish-paypal.eml"), "--json"])
    assert code == 0 and json.loads(out)[0]["phishing_label"] == "phishing"


def test_cli_sync_apply_digest_correct(tmp_path, monkeypatch):
    db = str(tmp_path / "cli.db")
    fake = FakeIMAP(list(RAW.values()))
    code, out = run(["--db", db, "sync", "--host", "h", "--user", "you@example.com"], monkeypatch, fake)
    assert code == 0 and "synced 4 new message(s)" in out and "1 phishing" in out
    assert fake.readonly is True  # sync never writes

    code, out = run(["--db", db, "sync", "--host", "h", "--user", "you@example.com"], monkeypatch, fake)
    assert "synced 0 new message(s)" in out and "after uid 4" in out

    inbox_before = dict(fake.boxes["INBOX"])
    code, out = run(["--db", db, "apply", "--host", "h", "--user", "u"], monkeypatch, fake)
    assert code == 0 and "dry run" in out and fake.boxes["INBOX"].keys() == inbox_before.keys()

    code, out = run(["--db", db, "apply", "--host", "h", "--user", "u", "--apply"], monkeypatch, fake)
    assert code == 0
    assert len(fake.boxes["Quarantine"]) == 1 and len(fake.boxes["Later"]) == 1
    quarantined = next(iter(fake.boxes["Quarantine"].values()))
    assert b"paypa1-support.com" in quarantined["raw"]

    code, out = run(["--db", db, "apply", "--host", "h", "--user", "u", "--apply"], monkeypatch, fake)
    assert "0 message(s) with actions" in out  # already applied, nothing twice

    code, out = run(["--db", db, "digest"])
    assert "Quarantined as phishing (1)" in out
    html_path = tmp_path / "d.html"
    assert run(["--db", db, "digest", "--html", str(html_path)])[0] == 0 and html_path.exists()

    code, out = run(["--db", db, "correct", "--uid", "1", "--category", "action"])
    assert code == 0 and "-> action" in out


def test_cli_requires_password_env(monkeypatch):
    monkeypatch.delenv(cli.PASSWORD_ENV, raising=False)
    with pytest.raises(SystemExit, match="TRIAGE_IMAP_PASSWORD"):
        cli.main(["sync", "--host", "h", "--user", "u"], out=io.StringIO())


def test_cli_bad_rules_file_exits_1(tmp_path):
    rules = tmp_path / "r.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    assert run(["--db", str(tmp_path / "x.db"), "apply", "--host", "h", "--user", "u", "--rules", str(rules)])[0] == 1


def test_copy_fallback_is_retry_safe_after_a_dropped_connection(tmp_path, monkeypatch):
    db = str(tmp_path / "retry.db")
    fake = FakeIMAP([RAW["newsletter"]], caps="IMAP4rev1 UIDPLUS")
    assert run(["--db", db, "sync", "--host", "h", "--user", "u"], monkeypatch, fake)[0] == 0
    fake.fail_once = {"EXPUNGE"}  # COPY succeeds, then the connection drops
    assert run(["--db", db, "apply", "--host", "h", "--user", "u", "--apply"], monkeypatch, fake)[0] == 1
    assert len(fake.boxes["Later"]) == 1 and len(fake.boxes["INBOX"]) == 1
    assert run(["--db", db, "apply", "--host", "h", "--user", "u", "--apply"], monkeypatch, fake)[0] == 0
    assert len(fake.boxes["Later"]) == 1, "retry must not copy the message a second time"
    assert fake.boxes["INBOX"] == {}
    assert sum(1 for entry in fake.log if entry[0] == "COPY") == 1
