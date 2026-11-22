from email.message import EmailMessage
from pathlib import Path

import pytest

from triage.classify import load_corpus
from triage.mail import Attachment, Link, Mail, html_to_text, parse, parse_auth_results
from triage.phishing import assess, lookalike_of, registrable

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def eml(name: str) -> Mail:
    return parse((EXAMPLES / name).read_bytes())


def test_parse_plain_message():
    m = eml("action-budget.eml")
    assert (m.from_name, m.from_addr, m.from_domain) == ("Priya Nair", "priya@acme-corp.com", "acme-corp.com")
    assert m.to == ["you@example.com"]
    assert m.date.startswith("2026-11-24T10:05:00")
    assert m.auth == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    assert "approve it by Wednesday" in m.text


def test_parse_html_keeps_links_and_drops_styles():
    m = eml("newsletter.eml")
    assert m.list_unsubscribe and m.auto_submitted
    assert "color:red" not in m.text and "Welcome to issue 690" in m.text
    assert Link("Read online", "https://pythonweekly.com/archive/690") in m.links


def test_parse_encoded_headers_attachments_and_multipart():
    msg = EmailMessage()
    msg["From"] = "=?utf-8?b?w4lsb2RpZQ==?= <elodie@example.fr>"
    msg["To"] = "a@example.com, B <b@example.com>"
    msg["Cc"] = "c@example.com"
    msg["Subject"] = "=?utf-8?q?R=C3=A9union?=  demain"
    msg.set_content("Plain body")
    msg.add_alternative("<p>HTML <a href='https://x.example/a'>body</a></p>", subtype="html")
    msg.add_attachment(b"MZ", maintype="application", subtype="octet-stream", filename="invoice.pdf.exe")
    m = parse(msg.as_bytes(), uid=7)
    assert m.from_name == "Élodie" and m.subject == "Réunion demain" and m.uid == 7
    assert m.to == ["a@example.com", "b@example.com"] and m.cc == ["c@example.com"]
    assert m.text == "Plain body"  # text/plain preferred over HTML
    assert m.attachments == [Attachment("invoice.pdf.exe", "application/octet-stream")]


def test_plain_text_urls_become_links_and_bad_dates_are_ignored():
    raw = b"From: a@b.com\r\nDate: not a date\r\nSubject: x\r\n\r\nsee https://example.com/x, thanks"
    m = parse(raw)
    assert m.date == "" and m.links == [Link("https://example.com/x", "https://example.com/x")]


def test_html_to_text_and_auth_parsing():
    text, links = html_to_text("<script>evil()</script><p>Hi <a href='h'>there</a></p>")
    assert text == "Hi there" and links == [Link("there", "h")]
    assert parse_auth_results(["mx; spf=softfail; DKIM=pass", "spf=pass"]) == {"spf": "softfail", "dkim": "pass"}


def test_forged_authentication_results_are_ignored(monkeypatch):
    ours = "mx.example.com; spf=fail smtp.mailfrom=evil.example"
    forged = "mx.example.com; spf=pass; dkim=pass"
    # Our server prepends its header, so a forged one sits below it and is ignored.
    assert parse_auth_results([ours, forged]) == {"spf": "fail"}
    # With a trusted authserv-id, headers naming any other server are ignored wherever they are.
    assert parse_auth_results(["evil; spf=pass", ours], {"mx.example.com"}) == {"spf": "fail"}
    raw = (
        f"Authentication-Results: {ours}\r\nAuthentication-Results: {forged}\r\nFrom: a@evil.example\r\n\r\nhi"
    ).encode()
    assert parse(raw).auth == {"spf": "fail"}
    monkeypatch.setenv("TRIAGE_AUTHSERV_ID", "other.example")
    assert parse(raw).auth == {}


def test_plain_text_urls_are_kept_alongside_html_links():
    msg = EmailMessage()
    msg["From"] = "a@shop.example"
    msg.set_content("Log in at http://185.243.115.7/login now")
    msg.add_alternative("<p><a href='https://shop.example/account'>Your account</a></p>", subtype="html")
    mail = parse(msg.as_bytes())
    assert {link.href for link in mail.links} == {"https://shop.example/account", "http://185.243.115.7/login"}
    assert "ip-link" in {s.name for s in assess(mail).signals}


def test_example_phish_is_caught_with_reasons():
    v = assess(eml("phish-paypal.eml"))
    assert v.label == "phishing" and v.score >= 0.95
    names = {s.name for s in v.signals}
    assert {
        "display-name-spoof",
        "lookalike-sender",
        "reply-to-mismatch",
        "auth-failed",
        "link-text-mismatch",
        "ip-link",
        "credential-request",
        "urgent-language",
    } <= names


@pytest.mark.parametrize("name", ["action-budget.eml", "newsletter.eml", "alert.eml"])
def test_legitimate_examples_are_clean(name):
    assert assess(eml(name)).label == "clean"


def test_no_false_alarms_on_the_whole_corpus():
    corpus = load_corpus("train.jsonl") + load_corpus("heldout.jsonl")
    flagged = [(m.from_addr, assess(m).score) for m, _ in corpus if assess(m).label != "clean"]
    assert flagged == []


@pytest.mark.parametrize(
    ("domain", "imitates"),
    [
        ("paypa1-support.com", "paypal.com"),
        ("rnicrosoft.com", "microsoft.com"),
        ("paypal-security.com", "paypal.com"),
        ("secure-hdfcbank-login.net", "hdfcbank.com"),
        ("githubb.com", "github.com"),
        ("accounts.google.com", None),
        ("sns.amazonaws.com", None),
        ("mail.amazon.co.uk", None),
        ("example.com", None),
        ("sbx.com", None),  # 3-letter brands are not typo-matched
    ],
)
def test_lookalikes(domain, imitates):
    assert lookalike_of(domain) == imitates


def test_registrable_domain():
    assert registrable("a.b.example.co.uk") == "example.co.uk"
    assert registrable("mail.google.com") == "google.com"


def test_attachments_punycode_and_shorteners():
    m = Mail(
        from_addr="x@shop.example",
        attachments=[Attachment("scan.pdf.exe", "application/x-msdownload"), Attachment("ok.pdf", "application/pdf")],
        links=[Link("click", "https://xn--pypal-4ve.com/"), Link("here", "https://bit.ly/abc")],
    )
    names = {s.name for s in assess(m).signals}
    assert {"risky-attachment", "double-extension", "punycode-link", "shortened-link"} <= names


def test_a_single_weak_signal_is_not_suspicious():
    m = Mail(from_addr="x@shop.example", links=[Link("here", "https://bit.ly/abc")])
    assert assess(m).label == "clean"


def test_link_text_that_is_not_a_domain_is_not_a_mismatch():
    m = Mail(from_addr="x@shop.example", links=[Link("Read online", "https://other.example/x")])
    assert "link-text-mismatch" not in {s.name for s in assess(m).signals}
