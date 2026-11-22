"""Parse raw RFC 822 messages into the fields triage needs.

Uses only the standard library ``email`` package with the modern policy, which
decodes RFC 2047 headers (``=?utf-8?b?...?=``) and charsets. HTML bodies are reduced
to text with ``html.parser`` (scripts and styles dropped) and every ``<a href>`` is
kept with its visible text, because a mismatch between the two is a phishing signal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html.parser import HTMLParser

MAX_BODY_CHARS = 20_000


@dataclass
class Link:
    text: str
    href: str


@dataclass
class Attachment:
    filename: str
    content_type: str


@dataclass
class Mail:
    message_id: str = ""
    from_name: str = ""
    from_addr: str = ""
    reply_to: str = ""
    to: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    subject: str = ""
    date: str = ""
    text: str = ""
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    auth: dict[str, str] = field(default_factory=dict)  # spf/dkim/dmarc -> pass/fail/...
    list_unsubscribe: bool = False
    auto_submitted: bool = False
    uid: int | None = None

    @property
    def from_domain(self) -> str:
        return domain_of(self.from_addr)

    def as_text(self) -> str:
        """Text used by the classifier: sender name, subject and body."""
        return f"{self.from_name}\n{self.subject}\n{self.text}"


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(">").strip() if "@" in addr else ""


class _HTMLText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[Link] = []
        self._skip = 0
        self._href: str | None = None
        self._link_text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "head"):
            self._skip += 1
        elif tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._link_text = []
        elif tag in ("br", "p", "div", "tr", "li", "h1", "h2", "h3"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head") and self._skip:
            self._skip -= 1
        elif tag == "a" and self._href is not None:
            self.links.append(Link(" ".join("".join(self._link_text).split()), self._href))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.parts.append(data)
        if self._href is not None:
            self._link_text.append(data)

    def text(self) -> str:
        return re.sub(r"[ \t]+", " ", re.sub(r"\n\s*\n+", "\n\n", "".join(self.parts))).strip()


def html_to_text(html: str) -> tuple[str, list[Link]]:
    parser = _HTMLText()
    parser.feed(html)
    parser.close()
    return parser.text(), parser.links


_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.I)


def parse_auth_results(values: list[str]) -> dict[str, str]:
    """First verdict per mechanism from Authentication-Results headers."""
    out: dict[str, str] = {}
    for value in values:
        for mech, verdict in _AUTH_RE.findall(value):
            out.setdefault(mech.lower(), verdict.lower())
    return out


def parse(raw: bytes, uid: int | None = None) -> Mail:
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)  # type: ignore[assignment]
    name, addr = parseaddr(str(msg.get("From", "")))
    _, reply_to = parseaddr(str(msg.get("Reply-To", "")))
    date = ""
    if msg.get("Date"):
        try:
            date = parsedate_to_datetime(str(msg["Date"])).isoformat()
        except (TypeError, ValueError):
            date = ""

    plain: list[str] = []
    html: list[str] = []
    attachments: list[Attachment] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        ctype = part.get_content_type()
        if filename or part.get_content_disposition() == "attachment":
            attachments.append(Attachment(filename or "", ctype))
            continue
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeDecodeError):
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="replace")
        (plain if ctype == "text/plain" else html).append(str(content))

    links: list[Link] = []
    html_text = ""
    for chunk in html:
        text, found = html_to_text(chunk)
        html_text += text + "\n"
        links += found
    text = "\n".join(plain).strip() or html_text.strip()
    if not html:
        urls = [u.rstrip(".,;:!?") for u in _URL_RE.findall(text)]  # sentence punctuation is not part of a URL
        links = [Link(u, u) for u in urls]

    return Mail(
        message_id=str(msg.get("Message-ID", "")).strip(),
        from_name=name.strip(),
        from_addr=addr.strip().lower(),
        reply_to=reply_to.strip().lower(),
        to=[a.lower() for _, a in getaddresses([str(v) for v in msg.get_all("To", [])]) if a],
        cc=[a.lower() for _, a in getaddresses([str(v) for v in msg.get_all("Cc", [])]) if a],
        subject=" ".join(str(msg.get("Subject", "")).split()),
        date=date,
        text=text[:MAX_BODY_CHARS],
        links=links,
        attachments=attachments,
        auth=parse_auth_results([str(v) for v in msg.get_all("Authentication-Results", [])]),
        list_unsubscribe=bool(msg.get("List-Unsubscribe")),
        auto_submitted=str(msg.get("Auto-Submitted", "no")).lower() not in ("", "no")
        or str(msg.get("Precedence", "")).lower() in ("bulk", "auto_reply", "list"),
        uid=uid,
    )


def from_fields(sender: str, subject: str, body: str) -> Mail:
    """Build a Mail from corpus fields (used for training and evaluation)."""
    name, addr = parseaddr(sender)
    return Mail(from_name=name, from_addr=addr.lower(), subject=subject, text=body)
