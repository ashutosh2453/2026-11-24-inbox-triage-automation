"""Explainable phishing signals.

Each signal is a rule with a weight and a human-readable reason, so the digest can
say *why* a message was quarantined. The score is ``1 - prod(1 - w)`` over fired
signals: independent weak signals add up, but no single weak one dominates.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from .mail import Mail, domain_of

# Brands commonly impersonated, mapped to the domains they really send from.
BRANDS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com",),
    "microsoft": ("microsoft.com", "office.com", "outlook.com", "live.com", "microsoftonline.com"),
    "office 365": ("microsoft.com", "office.com"),
    "google": ("google.com", "gmail.com", "youtube.com", "googleusercontent.com", "googleapis.com"),
    "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com"),
    "netflix": ("netflix.com",),
    "hdfc": ("hdfcbank.com", "hdfcbank.net"),
    "sbi": ("sbi.co.in", "onlinesbi.sbi"),
    "icici": ("icicibank.com",),
    "github": ("github.com", "githubusercontent.com"),
    "linkedin": ("linkedin.com",),
    "dhl": ("dhl.com",),
    "fedex": ("fedex.com",),
}
RISKY_EXTENSIONS = (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".iso", ".img", ".html", ".htm", ".lnk", ".hta")
URGENT = re.compile(
    r"\b(verify your (account|identity)|account (will be|has been) (suspended|locked|closed)|"
    r"within 24 hours|immediately|unusual (sign-in|activity)|confirm your (password|details)|"
    r"update your payment|final notice|act now)\b",
    re.I,
)
CREDENTIAL_ASK = re.compile(r"\b(password|one[- ]time password|otp|pin|cvv|card number)\b", re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at"}


@dataclass(frozen=True)
class Signal:
    name: str
    weight: float
    reason: str


@dataclass(frozen=True)
class Verdict:
    score: float
    signals: tuple[Signal, ...]

    @property
    def label(self) -> str:
        return "phishing" if self.score >= 0.7 else "suspicious" if self.score >= 0.4 else "clean"


def registrable(domain: str) -> str:
    """Approximate registrable domain: last two labels, three for ccTLD second levels."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "net", "org", "gov", "ac", "edu"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _edit_distance_le1(a: str, b: str) -> bool:
    if a == b:
        return False
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b, strict=True)) == 1
    short, long_ = sorted((a, b), key=len)
    return any(long_[:i] + long_[i + 1 :] == short for i in range(len(long_)))


_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t"})


def lookalike_of(domain: str) -> str | None:
    """Brand domain this one imitates (typo, digit swap or brand-plus-word), if any."""
    reg = registrable(domain)
    label = reg.split(".")[0]
    for real_domains in BRANDS.values():
        for real in real_domains:
            if reg == real:
                return None
    for real_domains in BRANDS.values():
        for real in real_domains:
            real_label = real.split(".")[0]
            normalized = label.translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w")
            # Typo matching only for longer names: 3-letter brands (sbi) would match half the internet.
            if normalized == real_label or (len(real_label) >= 5 and _edit_distance_le1(label, real_label)):
                return real
            if len(real_label) >= 5 and real_label in normalized and label != real_label:
                return real  # paypal-security.com, secure-hdfcbank-login.net
    return None


def _host(href: str) -> str:
    try:
        return (urlparse(href.strip()).hostname or "").lower()
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def assess(mail: Mail) -> Verdict:
    signals: list[Signal] = []

    def fire(name: str, weight: float, reason: str) -> None:
        signals.append(Signal(name, weight, reason))

    sender_domain = mail.from_domain
    sender_reg = registrable(sender_domain) if sender_domain else ""
    name_l = mail.from_name.lower()

    for brand, domains in BRANDS.items():
        if re.search(rf"\b{re.escape(brand)}\b", name_l) and sender_reg not in domains:
            fire("display-name-spoof", 0.55, f"display name says {brand!r} but the sender domain is {sender_domain!r}")
            break

    imitated = lookalike_of(sender_domain) if sender_domain else None
    if imitated:
        fire("lookalike-sender", 0.6, f"sender domain {sender_domain!r} imitates {imitated!r}")

    if mail.reply_to and sender_reg and registrable(domain_of(mail.reply_to)) != sender_reg:
        fire("reply-to-mismatch", 0.3, f"replies go to {domain_of(mail.reply_to)!r}, not {sender_domain!r}")

    failed = sorted(k for k, v in mail.auth.items() if v in ("fail", "softfail", "permerror"))
    if failed:
        fire("auth-failed", 0.45, f"{', '.join(failed)} failed for the sender")

    seen_link_reasons: set[str] = set()
    for link in mail.links:
        host = _host(link.href)
        if not host:
            continue
        shown = _host(link.text if "://" in link.text else "http://" + link.text) if "." in link.text else ""
        if shown and "." in shown and " " not in link.text.strip() and registrable(shown) != registrable(host):
            reason = f"link text shows {shown!r} but points to {host!r}"
            if reason not in seen_link_reasons:
                fire("link-text-mismatch", 0.5, reason)
                seen_link_reasons.add(reason)
        if _is_ip(host):
            fire("ip-link", 0.4, f"link points to a raw IP address ({host})")
        if host.startswith("xn--") or ".xn--" in host:
            fire("punycode-link", 0.4, f"link uses a punycode domain ({host})")
        if host in SHORTENERS:
            fire("shortened-link", 0.15, f"link hides its destination behind {host}")
        link_imitates = lookalike_of(host)
        if link_imitates:
            fire("lookalike-link", 0.5, f"link domain {host!r} imitates {link_imitates!r}")

    for att in mail.attachments:
        lower = att.filename.lower()
        if lower.endswith(RISKY_EXTENSIONS):
            fire("risky-attachment", 0.5, f"attachment {att.filename!r} can run code or phish credentials")
        if re.search(r"\.(pdf|docx?|xlsx?|jpg|png)\.\w+$", lower):
            fire("double-extension", 0.4, f"attachment {att.filename!r} hides its real type")

    body = f"{mail.subject}\n{mail.text}"
    if URGENT.search(body):
        fire("urgent-language", 0.2, "pressure language (deadline or account threat)")
    if CREDENTIAL_ASK.search(body) and (URGENT.search(body) or mail.links):
        fire("credential-request", 0.25, "asks for a password, OTP or card details")

    # Deduplicate by name, keeping the strongest instance, then combine.
    best: dict[str, Signal] = {}
    for s in signals:
        if s.name not in best or s.weight > best[s.name].weight:
            best[s.name] = s
    unique = tuple(sorted(best.values(), key=lambda s: -s.weight))
    keep = 1.0
    for s in unique:
        keep *= 1 - s.weight
    return Verdict(round(1 - keep, 3), unique)
