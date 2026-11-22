"""Explainable 0-1 priority score.

Every point added comes with a reason string, so the digest can show *why* a
message is at the top. Phishing always scores zero: it goes to quarantine, never to
the top of the inbox where someone might act on it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date

from .actions import ActionItem
from .mail import Mail

BASE = {"action": 0.55, "meeting": 0.4, "notification": 0.15, "newsletter": 0.05, "promotion": 0.0, "review": 0.3}
ALERT = re.compile(r"\b(alarm|triggered|failed|failure|outage|down|security alert|incident|breach)\b", re.I)


@dataclass(frozen=True)
class Profile:
    """Who "me" is and who matters, from the user's config."""

    me: tuple[str, ...] = ()
    vip_senders: tuple[str, ...] = ()  # full addresses or @domain.com
    vip_keywords: tuple[str, ...] = ()

    def is_vip(self, addr: str) -> bool:
        addr = addr.lower()
        return any(addr == v.lower() or (v.startswith("@") and addr.endswith(v.lower())) for v in self.vip_senders)


@dataclass
class Priority:
    score: float
    reasons: list[str] = field(default_factory=list)


def score(
    mail: Mail, category: str, actions: list[ActionItem], phishing: float, profile: Profile, today: date
) -> Priority:
    if phishing >= 0.7:
        return Priority(0.0, ["likely phishing: quarantined, never prioritised"])
    s = BASE.get(category, 0.3)
    reasons = [f"{category} (+{s:.2f})"]

    def add(points: float, why: str) -> None:
        nonlocal s
        s += points
        reasons.append(f"{why} ({points:+.2f})")

    if profile.is_vip(mail.from_addr):
        add(0.25, "VIP sender")
    me = {a.lower() for a in profile.me}
    if me:
        if me & set(mail.to):
            add(0.05, "sent directly to you")
        elif me & set(mail.cc):
            add(-0.05, "you are only in Cc")
    dues = [a.due for a in actions if a.due]
    if dues:
        days = (min(dues) - today).days
        if days < 0:
            add(0.2, f"deadline passed {-days} day(s) ago")
        elif days <= 1:
            add(0.25, "due today or tomorrow")
        elif days <= 3:
            add(0.15, f"due in {days} days")
        else:
            add(0.05, f"due in {days} days")
    if category == "notification" and ALERT.search(f"{mail.subject} {mail.text[:500]}"):
        add(0.35, "operational or security alert")
    lowered = f"{mail.subject} {mail.text}".lower()
    hits = [k for k in profile.vip_keywords if k.lower() in lowered]
    if hits:
        add(0.1, f"mentions {', '.join(hits)}")
    if 0.4 <= phishing < 0.7:
        add(-0.2, "suspicious signals")
    return Priority(round(min(max(s, 0.0), 1.0), 3), reasons)
