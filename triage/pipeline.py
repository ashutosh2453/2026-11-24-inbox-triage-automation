"""Run every triage step on a message and collect one explainable result."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime

from . import actions as action_mod
from .classify import Classifier
from .mail import Mail
from .phishing import assess
from .priority import Profile, score
from .summarize import Summarizer


@dataclass
class Triage:
    category: str
    confidence: float
    phishing_score: float
    phishing_label: str
    phishing_reasons: list[str]
    priority: float
    priority_reasons: list[str]
    actions: list[dict[str, str | None]] = field(default_factory=list)
    summary: str = ""


def _received(mail: Mail) -> datetime | None:
    try:
        return datetime.fromisoformat(mail.date) if mail.date else None
    except ValueError:
        return None


def triage_many(
    mails: list[Mail],
    classifier: Classifier,
    profile: Profile | None = None,
    summarizer: Summarizer | None = None,
    today: date | None = None,
) -> list[Triage]:
    profile = profile or Profile()
    summarizer = summarizer or Summarizer(model="")
    preds = classifier.predict(mails) if mails else []
    out = []
    for mail, pred in zip(mails, preds, strict=True):
        verdict = assess(mail)
        received = _received(mail)
        items = action_mod.extract(mail.text, received or today)
        # Deadlines are *resolved* against the message date ("tomorrow" = day after it was sent)
        # but *compared* with the triage date, so an old "by tomorrow" shows up as overdue.
        ref = today or date.today()
        prio = score(mail, pred.category, items, verdict.score, profile, ref)
        out.append(
            Triage(
                category=pred.category,
                confidence=pred.confidence,
                phishing_score=verdict.score,
                phishing_label=verdict.label,
                phishing_reasons=[s.reason for s in verdict.signals],
                priority=prio.score,
                priority_reasons=prio.reasons,
                actions=[
                    {"text": a.text, "due": a.due.isoformat() if a.due else None, "phrase": a.due_phrase} for a in items
                ],
                summary=summarizer.summarize(mail),
            )
        )
    return out
