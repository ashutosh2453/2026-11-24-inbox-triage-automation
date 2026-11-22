"""Find requests addressed to the reader and the deadlines attached to them.

Rule-based on purpose: it is predictable, fast, and every extracted item points at
the sentence it came from. Relative deadlines ("by Thursday", "tomorrow", "EOD")
are resolved against the message date, not the time triage happens to run.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta

WEEKDAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
MONTHS = [
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
]
_MONTH_RE = "|".join(m[:3] + rf"(?:{m[3:]})?" for m in MONTHS)

REQUEST = re.compile(
    r"\b(could you|can you|would you( be able to| mind)?|please|kindly|need you to|let me know|"
    r"reply with|are you (free|able)|do you (still )?have|action required)\b",
    re.I,
)
NOT_FOR_ME = re.compile(r"\b(please do not reply|please reply to this email directly|no action is needed)\b", re.I)
_SENTENCES = re.compile(r"(?<=[.!?])\s+|\n+")


@dataclass(frozen=True)
class ActionItem:
    text: str
    due: date | None
    due_phrase: str


def _next_weekday(base: date, weekday: int) -> date:
    days = (weekday - base.weekday()) % 7
    return base + timedelta(days=days or 7)


def resolve_deadline(sentence: str, base: date) -> tuple[date | None, str]:
    s = sentence.lower()
    if m := re.search(r"\b(today|tonight|eod|end of (the )?day)\b", s):
        return base, m.group(0)
    if m := re.search(r"\btomorrow\b", s):
        return base + timedelta(days=1), m.group(0)
    if m := re.search(r"\b(this week|end of (the )?week)\b", s):
        return base + timedelta(days=(4 - base.weekday()) % 7), m.group(0)
    if m := re.search(r"\bnext week\b", s):
        return _next_weekday(base, 0) + timedelta(days=4), m.group(0)
    if m := re.search(r"\b(\d{4})-(\d{2})-(\d{2})\b", s):
        try:
            return date(int(m[1]), int(m[2]), int(m[3])), m.group(0)
        except ValueError:
            pass
    month_day = re.search(rf"\b(\d{{1,2}})(?:st|nd|rd|th)?\s+({_MONTH_RE})\b", s) or re.search(
        rf"\b({_MONTH_RE})\s+(\d{{1,2}})(?:st|nd|rd|th)?\b", s
    )
    if month_day:
        a, b = month_day.groups()
        day, month_name = (a, b) if a.isdigit() else (b, a)
        month = next(i for i, m in enumerate(MONTHS, 1) if m.startswith(month_name[:3]))
        try:
            due = date(base.year, month, int(day))
            if due < base - timedelta(days=60):
                due = date(base.year + 1, month, int(day))  # "15 January" written in December
            return due, month_day.group(0)
        except ValueError:
            pass
    if m := re.search(r"\b(?:by|before|on|due)?\s*the (\d{1,2})(?:st|nd|rd|th)\b", s):
        day = int(m[1])
        if 1 <= day <= 31:
            year, month = base.year, base.month
            if day < base.day:
                year, month = (year + 1, 1) if month == 12 else (year, month + 1)
            try:
                return date(year, month, day), m.group(0).strip()
            except ValueError:
                pass
    for i, name in enumerate(WEEKDAYS):
        if m := re.search(rf"\b{name}\b", s):
            return _next_weekday(base, i), m.group(0)
    return None, ""


def extract(text: str, received: datetime | date | None = None) -> list[ActionItem]:
    base = received.date() if isinstance(received, datetime) else (received or date.today())
    items: list[ActionItem] = []
    for raw in _SENTENCES.split(text):
        sentence = " ".join(raw.split())
        if len(sentence) < 8 or NOT_FOR_ME.search(sentence) or not REQUEST.search(sentence):
            continue
        due, phrase = resolve_deadline(sentence, base)
        items.append(ActionItem(sentence, due, phrase))
    # A deadline stated in a neighbouring sentence ("...approve it. Finance needs it by Thursday.")
    if items and all(i.due is None for i in items):
        due, phrase = resolve_deadline(text, base)
        if due:
            items[0] = ActionItem(items[0].text, due, phrase)
    return items
