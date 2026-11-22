"""User rules: turn triage results into IMAP actions.

    rules:
      - when: {phishing: ">= 0.7"}
        do: {move: Quarantine, flag: true}
      - when: {category: [newsletter, promotion]}
        do: {move: Later}
      - when: {priority: ">= 0.75"}
        do: {flag: true}

Rules are checked in order. Flags accumulate; the first matching ``move`` wins, so
a message can never be moved twice. The default rules quarantine phishing first.
"""

from __future__ import annotations

import operator
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .classify import CATEGORIES, REVIEW
from .imap import quote_mailbox

_CMP = re.compile(r"^\s*(>=|<=|>|<|==)\s*(\d+(\.\d+)?)\s*$")
_OPS = {">=": operator.ge, "<=": operator.le, ">": operator.gt, "<": operator.lt, "==": operator.eq}
NUMERIC = ("phishing", "priority", "confidence")
DEFAULT_RULES = [
    {"when": {"phishing": ">= 0.7"}, "do": {"move": "Quarantine", "flag": True}},
    {"when": {"category": ["newsletter", "promotion"]}, "do": {"move": "Later"}},
    {"when": {"priority": ">= 0.75"}, "do": {"flag": True}},
]


class RuleError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    when: dict[str, Any]
    move: str | None
    flag: bool

    def matches(self, msg: dict[str, Any]) -> bool:
        for key, cond in self.when.items():
            if key == "category":
                allowed = cond if isinstance(cond, list) else [cond]
                if msg.get("category") not in allowed:
                    return False
            elif key == "from_domain":
                domains = cond if isinstance(cond, list) else [cond]
                addr = str(msg.get("from_addr", "")).lower()
                if not any(addr.endswith("@" + d.lower()) for d in domains):
                    return False
            else:
                op, value = _parse_cmp(key, cond)
                field = {"phishing": "phishing_score"}.get(key, key)
                if not op(float(msg.get(field) or 0.0), value):
                    return False
        return True


def _parse_cmp(key: str, cond: Any):
    m = _CMP.match(str(cond))
    if not m:
        raise RuleError(f"{key}: expected a comparison like '>= 0.7', got {cond!r}")
    return _OPS[m[1]], float(m[2])


def parse(data: Any) -> list[Rule]:
    items = data.get("rules") if isinstance(data, dict) else data
    if not isinstance(items, list) or not items:
        raise RuleError("rules must be a non-empty list")
    rules = []
    for i, item in enumerate(items):
        if not isinstance(item, dict) or set(item) - {"when", "do"}:
            raise RuleError(f"rule {i}: expected keys 'when' and 'do'")
        when, do = item.get("when") or {}, item.get("do") or {}
        unknown = set(when) - {"category", "from_domain", *NUMERIC}
        if unknown:
            raise RuleError(f"rule {i}: unknown condition(s) {sorted(unknown)}")
        for key in NUMERIC:
            if key in when:
                _parse_cmp(key, when[key])
        if "category" in when:
            cats = when["category"] if isinstance(when["category"], list) else [when["category"]]
            bad = set(cats) - {*CATEGORIES, REVIEW}
            if bad:
                raise RuleError(f"rule {i}: unknown category {sorted(bad)}")
        if set(do) - {"move", "flag"} or not do:
            raise RuleError(f"rule {i}: 'do' supports move and flag")
        move = do.get("move")
        if move is not None:
            quote_mailbox(str(move))  # validates the folder name
        rules.append(Rule(when=dict(when), move=str(move) if move else None, flag=bool(do.get("flag", False))))
    return rules


def load(path: str | Path | None) -> list[Rule]:
    if path is None:
        return parse(DEFAULT_RULES)
    return parse(yaml.safe_load(Path(path).read_text(encoding="utf-8")))


def plan(msg: dict[str, Any], rules: list[Rule]) -> list[str]:
    """Actions for one stored message, e.g. ['flag', 'move:Quarantine']."""
    flag = False
    move: str | None = None
    for rule in rules:
        if rule.matches(msg):
            flag = flag or rule.flag
            if move is None and rule.move:
                move = rule.move
    out = ["flag"] if flag else []
    if move:
        out.append(f"move:{move}")
    return out
