"""Daily digest in Markdown or self-contained HTML (every field escaped)."""

from __future__ import annotations

import html
from typing import Any

ORDER = ["action", "meeting", "review", "notification", "newsletter", "promotion"]


def _sections(rows: list[dict[str, Any]]) -> tuple[list[dict], dict[str, list[dict]]]:
    quarantine = [r for r in rows if r["phishing_label"] == "phishing"]
    rest = [r for r in rows if r["phishing_label"] != "phishing"]
    groups: dict[str, list[dict]] = {c: [] for c in ORDER}
    for r in rest:
        groups.setdefault(r["category"], []).append(r)
    return quarantine, {k: sorted(v, key=lambda r: -r["priority"]) for k, v in groups.items() if v}


def markdown(rows: list[dict[str, Any]]) -> str:
    quarantine, groups = _sections(rows)
    lines = [f"# Inbox digest: {len(rows)} message(s)", ""]
    if quarantine:
        lines += [f"## ⚠️ Quarantined as phishing ({len(quarantine)})", ""]
        for r in quarantine:
            lines.append(f"- **{r['subject']}** from `{r['from_addr']}` (score {r['phishing_score']:.2f})")
            lines += [f"  - {reason}" for reason in r["phishing_reasons"]]
        lines.append("")
    for cat, items in groups.items():
        lines += [f"## {cat.title()} ({len(items)})", ""]
        for r in items:
            warn = " ⚠️ suspicious" if r["phishing_label"] == "suspicious" else ""
            lines.append(f"- [{r['priority']:.2f}] **{r['subject']}** from {r['from_name'] or r['from_addr']}{warn}")
            if r["summary"]:
                lines.append(f"  - {r['summary']}")
            for a in r["actions"]:
                due = f" (due {a['due']})" if a.get("due") else ""
                lines.append(f"  - [ ] {a['text']}{due}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def to_html(rows: list[dict[str, Any]]) -> str:
    e = html.escape
    quarantine, groups = _sections(rows)
    parts = [
        "<!doctype html><html lang=en><meta charset=utf-8>",
        "<meta name=viewport content='width=device-width,initial-scale=1'>",
        "<title>Inbox digest</title><style>",
        "body{font:15px/1.5 system-ui,sans-serif;max-width:860px;margin:2rem auto;padding:0 1rem;color:#1d1d1f}",
        "h2{margin-top:2rem;border-bottom:1px solid #ddd}.p{font-variant-numeric:tabular-nums;color:#555}",
        ".q{background:#fff4f2;border-left:4px solid #c62828;padding:.5rem 1rem}.s{color:#b26a00}",
        "li{margin:.4rem 0}small{color:#666}",
        "@media(prefers-color-scheme:dark){body{background:#111;color:#eee}.q{background:#2a1513}h2{border-color:#333}}",
        "</style>",
        f"<h1>Inbox digest: {len(rows)} message(s)</h1>",
    ]
    if quarantine:
        parts.append(f"<section class=q><h2>Quarantined as phishing ({len(quarantine)})</h2><ul>")
        for r in quarantine:
            reasons = "".join(f"<li>{e(x)}</li>" for x in r["phishing_reasons"])
            parts.append(
                f"<li><b>{e(r['subject'])}</b> <small>{e(r['from_addr'])}, "
                f"score {r['phishing_score']:.2f}</small><ul>{reasons}</ul></li>"
            )
        parts.append("</ul></section>")
    for cat, items in groups.items():
        parts.append(f"<h2>{e(cat.title())} ({len(items)})</h2><ul>")
        for r in items:
            warn = " <span class=s>suspicious</span>" if r["phishing_label"] == "suspicious" else ""
            acts = "".join(
                f"<li>☐ {e(a['text'])}{' <small>due ' + e(a['due']) + '</small>' if a.get('due') else ''}</li>"
                for a in r["actions"]
            )
            parts.append(
                f"<li><span class=p>[{r['priority']:.2f}]</span> <b>{e(r['subject'])}</b> "
                f"<small>{e(r['from_name'] or r['from_addr'])}</small>{warn}"
                f"<br>{e(r['summary'])}{'<ul>' + acts + '</ul>' if acts else ''}</li>"
            )
        parts.append("</ul>")
    parts.append("</html>")
    return "\n".join(parts)
