"""triage command line.

triage eval                                   held-out classifier metrics
triage file examples/*.eml                    triage local .eml files (no server needed)
triage sync  --host imap.example.com --user me@example.com     (password: TRIAGE_IMAP_PASSWORD)
triage apply --host ... --user ... [--rules rules.yaml] [--apply]
triage digest [--html digest.html]
triage correct --uid 42 --category action     teach the classifier; used on the next sync
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from . import __version__
from . import rules as rules_mod
from .classify import CATEGORIES, Classifier, evaluate, load_corpus
from .digest import markdown, to_html
from .imap import ImapClient, ImapError
from .mail import parse
from .pipeline import triage_many
from .priority import Profile
from .store import Store
from .summarize import Summarizer

PASSWORD_ENV = "TRIAGE_IMAP_PASSWORD"  # noqa: S105 (name of an env var, not a secret)


def _profile(args) -> Profile:
    return Profile(
        me=tuple(args.me or ([args.user] if getattr(args, "user", None) else [])),
        vip_senders=tuple(args.vip or []),
        vip_keywords=tuple(args.keyword or []),
    )


def _server_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int)
    p.add_argument("--user", required=True)
    p.add_argument("--mailbox", default="INBOX")
    p.add_argument("--no-ssl", action="store_true", help="plain IMAP (local test servers only)")


def _profile_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--me", action="append", help="your address(es); defaults to --user")
    p.add_argument("--vip", action="append", help="VIP sender address or @domain (repeatable)")
    p.add_argument("--keyword", action="append", help="keyword that raises priority (repeatable)")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="triage", description="Local-first inbox triage")
    ap.add_argument("--version", action="version", version=f"triage {__version__}")
    ap.add_argument("--db", default=os.environ.get("TRIAGE_DB", "triage.sqlite3"))
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("eval", help="train on the bundled corpus, score the held-out set")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("file", help="triage local .eml files")
    p.add_argument("paths", nargs="+")
    p.add_argument("--json", action="store_true")
    _profile_args(p)

    p = sub.add_parser("sync", help="fetch new mail over IMAP, triage it and store results")
    _server_args(p)
    _profile_args(p)
    p.add_argument("--limit", type=int, default=500, help="max new messages per run")

    p = sub.add_parser("apply", help="run rules against stored results (dry run unless --apply)")
    _server_args(p)
    p.add_argument("--rules", help="rules.yaml (default: quarantine phishing, file newsletters, flag urgent)")
    p.add_argument("--apply", action="store_true")

    p = sub.add_parser("digest", help="summary of stored results")
    p.add_argument("--html", help="write an HTML digest to this path")
    p.add_argument("--mailbox")

    p = sub.add_parser("correct", help="record the right category for a message")
    p.add_argument("--uid", type=int, required=True)
    p.add_argument("--category", required=True, choices=CATEGORIES)
    p.add_argument("--mailbox", default="INBOX")
    return ap


def _connect(args) -> ImapClient:
    password = os.environ.get(PASSWORD_ENV)
    if not password:
        raise SystemExit(f"error: set {PASSWORD_ENV} (the password is never accepted on the command line)")
    port = args.port or (143 if args.no_ssl else 993)
    return ImapClient.connect(args.host, port, args.user, password, use_ssl=not args.no_ssl)


def cmd_eval(args, out) -> int:
    r = evaluate(load_corpus("train.jsonl"), load_corpus("heldout.jsonl"))
    if args.json:
        print(json.dumps({k: v for k, v in r.items() if k != "report"}, indent=2), file=out)
        return 0
    print(f"train {r['n_train']} / held-out {r['n_test']}", file=out)
    print(f"accuracy {r['accuracy']}  macro-F1 {r['macro_f1']}", file=out)
    print(f"sent to review {r['sent_to_review']}, accuracy of auto-filed {r['auto_filed_accuracy']}", file=out)
    print(r["report"], file=out)
    for err in r["errors"]:
        print(f"  miss: {err['subject']!r} true={err['true']} pred={err['pred']} conf={err['confidence']}", file=out)
    return 0


def cmd_file(args, out) -> int:
    mails = [parse(Path(p).read_bytes()) for p in args.paths]
    results = triage_many(mails, Classifier.default(), _profile(args), Summarizer())
    if args.json:
        rows = [
            {"path": p, "subject": m.subject, **asdict(r)} for p, m, r in zip(args.paths, mails, results, strict=True)
        ]
        print(json.dumps(rows, indent=2), file=out)
        return 0
    for path, mail, r in zip(args.paths, mails, results, strict=True):
        print(f"{path}: {mail.subject!r}", file=out)
        print(f"  category {r.category} ({r.confidence:.2f})  priority {r.priority:.2f}", file=out)
        print(f"  phishing {r.phishing_label} ({r.phishing_score:.2f})", file=out)
        for reason in r.phishing_reasons:
            print(f"    - {reason}", file=out)
        for a in r.actions:
            print(f"  action: {a['text']}" + (f" (due {a['due']})" if a["due"] else ""), file=out)
        print(f"  summary: {r.summary}", file=out)
    return 0


def cmd_sync(args, out) -> int:
    store = Store(args.db)
    client = _connect(args)
    try:
        uidvalidity = client.select(args.mailbox, readonly=True)
        last = store.last_uid(args.mailbox, uidvalidity)
        uids = client.uids_after(last)[: args.limit]
        fetched = list(client.fetch(uids))
    finally:
        client.logout()
    mails = [parse(raw, uid=uid) for uid, raw in fetched]
    classifier = Classifier.default(corrections=store.corrections())
    summarizer = Summarizer()
    results = triage_many(mails, classifier, _profile(args), summarizer)
    for mail, result in zip(mails, results, strict=True):
        store.save(args.mailbox, uidvalidity, mail, result)
        store.set_last_uid(args.mailbox, uidvalidity, int(mail.uid or 0))
    phishing = sum(r.phishing_label == "phishing" for r in results)
    llm = f", llm summaries {summarizer.used_llm}, fallbacks {summarizer.fallbacks}" if summarizer.model else ""
    print(
        f"synced {len(mails)} new message(s) from {args.mailbox} (after uid {last}); {phishing} phishing{llm}", file=out
    )
    store.close()
    return 0


def cmd_apply(args, out) -> int:
    store = Store(args.db)
    rules = rules_mod.load(args.rules)
    pending = store.messages(args.mailbox, pending_only=True)
    plans = [(m, rules_mod.plan(m, rules)) for m in pending]
    plans = [(m, p) for m, p in plans if p]
    mode = "applying" if args.apply else "dry run"
    print(f"{len(plans)} message(s) with actions ({mode}):", file=out)
    for m, p in plans:
        print(f"  uid {m['uid']:>6}  {', '.join(p):<28} {m['subject'][:60]}", file=out)
    if not args.apply or not plans:
        for m, p in plans:
            store.mark_applied(m["mailbox"], m["uidvalidity"], m["uid"], p, dry_run=True)
        store.close()
        return 0
    client = _connect(args)
    try:
        uidvalidity = client.select(args.mailbox, readonly=False)
        for m, p in plans:
            if m["uidvalidity"] != uidvalidity:
                print(f"  skip uid {m['uid']}: mailbox UIDVALIDITY changed", file=out)
                continue
            for action in p:  # flag before move: the UID changes once a message moves
                if action == "flag":
                    client.flag(m["uid"])
                elif action.startswith("move:"):
                    target = action.split(":", 1)[1]
                    step = f"copied:{target}"
                    key = (m["mailbox"], m["uidvalidity"], m["uid"])
                    client.move(
                        m["uid"],
                        target,
                        already_copied=store.has_step(*key, step),
                        on_copied=lambda key=key, step=step: store.record_step(*key, step),
                    )
            store.mark_applied(m["mailbox"], m["uidvalidity"], m["uid"], p, dry_run=False)
    finally:
        client.logout()
        store.close()
    return 0


def cmd_digest(args, out) -> int:
    store = Store(args.db)
    rows = store.messages(args.mailbox)
    store.close()
    if args.html:
        Path(args.html).write_bytes(to_html(rows).encode("utf-8"))
        print(f"wrote {args.html} ({len(rows)} messages)", file=out)
    else:
        out.write(markdown(rows))
    return 0


def cmd_correct(args, out) -> int:
    store = Store(args.db)
    try:
        row = store.add_correction(args.mailbox, args.uid, args.category)
    finally:
        store.close()
    print(
        f"uid {args.uid} {row['subject']!r}: {row['category']} -> {args.category} (used from the next sync)", file=out
    )
    return 0


COMMANDS = {
    "eval": cmd_eval,
    "file": cmd_file,
    "sync": cmd_sync,
    "apply": cmd_apply,
    "digest": cmd_digest,
    "correct": cmd_correct,
}


def main(argv: list[str] | None = None, out=None) -> int:
    out = out or sys.stdout
    args = build_parser().parse_args(argv)
    try:
        return COMMANDS[args.command](args, out)
    except (ImapError, rules_mod.RuleError, KeyError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
