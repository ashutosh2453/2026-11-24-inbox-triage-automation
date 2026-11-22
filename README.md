# Inbox Triage Automation

[![CI](https://github.com/ashutosh2453/2026-11-24-inbox-triage-automation/actions/workflows/ci.yml/badge.svg)](https://github.com/ashutosh2453/2026-11-24-inbox-triage-automation/actions/workflows/ci.yml)

Local-first email triage over IMAP. It reads new mail without marking it read and:
- flags phishing, with the reasons;
- sorts each message into a category;
- finds what you're being asked to do and by when;
- ranks messages by priority, explaining why;
- files them with your rules.

Everything runs on your machine with SQLite. Summaries can use a **local** LLM through Ollama, so no mail is sent to a paid API.

```
IMAP (BODY.PEEK, by UID) ──► parse MIME ──┬─► phishing signals ──► score + reasons
                                          ├─► classifier ────────► category (or "review")
                                          ├─► requests + deadlines
                                          ├─► priority + reasons
                                          └─► summary (Ollama JSON → extractive fallback)
                                                        │
                                         SQLite (sync state, results, corrections, audit)
                                                        │
                                rules.yaml ──► flag / move (dry run by default) ──► IMAP
                                                        └──► Markdown / HTML digest
```

## Example

```text
$ triage file examples/*.eml
examples/action-budget.eml: 'Sign-off needed on the vendor budget'
  category action (0.71)  priority 0.70
  phishing clean (0.00)
  action: Could you review the vendor budget sheet and approve it by Wednesday? (due 2026-11-25)
  summary: Could you review the vendor budget sheet and approve it by Wednesday?
examples/phish-paypal.eml: 'Your account has been limited - verify within 24 hours'
  category review (0.34)  priority 0.00
  phishing phishing (0.99)
    - sender domain 'paypa1-support.com' imitates 'paypal.com'
    - display name says 'paypal' but the sender domain is 'paypa1-support.com'
    - link text shows 'www.paypal.com' but points to '185.243.115.7'
    - dmarc, spf failed for the sender
    - link points to a raw IP address (185.243.115.7)
    - replies go to 'secure-mailbox.ru', not 'paypa1-support.com'
    - asks for a password, OTP or card details
    - pressure language (deadline or account threat)
  action: Please confirm your password and card number to restore access.
  summary: We noticed unusual activity.
```

The priority of the first email depends on the day you run it, because the deadline is compared with today.

## How well does it classify?

The repo includes a hand-written, labelled corpus: 60 training emails and 30 **held-out** emails across 5 balanced categories (action, meeting, notification, newsletter, promotion), with no overlap.
- Settings were chosen with repeated 5-fold cross-validation on the training set only.
- The held-out set was scored once, after that.

| Metric (held-out, n=30) | Value |
|---|---|
| Accuracy | **0.933** |
| Macro-F1 | **0.935** |
| Sent to `review` (low confidence) | 2 |
| Accuracy of auto-filed mail | 0.929 |

The two misses are listed by `triage eval`:
- "Dinner on Saturday" (meeting, predicted action);
- an npm publish notice (notification, predicted action, sent to review).

The corpus is small and written by one author, so expect lower accuracy on real mail. That's why `triage correct` exists, and corrections are included in the next retraining. Every email in both corpora is classed clean by the phishing check, so it raises no false alarms on them.

## Phishing signals

| Signal | Example |
|---|---|
| Display-name spoof | "PayPal Security" sending from `paypa1-support.com` |
| Lookalike domain (sender or link) | `paypa1`, `rnicrosoft`, `paypal-security`, `secure-hdfcbank-login` |
| Link text ≠ destination | text `www.paypal.com`, href `http://185.243.115.7/...` |
| Raw-IP, punycode, shortened links | `http://185…`, `xn--…`, `bit.ly` |
| Reply-To on another domain | replies go to `secure-mailbox.ru` |
| SPF/DKIM/DMARC failed | only from **our** receiving server's `Authentication-Results` (topmost, or `TRIAGE_AUTHSERV_ID`); a forged header added by the sender is ignored |
| Risky attachments | `.exe .js .html .iso .lnk …`, double extensions such as `invoice.pdf.exe` |
| Pressure and credential requests | "verify within 24 hours", "confirm your password" |

The score is `1 − Π(1 − w)` over the signals that fire: ≥ 0.7 is phishing and is quarantined; ≥ 0.4 is suspicious.

## Usage

```bash
pip install -e .
triage eval                                       # held-out metrics
triage file examples/*.eml                        # no server needed

export TRIAGE_IMAP_PASSWORD='app-password'        # never accepted on the command line
triage sync  --host imap.example.com --user me@example.com --vip @mycompany.com
triage apply --host imap.example.com --user me@example.com --rules examples/rules.yaml           # dry run
triage apply --host imap.example.com --user me@example.com --rules examples/rules.yaml --apply   # do it
triage digest --html digest.html
triage correct --uid 1234 --category action       # used on the next sync

export TRIAGE_OLLAMA_MODEL=llama3.2               # optional local LLM summaries
```

Rules (`examples/rules.yaml`):

```yaml
rules:
  - when: {phishing: ">= 0.7"}
    do: {move: Quarantine, flag: true}
  - when: {category: [newsletter, promotion]}
    do: {move: Later}
  - when: {priority: ">= 0.75"}
    do: {flag: true}
```

## Safety properties (all tested)

- **Sync is read-only.** It uses a read-only `SELECT` and `BODY.PEEK[]`, so nothing is marked read.
- **Sync is incremental by UID.** If the server changes UIDVALIDITY, that mailbox is resynced from scratch rather than mismatching UIDs.
- **`apply` is a dry run unless you pass `--apply`.** Every action is logged to the audit table, and a message is never processed twice.
- **Moves never touch other mail.** They use `UID MOVE`, or COPY plus `UID EXPUNGE` of that single UID. A bare `EXPUNGE`, which would also purge messages you deleted yourself, is refused.
- **No IMAP command injection.** Mailbox names and flags are validated.
- **The LLM URL must be loopback**, so mail never leaves the machine.
- **The HTML digest escapes every field**, including subjects such as `<img onerror=…>`.

## Tests

- 75 unit tests, using an in-memory fake IMAP server.
- A CI job runs **GreenMail**, a real IMAP and SMTP server. It delivers the four example emails over SMTP, then runs `sync` and `apply --apply`. The phishing email lands in `Quarantine`, the newsletter in `Later`, and the other two stay in the inbox.

```bash
docker run -p 3025:3025 -p 3143:3143 -e GREENMAIL_OPTS="-Dgreenmail.setup.test.smtp -Dgreenmail.setup.test.imap -Dgreenmail.hostname=0.0.0.0 -Dgreenmail.auth.disabled" greenmail/standalone:2.1.3
TRIAGE_IT_HOST=127.0.0.1 pytest tests/test_greenmail.py
```

## Limits

- Requests and deadlines are found with English rules: predictable, but they miss indirect asks.
- The lookalike check covers a fixed list of commonly impersonated brands.
- There's no OAuth2 (XOAUTH2) login yet. Gmail and Outlook need an app password.

## License

MIT
