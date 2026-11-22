import json
from datetime import date

import pytest

from triage.actions import extract, resolve_deadline
from triage.classify import CATEGORIES, REVIEW, Classifier, evaluate, load_corpus
from triage.mail import Mail, from_fields
from triage.priority import Profile, score
from triage.summarize import Summarizer, extractive

MON = date(2026, 11, 23)  # a Monday


@pytest.fixture(scope="module")
def clf():
    return Classifier.default()


def test_corpus_is_balanced_and_disjoint():
    train, held = load_corpus("train.jsonl"), load_corpus("heldout.jsonl")
    assert {c: sum(lab == c for _, lab in train) for c in CATEGORIES} == dict.fromkeys(CATEGORIES, 12)
    assert {c: sum(lab == c for _, lab in held) for c in CATEGORIES} == dict.fromkeys(CATEGORIES, 6)
    assert not {m.subject for m, _ in train} & {m.subject for m, _ in held}


def test_heldout_quality_does_not_regress():
    r = evaluate(load_corpus("train.jsonl"), load_corpus("heldout.jsonl"))
    # Recorded result: accuracy 0.933, macro-F1 0.935 (2 of 30 sent to review).
    assert r["accuracy"] >= 0.9 and r["macro_f1"] >= 0.9
    assert r["n_test"] == 30 and sum(map(sum, r["confusion"]["matrix"])) == 30


def test_low_confidence_goes_to_review(clf):
    strict = Classifier(threshold=0.99).fit(load_corpus("train.jsonl"))
    assert strict.predict([from_fields("a@b.c", "hello", "hello")])[0].category == REVIEW


def test_corrections_teach_the_classifier():
    mail = from_fields("Build Bot <bot@ci.example>", "Weekly flaky test report", "Here is your weekly report.")
    before = Classifier.default().predict([mail])[0]
    after = Classifier.default(corrections=[(mail, "notification")]).predict([mail])[0]
    assert after.category == "notification" and after.scores["notification"] > before.scores["notification"]


def test_unknown_category_rejected():
    with pytest.raises(ValueError):
        Classifier().fit([(Mail(), "spam")])


def test_predict_before_fit_fails():
    with pytest.raises(RuntimeError):
        Classifier().predict([Mail()])


@pytest.mark.parametrize(
    ("sentence", "due"),
    [
        ("approve it by Thursday", date(2026, 11, 26)),
        ("send it today please", MON),
        ("needs it by EOD", MON),
        ("I start tomorrow", date(2026, 11, 24)),
        ("please finish this week", date(2026, 11, 27)),
        ("anytime next week", date(2026, 12, 4)),
        ("due 2026-12-01", date(2026, 12, 1)),
        ("before 30 November", date(2026, 11, 30)),
        ("by December 3rd", date(2026, 12, 3)),
        ("portal closes on the 15th", date(2026, 12, 15)),
        ("by Monday", date(2026, 11, 30)),  # "Monday" on a Monday means next week
        ("by 15 January", date(2027, 1, 15)),
        ("no date here", None),
    ],
)
def test_deadlines(sentence, due):
    assert resolve_deadline(sentence, MON)[0] == due


def test_extract_requests_and_neighbouring_deadline():
    items = extract("Hi. Could you approve the budget? Finance needs it by Friday. Thanks!", MON)
    assert len(items) == 1 and items[0].due == date(2026, 11, 27) and items[0].text.startswith("Could you")
    assert extract("This is an automated message, please do not reply.", MON) == []


def test_priority_reasons_and_phishing_override():
    mail = Mail(from_addr="ceo@acme.com", to=["me@acme.com"], subject="Board deck", text="")
    items = extract("Can you send the deck by tomorrow?", MON)
    prof = Profile(me=("me@acme.com",), vip_senders=("@acme.com",), vip_keywords=("board",))
    p = score(mail, "action", items, 0.0, prof, MON)
    assert p.score == 1.0
    assert any("VIP" in r for r in p.reasons) and any("due today or tomorrow" in r for r in p.reasons)
    assert score(mail, "action", items, 0.9, prof, MON).score == 0.0
    cc = Mail(from_addr="x@y.com", cc=["me@acme.com"])
    assert score(cc, "newsletter", [], 0.0, prof, MON).score == 0.0
    alert = Mail(from_addr="no-reply@sns.amazonaws.com", subject="ALARM: high CPU")
    assert score(alert, "notification", [], 0.0, Profile(), MON).score == 0.5


def test_extractive_summary_skips_greetings_and_boilerplate():
    m = Mail(
        subject="S",
        text="Hi Ana,\nYou are receiving this because you subscribed.\nThe release moved to Friday at noon.",
    )
    assert extractive(m) == "The release moved to Friday at noon."
    assert extractive(Mail(subject="Only a subject", text="")) == "Only a subject"
    long = Mail(text="word " * 100)
    assert len(extractive(long)) <= 160 and extractive(long).endswith("…")


def test_llm_summary_and_fallbacks():
    calls = []

    def good(url, payload, timeout):
        calls.append((url, payload))
        return {"response": json.dumps({"summary": "Approve the budget by Friday."})}

    s = Summarizer(model="llama3.2", transport=good)
    m = Mail(subject="Budget", text="Could you approve the budget by Friday?")
    assert s.summarize(m) == "Approve the budget by Friday."
    assert calls[0][0] == "http://127.0.0.1:11434/api/generate" and calls[0][1]["format"] == "json"

    for bad in ({"response": "not json"}, {"response": json.dumps({"summary": ""})}, {"response": "[1]"}):
        s = Summarizer(model="m", transport=lambda u, p, t, bad=bad: bad)
        assert s.summarize(m) == extractive(m) and s.fallbacks == 1

    def down(url, payload, timeout):
        raise OSError("connection refused")

    assert Summarizer(model="m", transport=down).summarize(m) == extractive(m)
    assert Summarizer(model="").summarize(m) == extractive(m)


def test_llm_url_must_be_local():
    with pytest.raises(ValueError, match="local"):
        Summarizer(model="m", url="https://api.example.com/api/generate")
