"""Category classifier: TF-IDF + logistic regression, retrainable from user corrections.

Text alone misses strong structural evidence, so a few header facts are injected as
pseudo-tokens (``__unsub__`` when List-Unsubscribe is present, ``__noreply__`` for
no-reply senders, the sender domain). Low-confidence predictions are labelled
``review`` instead of guessing, so nothing is auto-filed on a coin flip.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib import resources
from typing import Any

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.pipeline import FeatureUnion, Pipeline

from .mail import Mail, from_fields

CATEGORIES = ("action", "meeting", "notification", "newsletter", "promotion")
REVIEW = "review"
TOKENS = r"[\w_]+"  # keeps __pseudo_tokens__ whole
_NOREPLY = re.compile(r"(no-?reply|notifications?|alerts?|mailer-daemon|do-?not-?reply)", re.I)


def features(mail: Mail) -> str:
    local = mail.from_addr.split("@", 1)[0]
    tokens = [f"__dom_{mail.from_domain.replace('.', '_')}__"] if mail.from_domain else []
    if mail.list_unsubscribe:
        tokens.append("__unsub__")
    if mail.auto_submitted:
        tokens.append("__auto__")
    if _NOREPLY.search(local):
        tokens.append("__noreply__")
    if "?" in mail.text:
        tokens.append("__question__")
    return " ".join(tokens) + "\n" + mail.as_text()


def load_corpus(name: str) -> list[tuple[Mail, str]]:
    text = resources.files("triage.data").joinpath(name).read_text(encoding="utf-8")
    rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    return [(from_fields(r["f"], r["s"], r["b"]), r["c"]) for r in rows]


def _pipeline() -> Pipeline:
    return Pipeline(
        [
            (
                "features",
                FeatureUnion(
                    [
                        (
                            "words",
                            TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=1, token_pattern=TOKENS),
                        ),
                        ("chars", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, min_df=2)),
                    ]
                ),
            ),
            ("clf", LogisticRegression(C=10.0, max_iter=2000, class_weight="balanced")),
        ]
    )


@dataclass(frozen=True)
class Prediction:
    category: str
    confidence: float
    scores: dict[str, float]


class Classifier:
    def __init__(self, threshold: float = 0.35) -> None:
        self.threshold = threshold
        self.model: Pipeline | None = None

    def fit(self, examples: list[tuple[Mail, str]]) -> Classifier:
        labels = [label for _, label in examples]
        unknown = set(labels) - set(CATEGORIES)
        if unknown:
            raise ValueError(f"unknown categories: {sorted(unknown)}")
        self.model = _pipeline().fit([features(m) for m, _ in examples], labels)
        return self

    @classmethod
    def default(cls, corrections: list[tuple[Mail, str]] | None = None, **kwargs: Any) -> Classifier:
        """Train on the bundled corpus plus any user corrections (later ones win by repetition)."""
        examples = load_corpus("train.jsonl") + list(corrections or []) * 3
        return cls(**kwargs).fit(examples)

    def predict(self, mails: list[Mail]) -> list[Prediction]:
        if self.model is None:
            raise RuntimeError("classifier is not trained")
        probs = self.model.predict_proba([features(m) for m in mails])
        classes = [str(c) for c in self.model.classes_]
        out = []
        for row in probs:
            i = int(np.argmax(row))
            conf = float(row[i])
            cat = classes[i] if conf >= self.threshold else REVIEW
            out.append(
                Prediction(cat, round(conf, 3), {c: round(float(p), 3) for c, p in zip(classes, row, strict=True)})
            )
        return out


def evaluate(train: list[tuple[Mail, str]], test: list[tuple[Mail, str]], threshold: float = 0.35) -> dict[str, Any]:
    clf = Classifier(threshold=threshold).fit(train)
    preds = clf.predict([m for m, _ in test])
    y_true = [label for _, label in test]
    y_raw = [max(p.scores, key=p.scores.get) for p in preds]
    y_final = [p.category for p in preds]
    labels = list(CATEGORIES)
    return {
        "n_train": len(train),
        "n_test": len(test),
        "accuracy": round(sum(a == b for a, b in zip(y_true, y_raw, strict=True)) / len(test), 3),
        "macro_f1": round(float(f1_score(y_true, y_raw, labels=labels, average="macro")), 3),
        "sent_to_review": sum(c == REVIEW for c in y_final),
        "auto_filed_accuracy": _auto_filed_accuracy(y_true, y_final),
        "confusion": {"labels": labels, "matrix": confusion_matrix(y_true, y_raw, labels=labels).tolist()},
        "report": classification_report(y_true, y_raw, labels=labels, zero_division=0),
        "errors": [
            {"subject": m.subject, "true": t, "pred": r, "confidence": p.confidence}
            for (m, t), r, p in zip(test, y_raw, preds, strict=True)
            if t != r
        ],
    }


def _auto_filed_accuracy(y_true: list[str], y_final: list[str]) -> float | None:
    pairs = [(t, f) for t, f in zip(y_true, y_final, strict=True) if f != REVIEW]
    return round(sum(t == f for t, f in pairs) / len(pairs), 3) if pairs else None
