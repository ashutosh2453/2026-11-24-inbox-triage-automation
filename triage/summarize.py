"""One-line summaries: a local LLM through Ollama when enabled, extractive otherwise.

The LLM is optional and local (no paid API, no mail leaves the machine). Its output
must be JSON matching a tiny schema; anything else, or a timeout, falls back to the
extractive summary, so triage never blocks on the model.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from collections.abc import Callable
from typing import Any

from .mail import Mail

GREETING = re.compile(r"^(hi|hello|hey|dear|good (morning|afternoon|evening)|greetings)\b[^.!?\n]{0,40}[,!.]?\s*", re.I)
BOILERPLATE = re.compile(
    r"(unsubscribe|view (it|this) in your browser|you are receiving this|this (is a|email was) (system|sent)|"
    r"do not reply|privacy policy)",
    re.I,
)
MAX_CHARS = 160
Transport = Callable[[str, dict[str, Any], float], dict[str, Any]]


def extractive(mail: Mail) -> str:
    sentences = re.split(r"(?<=[.!?])\s+|\n+", GREETING.sub("", mail.text.strip()))
    picked = next((s.strip() for s in sentences if len(s.strip()) > 15 and not BOILERPLATE.search(s)), "")
    text = picked or mail.subject
    return text if len(text) <= MAX_CHARS else text[: MAX_CHARS - 1].rsplit(" ", 1)[0] + "…"


def _http_transport(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    req = urllib.request.Request(  # noqa: S310 (local Ollama URL from config)
        url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8"))


class Summarizer:
    def __init__(
        self,
        model: str | None = None,
        url: str | None = None,
        timeout: float = 20.0,
        transport: Transport = _http_transport,
    ) -> None:
        self.model = model if model is not None else os.environ.get("TRIAGE_OLLAMA_MODEL", "")
        self.url = url or os.environ.get("TRIAGE_OLLAMA_URL", "http://127.0.0.1:11434") + "/api/generate"
        if not re.match(r"^http://(127\.0\.0\.1|localhost|\[::1\])(:\d+)?/", self.url):
            raise ValueError("TRIAGE_OLLAMA_URL must point at a local Ollama (mail must not leave the machine)")
        self.timeout = timeout
        self.transport = transport
        self.used_llm = 0
        self.fallbacks = 0

    def summarize(self, mail: Mail) -> str:
        if not self.model:
            return extractive(mail)
        prompt = (
            "Summarize this email in one sentence of at most 25 words for a busy reader. "
            'Reply with JSON only: {"summary": "..."}.\n\n'
            f"From: {mail.from_name} <{mail.from_addr}>\nSubject: {mail.subject}\n\n{mail.text[:4000]}"
        )
        try:
            reply = self.transport(
                self.url,
                {
                    "model": self.model,
                    "prompt": prompt,
                    "format": "json",
                    "stream": False,
                    "options": {"temperature": 0},
                },
                self.timeout,
            )
            data = json.loads(reply.get("response", ""))
            summary = data.get("summary") if isinstance(data, dict) else None
            if not isinstance(summary, str) or not summary.strip() or len(summary) > 400:
                raise ValueError("bad summary")
            self.used_llm += 1
            return " ".join(summary.split())
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            self.fallbacks += 1
            return extractive(mail)
