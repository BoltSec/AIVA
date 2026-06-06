"""LLM reasoning layer for AIVA — provider-agnostic, free-tier friendly.

Genuinely *reasons* (vs lookup/compute):
  - per-finding remediation tailored to CVE + host + exploit context
  - an executive triage summary across the ranked set

Works with any OpenAI-compatible endpoint (free providers):
  AIVA_LLM_PROVIDER = gemini | groq | openrouter | ollama | openai

Free-tier survival (this is what fixes the 429 storms):
  - RATE LIMITING: calls are paced to AIVA_LLM_RPM requests/min (default 12),
    so a 30-finding scan no longer fires 30 calls at once.
  - RETRY + BACKOFF: 429/503 are retried with exponential backoff instead of
    instantly falling back to a template.
  - CACHING: each CVE's recommendation is cached to disk, so re-running the
    same scan makes zero new calls.
  - GRACEFUL FALLBACK: only after retries are exhausted does a finding fall
    back to the deterministic template. Scans never crash.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from pathlib import Path

from shared.models import Finding

_PROVIDERS = {
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai/",
               "gemini-2.5-flash", "GEMINI_API_KEY"),
    "groq": ("https://api.groq.com/openai/v1",
             "llama-3.3-70b-versatile", "GROQ_API_KEY"),
    "openrouter": ("https://openrouter.ai/api/v1",
                   "meta-llama/llama-3.3-70b-instruct:free", "OPENROUTER_API_KEY"),
    "ollama": ("http://localhost:11434/v1", "llama3.2", "OLLAMA_API_KEY"),
    "openai": (None, "gpt-4o-mini", "OPENAI_API_KEY"),
}

_CACHE_PATH = Path(__file__).parent / "fixtures" / "llm_cache.json"

_SYSTEM = (
    "You are a senior vulnerability-remediation analyst. Given one finding, "
    "give concise, concrete remediation in 2-3 sentences: the specific fix "
    "(patch, version, or config change), the urgency, and a compensating "
    "control to use if patching must wait. Be specific to the named CVE. If "
    "you state a fixed version, tell the reader to confirm it against the "
    "vendor advisory. No preamble, no markdown, plain prose."
)
_SUMMARY_SYSTEM = (
    "You are briefing a security lead. Given a ranked list of the most urgent "
    "findings, write a 3-4 sentence executive summary: the overall risk "
    "picture, the common themes (e.g. internet-facing RCE, actively exploited), "
    "and what to do first. Plain prose, no markdown, no preamble."
)


def _config():
    provider = os.getenv("AIVA_LLM_PROVIDER", "gemini").lower()
    base_url, default_model, key_env = _PROVIDERS.get(provider, _PROVIDERS["gemini"])
    base_url = os.getenv("AIVA_LLM_BASE_URL", base_url)
    model = os.getenv("AIVA_LLM_MODEL", default_model)
    api_key = os.getenv("AIVA_LLM_API_KEY") or os.getenv(key_env)
    if api_key:
        # strip hidden whitespace (e.g. \xa0 from copy-paste) that would
        # otherwise crash the HTTP header encoding before any call is sent.
        api_key = "".join(api_key.split())
    if provider == "ollama":
        api_key = api_key or "ollama"
    return provider, base_url, model, api_key


def llm_available() -> bool:
    return bool(_config()[3])


def _is_rate_limit(exc: Exception) -> bool:
    s = str(exc).lower()
    code = getattr(exc, "status_code", None)
    return code in (429, 503) or "429" in s or "503" in s \
        or "rate" in s or "too many" in s or "overloaded" in s or "unavailable" in s


class _RateLimiter:
    """Spaces calls to at most `rpm` per minute across all coroutines."""
    def __init__(self, rpm: int):
        self._interval = 60.0 / max(1, rpm)
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def wait(self, skip_if=None):
        if skip_if and skip_if():
            return
        async with self._lock:
            if skip_if and skip_if():
                return
            now = time.monotonic()
            sleep = max(0.0, self._next - now)
            self._next = max(now, self._next) + self._interval
        # interruptible sleep: re-check the breaker every 0.5s so a tripped
        # provider doesn't leave waiters stuck in a long pre-assigned sleep.
        end = time.monotonic() + sleep
        while True:
            remaining = end - time.monotonic()
            if remaining <= 0:
                return
            if skip_if and skip_if():
                return
            await asyncio.sleep(min(0.5, remaining))


class LLMReasoner:
    def __init__(self):
        from openai import AsyncOpenAI
        _, base_url, model, api_key = _config()
        timeout = float(os.getenv("AIVA_LLM_TIMEOUT", "20"))
        self._client = AsyncOpenAI(api_key=api_key, base_url=base_url,
                                   timeout=timeout, max_retries=0)
        self._model = model
        self._rl = _RateLimiter(int(os.getenv("AIVA_LLM_RPM", "12")))
        self._max_retries = int(os.getenv("AIVA_LLM_RETRIES", "2"))
        # circuit breaker: after N consecutive failures, stop calling for this
        # run and use templates — prevents long hangs when the provider is down.
        self._fail_streak = 0
        self._trip_at = int(os.getenv("AIVA_LLM_TRIP", "4"))
        self._disabled = False
        self._cache = self._load_cache()
        self._dirty = False

    def _load_cache(self) -> dict:
        try:
            return json.loads(_CACHE_PATH.read_text())
        except Exception:
            return {}

    def flush(self):
        if self._dirty:
            try:
                _CACHE_PATH.write_text(json.dumps(self._cache, indent=2))
            except Exception:
                pass
            self._dirty = False

    async def _chat(self, system: str, user: str, max_tokens: int) -> str:
        delay = 2.0
        for attempt in range(self._max_retries + 1):
            if self._disabled:
                raise RuntimeError("llm provider disabled for this run")
            await self._rl.wait(skip_if=lambda: self._disabled)
            if self._disabled:
                raise RuntimeError("llm provider disabled for this run")
            try:
                resp = await self._client.chat.completions.create(
                    model=self._model, max_tokens=max_tokens,
                    messages=[{"role": "system", "content": system},
                              {"role": "user", "content": user}])
                self._fail_streak = 0          # success resets the breaker
                return (resp.choices[0].message.content or "").strip()
            except Exception as e:
                self._fail_streak += 1         # count every failed attempt
                if self._fail_streak >= self._trip_at:
                    self._disabled = True      # provider down — stop trying
                    raise
                if attempt < self._max_retries and _is_rate_limit(e):
                    await asyncio.sleep(delay)
                    delay *= 2
                    continue
                raise

    async def recommend(self, f: Finding, fallback: str) -> str:
        key = f"rec::{self._model}::{f.cve}"
        if key in self._cache:
            return self._cache[key]
        if self._disabled:                 # provider tripped — skip the call
            return fallback
        kev = "yes (CISA KEV — actively exploited)" if f.in_kev else "no"
        prompt = (
            f"CVE: {f.cve}\nTitle: {f.name or 'n/a'}\nHost: {f.host}\n"
            f"CVSS base score: {f.cvss}\n"
            f"EPSS (exploitation probability, 0-1): {f.epss:.2f}\n"
            f"Actively exploited: {kev}\n"
            f"Computed priority score: {f.priority_score}\n\nGive the remediation."
        )
        try:
            text = await self._chat(_SYSTEM, prompt, 320) or fallback
        except Exception:
            return fallback
        self._cache[key] = text
        self._dirty = True
        return text

    async def summary(self, findings: list[Finding]) -> str:
        top = findings[:12]
        lines = "\n".join(
            f"- {f.cve} on {f.host}: CVSS {f.cvss}, EPSS {f.epss:.2f}, "
            f"KEV={'yes' if f.in_kev else 'no'}, score {f.priority_score}"
            for f in top)
        key = "sum::" + hashlib.sha1(
            (self._model + lines).encode()).hexdigest()[:16]
        if key in self._cache:
            return self._cache[key]
        try:
            text = await self._chat(_SUMMARY_SYSTEM, f"Findings:\n{lines}", 300)
        except Exception:
            return ""
        self._cache[key] = text
        self._dirty = True
        return text


def build_reasoner() -> "LLMReasoner | None":
    return LLMReasoner() if llm_available() else None
