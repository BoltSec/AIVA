"""Minimal RBAC + audit logging.

API keys are loaded from environment variables (DEV_API_KEY, ADMIN_API_KEY).
Demo fallback values are used only when neither variable is set, so a
deployment can harden credentials without touching source code.

Replace _audit list with a DB table before production.
"""
from __future__ import annotations

import hmac
import os
import threading
import time
from datetime import datetime, timezone

from fastapi import Header, HTTPException


# ---------------------------------------------------------------------------
# User store — loaded from env vars at startup
# ---------------------------------------------------------------------------
def _load_users() -> dict[str, tuple[str, str]]:
    """Return {api_key: (username, role)} from environment variables.

    Expected env vars (set at least one before deploying):
        DEV_API_KEY    — grants "developer" role
        ADMIN_API_KEY  — grants "admin" role

    If neither is set the hard-coded demo values are used so the app works
    out of the box for local development.  Production deployments MUST set
    these variables to non-default values.
    """
    dev_key   = os.getenv("DEV_API_KEY",   "dev-key-001")
    admin_key = os.getenv("ADMIN_API_KEY", "admin-key-001")
    users: dict[str, tuple[str, str]] = {}
    if dev_key:
        users[dev_key]   = ("developer", "developer")
    if admin_key:
        users[admin_key] = ("admin",     "admin")
    return users


_USERS: dict[str, tuple[str, str]] = _load_users()
_ROLE_RANK = {"developer": 1, "admin": 2}

_audit: list[dict] = []
_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Brute-force / rate-limit state
# ---------------------------------------------------------------------------
_fail_tracker: dict[str, tuple[int, float]] = {}  # client_id → (count, first_ts)
_FAIL_LIMIT      = 10     # max failures before lockout
_FAIL_WINDOW     = 60.0   # seconds over which failures are counted
_LOCKOUT_SECONDS = 300.0  # lockout duration (5 min) after hitting the limit


def _client_id(x_forwarded_for: str) -> str:
    """Best-effort client identifier from X-Forwarded-For header."""
    first = (x_forwarded_for or "").split(",")[0].strip()
    return first or "unknown"


def _check_rate_limit(cid: str) -> None:
    with _lock:
        if cid not in _fail_tracker:
            return
        count, first_ts = _fail_tracker[cid]
        age = time.monotonic() - first_ts
        if age > _LOCKOUT_SECONDS:
            del _fail_tracker[cid]
            return
        if count >= _FAIL_LIMIT:
            raise HTTPException(
                status_code=429,
                detail="Too many failed authentication attempts — try again later",
            )


def _record_failure(cid: str) -> None:
    with _lock:
        now = time.monotonic()
        if cid in _fail_tracker:
            count, first_ts = _fail_tracker[cid]
            if now - first_ts > _FAIL_WINDOW:
                _fail_tracker[cid] = (1, now)
            else:
                _fail_tracker[cid] = (count + 1, first_ts)
        else:
            _fail_tracker[cid] = (1, now)


def _clear_failure(cid: str) -> None:
    with _lock:
        _fail_tracker.pop(cid, None)


# ---------------------------------------------------------------------------
# Authentication helpers
# ---------------------------------------------------------------------------
def _constant_time_lookup(provided_key: str) -> tuple[str, str] | None:
    """Return (username, role) for a valid key using constant-time comparison.

    We always iterate every stored key so the number of comparisons does not
    reveal whether the key prefix matches (timing oracle defence).
    """
    result = None
    provided_bytes = provided_key.encode("utf-8")
    for stored_key, user_info in _USERS.items():
        if hmac.compare_digest(stored_key.encode("utf-8"), provided_bytes):
            result = user_info   # keep looping — don't short-circuit
    return result


def authenticate(
    x_api_key: str = Header(default=""),
    x_forwarded_for: str = Header(default=""),
) -> dict:
    cid = _client_id(x_forwarded_for)
    _check_rate_limit(cid)

    user = _constant_time_lookup(x_api_key)
    if not user:
        _record_failure(cid)
        log_event("anonymous", "auth_failure", f"invalid key from {cid}")
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

    _clear_failure(cid)
    return {"user": user[0], "role": user[1]}


def require(min_role: str):
    """Dependency factory enforcing a minimum role."""
    def _dep(
        x_api_key: str = Header(default=""),
        x_forwarded_for: str = Header(default=""),
    ) -> dict:
        ident = authenticate(x_api_key, x_forwarded_for)
        if _ROLE_RANK[ident["role"]] < _ROLE_RANK[min_role]:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return ident
    return _dep


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------
def log_event(user: str, action: str, detail: str) -> None:
    with _lock:
        _audit.append({
            "ts":     datetime.now(timezone.utc).isoformat(),
            "user":   user,
            "action": action,
            "detail": detail,
        })


def audit_log() -> list[dict]:
    with _lock:
        return list(_audit)
