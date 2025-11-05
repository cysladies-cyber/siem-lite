"""Authentication helpers."""
from __future__ import annotations

import secrets
import time
from typing import Dict, Optional

from flask import session

from models import register_session, verify_user

# simple in-memory rate limiter
_ATTEMPTS: Dict[str, list[float]] = {}
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 300


def _cleanup(ip: str) -> None:
    attempts = _ATTEMPTS.get(ip, [])
    cutoff = time.time() - WINDOW_SECONDS
    _ATTEMPTS[ip] = [ts for ts in attempts if ts >= cutoff]


def can_attempt(ip: str) -> bool:
    _cleanup(ip)
    return len(_ATTEMPTS.get(ip, [])) < MAX_ATTEMPTS


def register_attempt(ip: str) -> None:
    _ATTEMPTS.setdefault(ip, []).append(time.time())


def login_user(email: str, password: str, ip: str) -> Optional[Dict[str, str]]:
    if not can_attempt(ip):
        return None
    user = verify_user(email, password)
    if not user:
        register_attempt(ip)
        return None
    token = secrets.token_urlsafe(32)
    register_session(user_id=user["id"], token=token)
    session["user"] = {
        "id": user["id"],
        "email": user["email"],
        "role": user["role"],
        "token": token,
    }
    return session["user"]


def current_user() -> Optional[Dict[str, str]]:
    user = session.get("user")
    if user and isinstance(user, dict):
        return user
    return None


def require_role(role: str) -> bool:
    user = current_user()
    if not user:
        return False
    allowed_roles = {role}
    if role == "analyst":
        allowed_roles = {"analyst", "admin"}
    return user["role"] in allowed_roles


def logout_user() -> None:
    session.pop("user", None)
