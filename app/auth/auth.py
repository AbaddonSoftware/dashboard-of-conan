# app/auth/auth.py
from __future__ import annotations

from dataclasses import asdict
from urllib.parse import urlparse
from flask import (
    request,
    redirect,
    render_template,
    session,
    url_for,
    abort,
)
import requests
from .discord_oauth2_client import DiscordOAuth2Client 
from .oauth2_client import Tokens, UserProfile
from . import bp


oauth = DiscordOAuth2Client() 


# --- helpers ---------------------------------------------------------------

def _is_safe_next_url(value: str | None) -> bool:
    """Only allow same-origin relative paths to avoid open redirects."""
    if not value:
        return False
    parsed = urlparse(value)
    return parsed.scheme == "" and parsed.netloc == "" and value.startswith("/")

def _pack_tokens(t: Tokens) -> dict:
    # Keep only serializable bits in the session
    return {
        "access_token": t.access_token,
        "refresh_token": t.refresh_token,
        "expires_in": t.expires_in,
        "token_type": t.token_type or "Bearer",
    }

def _unpack_tokens(d: dict | None) -> Tokens | None:
    if not d:
        return None
    return Tokens(
        access_token=d["access_token"],
        refresh_token=d.get("refresh_token"),
        expires_in=d.get("expires_in"),
        token_type=d.get("token_type", "Bearer"),
        raw=d,  # preserve what we stored
    )


# --- routes ----------------------------------------------------------------

@bp.get("/login")
def login():
    # If guard redirected here with ?next=..., pass it through to the template
    next_url = request.args.get("next")
    return render_template("login.html", next_url=next_url)

@bp.get("/start")
def start():  # user clicked the button on /auth/login
    next_param = request.args.get("next")
    if _is_safe_next_url(next_param):
        session["after_login"] = next_param
    else:
        session.pop("after_login", None)
    return oauth.login_redirect()


@bp.get("/callback")
def callback():
    """
    Handles Discord's redirect back.
    - verifies 'state' against the one stored in session
    - exchanges 'code' for tokens
    - fetches the user profile
    - stores minimal auth info in session
    - redirects to saved 'after_login' or dashboard
    """
    err = request.args.get("error")
    if err:
        # You could flash a message here instead.
        abort(400, f"OAuth error from provider: {err}")

    # CSRF state verification
    sent_state = request.args.get("state")
    stored_state = session.pop("oauth_state", None)  # one-time use
    if not sent_state or not stored_state or sent_state != stored_state:
        abort(400, "State mismatch.")

    code = request.args.get("code")
    if not code:
        abort(400, "Missing authorization code.")

    # Exchange code for tokens, then fetch the user
    try:
        tokens: Tokens = oauth.exchange_code(code)
        profile: UserProfile = oauth.fetch_user(tokens)
    except Exception as e:
        abort(400, f"Token exchange or user fetch failed: {e}")

    # Persist minimal auth context in session for your guard/is_authenticated()
    session["tokens"] = _pack_tokens(tokens)
    session["user"] = {
        "id": profile.id,
        "username": profile.username,
        "discriminator": profile.discriminator,
        "avatar": profile.avatar,
    }

    # Prefer the URL your guard stored; otherwise go to dashboard
    target = session.pop("after_login", None)
    if not _is_safe_next_url(target):
        target = url_for("dashboard.index")  # ensure this endpoint exists

    return redirect(target)


@bp.get("/logout")
def logout():
    """
    Revokes the refresh_token if present (falls back to access_token),
    clears session, and sends user to the login screen.
    """
    token_dict = session.get("tokens")
    tokens = _unpack_tokens(token_dict)

    # Best-effort revoke; ignore failures
    if tokens:
        try:
            oauth.revoke(tokens)
        except Exception:
            pass

    session.clear()
    return redirect(url_for("auth.login"))