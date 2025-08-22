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
from .discord_oauth2_client import DiscordOAuth2Client 
# from .discord_authlib_client import DiscordAuthlibClient
from .oauth2_client import Tokens, UserProfile
from . import bp

oauth = DiscordOAuth2Client()
# oauth = DiscordAuthlibClient() 


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


    try:
        tokens: Tokens = oauth.exchange_code()
        profile: UserProfile = oauth.fetch_user(tokens)
    except Exception as e:
        abort(400, f"Token exchange or user fetch failed: {e}")

    session["tokens"] = _pack_tokens(tokens)
    session["user"] = {
        "id": profile.id,
        "username": profile.username,
        "discriminator": profile.discriminator,
        "avatar": profile.avatar,
    }

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