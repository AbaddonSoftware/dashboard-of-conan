from flask import redirect, session, Response
import requests
import os, secrets
from urllib.parse import urlencode
from .oauth2_client import OAuth2Client, Tokens, UserProfile


DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI")

DISCORD_AUTH_URL = "https://discord.com/api/oauth2/authorize"
DISCORD_TOKEN_URL = "https://discord.com/api/oauth2/token"
DISCORD_REVOKE_URL = "https://discord.com/api/oauth2/token/revoke"
DISCORD_ME_URL = "https://discord.com/api/users/@me"

OAUTH_SCOPES = ["identify", "guilds"]
FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}


class DiscordOAuth2Client(OAuth2Client):
    def login_redirect(self) -> Response:
        state = secrets.token_urlsafe(32)
        session["oauth_state"] = state

        params = {
            "client_id": DISCORD_CLIENT_ID,
            "redirect_uri": DISCORD_REDIRECT_URI,
            "response_type": "code",
            "scope": " ".join(OAUTH_SCOPES),
            "state": state,
            "prompt": "consent",
        }
        query_string = urlencode(params)
        return redirect(f"{DISCORD_AUTH_URL}?{query_string}")

    def exchange_code(self, code: str) -> Tokens:
        data = {
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": DISCORD_REDIRECT_URI,
            "scope": " ".join(OAUTH_SCOPES),
        }
        headers = FORM_HEADERS

        r = requests.post(
            DISCORD_TOKEN_URL,
            data=data,
            headers=headers,
            timeout=10,
        )
        r.raise_for_status()
        payload = r.json()
        return Tokens(
            access_token=payload["access_token"],
            refresh_token=payload.get("refresh_token"),
            expires_in=payload.get("expires_in"),
            token_type=payload.get("token_type", "Bearer"),
            raw=payload,
        )

    def fetch_user(self, tokens: Tokens) -> UserProfile:
        headers = {"Authorization": f"Bearer {tokens.access_token}"}
        r = requests.get(DISCORD_ME_URL, headers=headers, timeout=10)
        r.raise_for_status()
        data = r.json()
        return UserProfile(
            id=str(data["id"]),
            username=data.get("username") or "error with retrieving username",
            discriminator=data.get("discriminator"),
            avatar=data.get("avatar"),
            raw=data,
        )

    def refresh(self, tokens: Tokens) -> Tokens:
        if not tokens.refresh_token:
            raise ValueError("No refresh_token to refresh.")

        data = {
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type": "refresh_token",
            "refresh_token": tokens.refresh_token,
        }
        headers = FORM_HEADERS

        r = requests.post(
            DISCORD_TOKEN_URL,
            data=data,
            headers=headers,
            timeout=10,
        )
        r.raise_for_status()
        payload = r.json()
        return Tokens(
            access_token=payload["access_token"],
            refresh_token=payload.get("refresh_token", tokens.refresh_token),
            expires_in=payload.get("expires_in"),
            token_type=payload.get("token_type", "Bearer"),
            raw=payload,
        )

    def revoke(self, tokens: Tokens) -> None:
        data = {
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "token": tokens.refresh_token or tokens.access_token,
        }
        headers = FORM_HEADERS

        r = requests.post(
            DISCORD_REVOKE_URL,
            data=data,
            headers=headers,
            timeout=10,
        )
        r.raise_for_status()