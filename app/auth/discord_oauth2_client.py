from flask import redirect, session, Response
import os, secrets, requests
from urllib.parse import urlencode
from app.auth.oauth2_client import OAuth2Client, Tokens, UserProfile


DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI")

DISCORD_AUTH_URL = "https://discord.com/api/oauth2/authorize"
DISCORD_TOKEN_URL = "https://discord.com/api/oauth2/token"
DISCORD_REVOKE_URL = "https://discord.com/api/oauth2/token/revoke"
DISCORD_ME_URL = "https://discord.com/api/users/@me"
OAUTH_SCOPES = ["identify", "guilds"]


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

        r = requests.post(
            DISCORD_TOKEN_URL,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )
        r.raise_for_status()
        return Tokens(**response.json())

    def fetch_user(self, tokens: Tokens) -> UserProfile:
        r = requests.get(
            DISCORD_ME_URL, headers={"Authorization": f"Bearer {tokens.access_token}"}
        )
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
        r = requests.post(
            DISCORD_TOKEN_URL,
            data={
                "client_id": DISCORD_CLIENT_ID,
                "client_secret": DISCORD_CLIENT_SECRET,
                "grant_type": "refresh_token",
                "refresh_token": tokens.refresh_token,
            },
        )
        r.raise_for_status()
        data = r.json()
        return Tokens(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token", tokens.refresh_token),
            expires_in=data.get("expires_in"),
            token_type=data.get("token_type", tokens.token_type or "Bearer"),
            raw=data,
        )

    def revoke(self, tokens: Tokens) -> None:
        requests.post(
            DISCORD_REVOKE_URL,
            data={
                "client_id": DISCORD_CLIENT_ID,
                "client_secret": DISCORD_CLIENT_SECRET,
                "token": tokens.refresh_token or tokens.access_token,
            },
        ).raise_for_status()
