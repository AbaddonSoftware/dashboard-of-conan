

from __future__ import annotations
import os
from flask import Response
from typing import Mapping, Any
from authlib.integrations.flask_client import OAuth
from .oauth2_client import OAuth2Client, Tokens, UserProfile, TokenExchangeError

DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI")

DISCORD_AUTH_URL = "https://discord.com/api/oauth2/authorize"
DISCORD_TOKEN_URL = "https://discord.com/api/oauth2/token"
DISCORD_REVOKE_URL = "https://discord.com/api/oauth2/token/revoke"
DISCORD_ME_URL = "https://discord.com/api/users/@me"

OAUTH_SCOPES = ["identify", "guilds"]
FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}


oauth = OAuth()

def init_oauth(app) -> OAuth:
    oauth.init_app(app)
    oauth.register(
        name="discord",
        client_id=DISCORD_CLIENT_ID,
        client_secret=DISCORD_CLIENT_SECRET,
        access_token_url=DISCORD_TOKEN_URL,
        authorize_url=DISCORD_AUTH_URL,
        revoke_url=DISCORD_REVOKE_URL,
        client_kwargs={
            "scope": " ".join(OAUTH_SCOPES),
            "token_endpoint_auth_method": "client_secret_post",
        },
        redirect_uri=DISCORD_REDIRECT_URI,
    )
    return oauth

def get_discord():
    return oauth.create_client("discord")

class DiscordAuthlibClient(OAuth2Client):
    def login_redirect(self) -> Response:
        return get_discord().authorize_redirect()

    def exchange_code(self) -> Tokens:
        try:
            token = get_discord().authorize_access_token()
        except Exception as exc:
            raise TokenExchangeError(f"Token exchange failed: {exc}") from exc
        return Tokens(
            access_token=token.get("access_token"),
            refresh_token=token.get("refresh_token"),
            expires_in=token.get("expires_in"),
            token_type=token.get("token_type", "Bearer"),
            raw=token,
        )

    def fetch_user(self, tokens: Tokens) -> UserProfile:
        bearer: Mapping[str, Any] = tokens.raw or {
            "access_token": tokens.access_token,
            "token_type": tokens.token_type or "Bearer",
        }
        resp = get_discord().get(DISCORD_ME_URL, token=bearer)
        if resp.status_code != 200:
            raise TokenExchangeError("Failed to fetch user profile.")
        data = resp.json()
        return UserProfile(
            id=data["id"],
            username=data["username"],
            discriminator=data.get("discriminator"),
            avatar=data.get("avatar"),
            raw=data,
        )

    def refresh(self, tokens: Tokens) -> Tokens:
        if not tokens.refresh_token:
            return tokens
        new_token = get_discord().refresh_token(
            DISCORD_TOKEN_URL,
            refresh_token=tokens.refresh_token,
        )
        return Tokens(
            access_token=new_token.get("access_token"),
            refresh_token=new_token.get("refresh_token") or tokens.refresh_token,
            expires_in=new_token.get("expires_in"),
            token_type=new_token.get("token_type", "Bearer"),
            raw=new_token,
        )

    def revoke(self, tokens: Tokens) -> None:
        c = get_discord()
        if tokens.access_token:
            c.post(
                DISCORD_REVOKE_URL,
                data={"token": tokens.access_token, "token_type_hint": "access_token"},
                withhold_token=True,
            )
        if tokens.refresh_token:
            c.post(
                DISCORD_REVOKE_URL,
                data={"token": tokens.refresh_token, "token_type_hint": "refresh_token"},
                withhold_token=True,
            )