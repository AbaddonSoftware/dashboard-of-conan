from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol, Optional, Mapping, Any


@dataclass(frozen=True)
class Tokens:
    access_token: str
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None
    token_type: Optional[str] = "Bearer"
    raw: Optional[Mapping[str, Any]] = None  # full provider payload


@dataclass(frozen=True)
class UserProfile:
    id: str
    username: str
    discriminator: Optional[str] = None
    avatar: Optional[str] = None
    raw: Optional[Mapping[str, Any]] = None


class AuthError(Exception):
    pass


class StateMismatch(AuthError):
    pass


class TokenExchangeError(AuthError):
    pass


class OAuth2Client(Protocol):
    """Abstract OAuth client interface for Discord."""

    def login_redirect(self) -> str:
        """Return a full provider authorize URL to redirect the user to."""
        ...

    def exchange_code(self, code: str) -> Tokens:
        """Exchange auth 'code' for tokens."""
        ...

    def fetch_user(self, tokens: Tokens) -> UserProfile:
        """Fetch the current user profile with the given access token."""
        ...

    def refresh(self, tokens: Tokens) -> Tokens:
        """Refresh an access token."""
        ...

    def revoke(self, tokens: Tokens) -> None:
        """Optionally revoke tokens."""
        ...