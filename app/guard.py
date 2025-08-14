from flask import redirect, url_for, request, Response
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

PUBLIC_ENDPOINTS = {
    "auth.login",
    "auth.start",
    "auth.callback",
    "auth.logout",
    "static",
}
SAFE_METHODS = {"GET", "HEAD"}

def is_public(endpoint: str | None) -> bool:
    return not endpoint or endpoint in PUBLIC_ENDPOINTS

def strip_param(url: str, key: str) -> str:
    p = urlparse(url)
    qs = [(k, v) for (k, v) in parse_qsl(p.query, keep_blank_values=True) if k.lower() != key.lower()]
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(qs, doseq=True), p.fragment))

def safe_next_from(url: str) -> str:
    """
    Produce a single, safe, relative next path from the current request URL.
    - de-nest any existing 'next'
    - forbid /auth/* targets to avoid loops
    - keep query string
    """
    clean = strip_param(url, "next")
    p = urlparse(clean)

    # if target points into /auth/*, fall back to dashboard
    if p.path.startswith("/auth/"):
        return url_for("dashboard.index")

    # relative-only next (prevents open redirects)
    next_rel = p.path + (f"?{p.query}" if p.query else "")
    return next_rel if next_rel.startswith("/") else url_for("dashboard.index")

AUTH_TARGET = {
    True: None,            # already authed -> no redirect
    False: "auth.login",   # not authed -> go to login
}

def should_redirect(method: str, endpoint: str | None, target: str | None) -> bool:
    return all((target is not None, method in SAFE_METHODS, not is_public(endpoint)))

def guard_request(req, is_authed_fn) -> "Response | None":
    target = AUTH_TARGET[bool(is_authed_fn())]
    return {
        True:  lambda: redirect(url_for(target, next=safe_next_from(req.url))),
        False: lambda: None,
    }[should_redirect(req.method, req.endpoint, target)]()