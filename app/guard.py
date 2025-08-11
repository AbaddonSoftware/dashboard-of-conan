from flask import redirect, url_for

PUBLIC_ENDPOINTS = {
    "auth.login",
    "auth.callback",
    "auth.logout",
    "public.landing",
    "static",
}
SAFE_METHODS = {"GET", "HEAD"}


def is_public(endpoint: str) -> bool:
    return not endpoint or endpoint in PUBLIC_ENDPOINTS


AUTH_TARGET = {
    True: None,  
    False: "auth.login", 
}


def should_redirect(method: str, endpoint: str, target: str) -> bool:
    return all(
        (
            target is not None,
            method in SAFE_METHODS,
            not is_public(endpoint),
        )
    )


def guard_request(request, is_authed_fn) -> "response|None":
    endpoint = request.endpoint
    target = AUTH_TARGET[bool(is_authed_fn())]

    action = {
        True: lambda: redirect(url_for(target, next=request.url)),
        False: lambda: None,
    }[should_redirect(request.method, endpoint, target)]

    return action()
