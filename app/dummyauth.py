from flask import session
def is_authenticated() -> bool:
    return "user" in session