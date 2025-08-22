import os
from flask import Flask, request, redirect, url_for
from app.auth.discord_authlib_client import init_oauth
from app.dummyauth import is_authenticated
from app.guard import guard_request


def create_app():
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.getenv("FLASK_SECRET_KEY"),
        SESSION_COOKIE_SECURE=False,     # only for http://localhost dev
        SESSION_COOKIE_SAMESITE="Lax",   # default; good for OAuth callbacks
        )

    init_oauth(app)

    from .auth import bp as auth_bp
    from .dashboard import bp as dashboard_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp, url_prefix="/dashboard")

    @app.before_request
    def _global_guard():
        return guard_request(request, is_authenticated)

    @app.route("/")
    def index():
        return redirect(url_for("dashboard.index"))

    return app
