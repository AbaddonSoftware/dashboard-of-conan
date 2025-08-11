from flask import Flask, request, redirect, url_for   
from app.dummyauth import is_authenticated
from app.guard import guard_request

def create_app():
    app = Flask(__name__)
    app.secret_key = "guessme"



    from .auth import bp as auth_bp
    from .dashboard import bp as dashboard_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp) 
    
    @app.before_request
    def _global_guard():
        return guard_request(request, is_authenticated)

    @app.route("/")
    def index():
        return redirect(url_for("dashboard.index"))




    return app
