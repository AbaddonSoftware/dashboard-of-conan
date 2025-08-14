from . import bp
from flask import render_template, session  

@bp.route("/")
def index():
    user = session.get("user")
    return render_template("dashboard.html", user=user)

