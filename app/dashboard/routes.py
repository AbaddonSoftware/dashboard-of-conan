from . import bp
from flask import render_template

@bp.route("/dashboard")
def index():
    return render_template("dashboard.html")

