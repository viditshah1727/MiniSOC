"""Session-based authentication for the dashboard.

Deliberately simple: one login form, server-side session, salted password
hashes (werkzeug PBKDF2). No password ever appears in code or config —
the seeded analyst's password comes from the environment.
"""
from functools import wraps

from flask import (Blueprint, flash, redirect, render_template, request,
                   session, url_for)

from app.models import User

auth_bp = Blueprint("auth", __name__)


def login_required(view):
    """Redirect anonymous users to the login page."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        # Length caps are basic input validation; the ORM parameterises the
        # query so injection is not possible either way.
        if not username or not password or len(username) > 80:
            flash("Invalid username or password.")
            return render_template("login.html"), 401

        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            # Same message for unknown user vs wrong password: don't leak
            # which usernames exist.
            flash("Invalid username or password.")
            return render_template("login.html"), 401

        session.clear()                       # rotate session on login
        session["user_id"] = user.id
        session["display_name"] = user.display_name or user.username
        target = request.args.get("next") or url_for("main.dashboard")
        # Only allow relative redirects — prevents open-redirect abuse.
        if not target.startswith("/") or target.startswith("//"):
            target = url_for("main.dashboard")
        return redirect(target)

    return render_template("login.html")


@auth_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
