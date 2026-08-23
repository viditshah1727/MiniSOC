"""MiniSOC application factory.

Creates and configures the Flask app: loads settings from environment
variables (.env), initialises the database, registers blueprints, and wires
up session-based CSRF protection for all state-changing requests.
"""
import os
import secrets
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, session

from app.database import db

PROJECT_ROOT = Path(__file__).resolve().parent.parent

load_dotenv(PROJECT_ROOT / ".env")


def create_app(test_config=None):
    app = Flask(__name__)

    # --- configuration ------------------------------------------------------
    # SECRET_KEY signs the session cookie. It must come from the environment;
    # for local dev without a .env we generate a random per-process key
    # (sessions won't survive restarts, which is a safe failure mode).
    secret_key = os.environ.get("SECRET_KEY")
    if not secret_key:
        secret_key = secrets.token_hex(32)
        app.logger.warning("SECRET_KEY not set; generated an ephemeral key. "
                           "Copy .env.example to .env for a persistent key.")

    data_dir = PROJECT_ROOT / "data"
    data_dir.mkdir(exist_ok=True)
    default_db = f"sqlite:///{data_dir / 'minisoc.db'}"

    app.config.update(
        SECRET_KEY=secret_key,
        SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", default_db),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,       # JS cannot read the session cookie
        SESSION_COOKIE_SAMESITE="Lax",      # blocks cross-site POSTs of the cookie
        # SESSION_COOKIE_SECURE should be True behind HTTPS in production.
        MAX_CONTENT_LENGTH=64 * 1024,       # request bodies are tiny JSON/forms
    )
    if test_config:
        app.config.update(test_config)

    db.init_app(app)

    # --- CSRF protection ----------------------------------------------------
    # Double-submit pattern: a random token lives in the (signed, HttpOnly)
    # session; templates/JS echo it back via form field or X-CSRF-Token
    # header on every state-changing request.
    def get_csrf_token():
        if "_csrf_token" not in session:
            session["_csrf_token"] = secrets.token_hex(32)
        return session["_csrf_token"]

    @app.before_request
    def csrf_protect():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            sent = (request.headers.get("X-CSRF-Token")
                    or request.form.get("csrf_token"))
            expected = session.get("_csrf_token")
            if not expected or not sent or not secrets.compare_digest(sent, expected):
                if request.path.startswith("/api/"):
                    return jsonify(error="Invalid or missing CSRF token"), 400
                return render_template("error.html", code=400,
                                       message="Invalid or missing CSRF token"), 400
        return None

    @app.context_processor
    def inject_globals():
        return {"csrf_token": get_csrf_token,
                "current_analyst": session.get("display_name")}

    # Display labels for severity codes (DB stores the uppercase codes).
    SEV_LABELS = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium",
                  "LOW": "Low", "INFO": "Informational"}

    @app.template_filter("sev_label")
    def sev_label(value):
        return SEV_LABELS.get(value, value)

    # --- blueprints ---------------------------------------------------------
    from app.auth import auth_bp
    from app.routes import main_bp
    from app.api import api_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix="/api")

    # --- error handling -----------------------------------------------------
    # API paths get JSON errors; page paths get a friendly error page.
    # Internal details are logged server-side, never sent to the client.
    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith("/api/"):
            return jsonify(error="Not found"), 404
        return render_template("error.html", code=404,
                               message="Page not found"), 404

    @app.errorhandler(500)
    def server_error(e):
        app.logger.exception("Unhandled server error")
        if request.path.startswith("/api/"):
            return jsonify(error="Internal server error"), 500
        return render_template("error.html", code=500,
                               message="Internal server error"), 500

    with app.app_context():
        db.create_all()

    return app
