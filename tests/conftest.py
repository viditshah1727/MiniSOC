"""Shared pytest fixtures: an isolated in-memory database per test, plus
helpers for an authenticated client with a valid CSRF token."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app                      # noqa: E402
from app.database import db as _db              # noqa: E402
from app.detection_engine import ensure_default_rules  # noqa: E402
from app.models import User                     # noqa: E402

CSRF = "test-csrf-token"


@pytest.fixture()
def app():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SECRET_KEY": "test-secret",
    })
    with app.app_context():
        _db.drop_all()
        _db.create_all()
        ensure_default_rules()
        user = User(username="tester", display_name="Test Analyst")
        user.set_password("test-password-123")
        _db.session.add(user)
        _db.session.commit()
        yield app
        _db.session.remove()


@pytest.fixture()
def db(app):
    return _db


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def auth_client(app):
    """A client that is logged in and carries a CSRF token in its session."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["display_name"] = "Test Analyst"
        sess["_csrf_token"] = CSRF
    return client


def csrf_headers():
    return {"X-CSRF-Token": CSRF}
