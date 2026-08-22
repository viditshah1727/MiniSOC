"""Database setup.

A single SQLAlchemy instance is created here and imported everywhere else,
so models, blueprints and scripts all share the same database session.
"""
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
