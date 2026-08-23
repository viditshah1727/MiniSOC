"""Reset and seed the MiniSOC database with simulated data.

Usage (from the project root, venv active):
    python scripts/seed_database.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app          # noqa: E402
from app.seed_data import seed_all  # noqa: E402


def main():
    app = create_app()
    with app.app_context():
        summary = seed_all(reset=True)
    print("Done. Log in with the analyst account configured via "
          "DEFAULT_ANALYST_USERNAME / DEFAULT_ANALYST_PASSWORD in your .env.")
    return summary


if __name__ == "__main__":
    main()
