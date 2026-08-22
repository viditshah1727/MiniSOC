"""MiniSOC entry point.

Usage:
    python run.py            # start the dashboard on http://127.0.0.1:5000
"""
import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    # Debug mode is opt-in via .env; never enable it in production —
    # the Werkzeug debugger allows arbitrary code execution.
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")),
            debug=debug)
