#!/usr/bin/env python3
"""Centralized telemetry server for CodeQL Devin Fixer.

Aggregates data from all action runs across every target repository into a
single dashboard.  Run data is stored in a SQLite database (migrated from
JSON files under ``telemetry/runs/``).

Route handlers are organized into Flask Blueprints under the ``routes/``
package:

* **api** -- core read endpoints, polling, dispatch, and audit log
* **orchestrator** -- orchestrator plan/dispatch/cycle/config endpoints
* **registry** -- repository registry CRUD
* **demo** -- demo data management
"""

import os
import pathlib

from flask import Flask, request as flask_request
from flask_cors import CORS
from cachelib import FileSystemCache
from flask_session import Session

from config import RUNS_DIR
from migrate_json_to_sqlite import ensure_db_populated
from oauth import oauth_bp
from routes import api_bp, orchestrator_bp, registry_bp, demo_bp

SAMPLE_DATA_DIR = pathlib.Path(__file__).parent / "sample_data"

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32).hex())

_SESSION_DIR = pathlib.Path(__file__).parent / "flask_session"
_SESSION_DIR.mkdir(parents=True, exist_ok=True)
app.config["SESSION_TYPE"] = "cachelib"
app.config["SESSION_CACHELIB"] = FileSystemCache(str(_SESSION_DIR), threshold=500)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true"
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
Session(app)

_cors_raw = os.environ.get("CORS_ORIGINS", "")
_cors_origins: list[str] | str = (
    [o.strip() for o in _cors_raw.split(",") if o.strip()]
    if _cors_raw
    else ["http://localhost:5000", "http://127.0.0.1:5000"]
)
CORS(app, origins=_cors_origins, supports_credentials=True)

app.register_blueprint(oauth_bp)
app.register_blueprint(api_bp)
app.register_blueprint(orchestrator_bp)
app.register_blueprint(registry_bp)
app.register_blueprint(demo_bp)

ensure_db_populated(RUNS_DIR, SAMPLE_DATA_DIR)


@app.after_request
def _set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    if flask_request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


if __name__ == "__main__":
    from dotenv import load_dotenv
    env_path = pathlib.Path(__file__).parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
    app.run(host="0.0.0.0", port=5000, debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true")
