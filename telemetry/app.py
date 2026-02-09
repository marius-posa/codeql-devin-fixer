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

from config import RUNS_DIR
from migrate_json_to_sqlite import ensure_db_populated
from oauth import oauth_bp
from routes import api_bp, orchestrator_bp, registry_bp, demo_bp
from helpers import _paginate, _audit, require_api_key

SAMPLE_DATA_DIR = pathlib.Path(__file__).parent / "sample_data"

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32).hex())
CORS(app)

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
