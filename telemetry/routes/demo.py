"""Demo data blueprint -- demo data management endpoints."""

from flask import Blueprint, jsonify, request as flask_request

from database import get_connection
from demo_data import (
    is_demo_data_loaded,
    load_demo_data_into_db,
    clear_demo_data_from_db,
    get_demo_data_summary,
    load_demo_data_from_files,
    save_demo_data_to_files,
    build_all_demo_data,
)
from helpers import require_api_key

demo_bp = Blueprint("demo", __name__)


@demo_bp.route("/api/demo-data")
def api_demo_data_status():
    conn = get_connection()
    try:
        loaded = is_demo_data_loaded(conn)
        summary = get_demo_data_summary()
        return jsonify({"loaded": loaded, "summary": summary})
    finally:
        conn.close()


@demo_bp.route("/api/demo-data", methods=["POST"])
@require_api_key
def api_demo_data_load():
    conn = get_connection()
    try:
        if is_demo_data_loaded(conn):
            return jsonify({"error": "Demo data is already loaded. Clear it first."}), 409
        stats = load_demo_data_into_db(conn)
        return jsonify({"loaded": True, "stats": stats})
    finally:
        conn.close()


@demo_bp.route("/api/demo-data", methods=["DELETE"])
@require_api_key
def api_demo_data_clear():
    conn = get_connection()
    try:
        stats = clear_demo_data_from_db(conn)
        return jsonify({"loaded": False, "stats": stats})
    finally:
        conn.close()


@demo_bp.route("/api/demo-data/reset", methods=["POST"])
@require_api_key
def api_demo_data_reset():
    conn = get_connection()
    try:
        clear_demo_data_from_db(conn)
        data = build_all_demo_data()
        save_demo_data_to_files(data)
        stats = load_demo_data_into_db(conn)
        return jsonify({"loaded": True, "stats": stats})
    finally:
        conn.close()


@demo_bp.route("/api/demo-data/files")
def api_demo_data_files():
    data = load_demo_data_from_files()
    if not data["runs"]:
        data = build_all_demo_data()
        save_demo_data_to_files(data)
        data = load_demo_data_from_files()
    return jsonify(data)


@demo_bp.route("/api/demo-data/files", methods=["PUT"])
@require_api_key
def api_demo_data_files_update():
    body = flask_request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body is required"}), 400
    if "runs" not in body or not isinstance(body["runs"], list):
        return jsonify({"error": "'runs' array is required"}), 400
    save_demo_data_to_files(body)
    conn = get_connection()
    try:
        was_loaded = is_demo_data_loaded(conn)
        if was_loaded:
            clear_demo_data_from_db(conn)
            stats = load_demo_data_into_db(conn)
            return jsonify({"saved": True, "reloaded": True, "stats": stats})
        return jsonify({"saved": True, "reloaded": False})
    finally:
        conn.close()
