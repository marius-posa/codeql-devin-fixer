"""One-time migration of JSON run files into the SQLite database.

Idempotent: skips runs whose ``run_label`` already exists in the DB.
Can be executed as a standalone script or called from app startup.
"""

import json
import pathlib
import sqlite3

from database import get_connection, init_db, is_db_empty, insert_run, DB_PATH


def migrate_json_files(
    runs_dir: pathlib.Path,
    conn: sqlite3.Connection,
) -> dict:
    stats = {"migrated": 0, "skipped": 0, "errors": 0}
    if not runs_dir.is_dir():
        return stats
    for fp in sorted(runs_dir.glob("*.json")):
        if fp.name.startswith("verification_"):
            continue
        try:
            with open(fp) as f:
                data = json.load(f)
            result = insert_run(conn, data, fp.name)
            if result is None:
                stats["skipped"] += 1
            else:
                stats["migrated"] += 1
        except (json.JSONDecodeError, OSError, sqlite3.Error) as exc:
            print(f"ERROR migrating {fp.name}: {exc}")
            stats["errors"] += 1
    conn.commit()
    return stats


def ensure_db_populated(runs_dir: pathlib.Path, sample_dir: pathlib.Path | None = None) -> None:
    init_db()
    conn = get_connection()
    if is_db_empty(conn):
        stats = migrate_json_files(runs_dir, conn)
        if stats["migrated"] == 0 and sample_dir and sample_dir.is_dir():
            stats = migrate_json_files(sample_dir, conn)
        print(f"DB migration: {stats}")
    conn.close()


if __name__ == "__main__":
    runs_dir = pathlib.Path(__file__).parent / "runs"
    init_db()
    conn = get_connection()
    stats = migrate_json_files(runs_dir, conn)
    print(f"Migration complete: {stats}")
    print(f"Database: {DB_PATH}")
    row = conn.execute("SELECT COUNT(*) as c FROM runs").fetchone()
    print(f"Total runs in DB: {row['c']}")
    conn.close()
