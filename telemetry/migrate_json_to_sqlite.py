"""One-time migration of JSON run files into the SQLite database.

Idempotent: skips runs whose ``run_label`` already exists in the DB.
Can be executed as a standalone script or called from app startup.
"""

import json
import logging
import pathlib
import sqlite3
import sys

from database import get_connection, init_db, is_db_empty, insert_run, refresh_fingerprint_issues, DB_PATH

logger = logging.getLogger(__name__)


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
            logger.error("ERROR migrating %s: %s", fp.name, exc)
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
        logger.info("DB migration: %s", stats)
    fp_count = conn.execute("SELECT COUNT(*) FROM fingerprint_issues").fetchone()[0]
    issue_count = conn.execute("SELECT COUNT(*) FROM issues").fetchone()[0]
    if fp_count == 0 and issue_count > 0:
        n = refresh_fingerprint_issues(conn)
        conn.commit()
        logger.info("Populated fingerprint_issues: %d rows", n)
    conn.close()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(levelname)s %(name)s %(message)s",
    )
    runs_dir = pathlib.Path(__file__).parent / "runs"
    init_db()
    conn = get_connection()
    stats = migrate_json_files(runs_dir, conn)
    logger.info("Migration complete: %s", stats)
    logger.info("Database: %s", DB_PATH)
    row = conn.execute("SELECT COUNT(*) as c FROM runs").fetchone()
    logger.info("Total runs in DB: %d", row['c'])
    conn.close()
