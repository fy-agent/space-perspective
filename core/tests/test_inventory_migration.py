from pathlib import Path
import shutil
import sqlite3

from core.db.connection import MIGRATIONS_DIR, initialize_database


def test_existing_p0_database_upgrades_additively(tmp_path: Path) -> None:
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    for name in ("0001_initial.sql", "0002_p0_core.sql"):
        shutil.copy2(MIGRATIONS_DIR / name, migrations / name)
    database = tmp_path / "p0.sqlite3"

    assert initialize_database(database, migrations) == 2
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO scan_sessions(
                id, requested_paths_json, options_json, status, started_at,
                files_seen, files_indexed, files_skipped, bytes_seen, error_summary_json
            ) VALUES ('scan_existing', '[]', '{}', 'completed', '2026-07-27T00:00:00Z',
                      0, 0, 0, 0, '[]')
            """
        )
        connection.commit()

    shutil.copy2(
        MIGRATIONS_DIR / "0003_inventory_reports.sql",
        migrations / "0003_inventory_reports.sql",
    )
    assert initialize_database(database, migrations) == 3
    shutil.copy2(
        MIGRATIONS_DIR / "0004_synthetic_provider_consent.sql",
        migrations / "0004_synthetic_provider_consent.sql",
    )
    assert initialize_database(database, migrations) == 4

    with sqlite3.connect(database) as connection:
        old_row = connection.execute(
            "SELECT id, status FROM scan_sessions WHERE id='scan_existing'"
        ).fetchone()
        new_tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        consent_foreign_keys = {
            row[2]
            for row in connection.execute(
                "PRAGMA foreign_key_list(analysis_consent_receipts)"
            )
        }
    assert old_row == ("scan_existing", "completed")
    assert {
        "inventory_scan_profiles",
        "inventory_checkpoints",
        "governance_objects",
        "governance_evidence",
        "report_snapshots",
        "analysis_packets",
        "ai_analyses",
        "model_call_receipts",
        "report_artifacts",
        "analysis_consent_receipts",
    } <= new_tables
    assert {"analysis_packets", "ai_analyses", "model_call_receipts"} <= (
        consent_foreign_keys
    )
