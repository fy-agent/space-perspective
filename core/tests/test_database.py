from pathlib import Path
import sqlite3

import pytest

from core.db.connection import (
    DatabaseInitializationError,
    get_schema_version,
    initialize_database,
)


def test_database_initialization_is_idempotent(tmp_path: Path) -> None:
    database_path = tmp_path / "app-data" / "data.sqlite3"

    assert initialize_database(database_path) == 4
    assert initialize_database(database_path) == 4
    assert get_schema_version(database_path) == 4

    with sqlite3.connect(database_path) as connection:
        versions = connection.execute(
            "SELECT version, name FROM schema_migrations ORDER BY version"
        ).fetchall()
        stage = connection.execute(
            "SELECT value FROM app_metadata WHERE key='schema_stage'"
        ).fetchone()

    assert versions == [
        (1, "0001_initial.sql"),
        (2, "0002_p0_core.sql"),
        (3, "0003_inventory_reports.sql"),
        (4, "0004_synthetic_provider_consent.sql"),
    ]
    assert stage == ("synthetic_provider_consent_v1",)


def test_migration_failure_is_readable_and_not_recorded(tmp_path: Path) -> None:
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    (migrations / "0001_broken.sql").write_text("CREATE TABLE broken (", encoding="utf-8")
    database_path = tmp_path / "data.sqlite3"

    with pytest.raises(DatabaseInitializationError, match="0001_broken.sql"):
        initialize_database(database_path, migrations)

    assert get_schema_version(database_path) == 0
