from __future__ import annotations

from contextlib import closing
from pathlib import Path
import re
import sqlite3


MIGRATIONS_DIR = Path(__file__).with_name("migrations")
EXPECTED_SCHEMA_VERSION = 4
_MIGRATION_NAME = re.compile(r"^(?P<version>\d{4})_.+\.sql$")


class DatabaseInitializationError(RuntimeError):
    """Raised when the local database cannot be initialized safely."""


def connect(database_path: Path) -> sqlite3.Connection:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path, timeout=5.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


def _migration_files(migrations_dir: Path) -> list[tuple[int, Path]]:
    migrations: list[tuple[int, Path]] = []
    for path in sorted(migrations_dir.glob("*.sql")):
        match = _MIGRATION_NAME.match(path.name)
        if not match:
            raise DatabaseInitializationError(f"迁移文件名无效：{path.name}")
        migrations.append((int(match.group("version")), path))
    return migrations


def initialize_database(database_path: Path, migrations_dir: Path = MIGRATIONS_DIR) -> int:
    try:
        with closing(connect(database_path)) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            connection.commit()
            applied = {
                row["version"]
                for row in connection.execute("SELECT version FROM schema_migrations")
            }
            for version, path in _migration_files(migrations_dir):
                if version in applied:
                    continue
                sql = path.read_text(encoding="utf-8")
                escaped_name = path.name.replace("'", "''")
                script = (
                    "BEGIN IMMEDIATE;\n"
                    f"{sql}\n"
                    "INSERT INTO schema_migrations(version, name) "
                    f"VALUES ({version}, '{escaped_name}');\n"
                    "COMMIT;"
                )
                try:
                    connection.executescript(script)
                except sqlite3.Error as exc:
                    connection.rollback()
                    raise DatabaseInitializationError(
                        f"数据库迁移失败：{path.name}"
                    ) from exc
            return get_schema_version(database_path)
    except OSError as exc:
        raise DatabaseInitializationError("无法创建本地数据库") from exc


def get_schema_version(database_path: Path) -> int:
    if not database_path.exists():
        return 0
    try:
        with closing(sqlite3.connect(database_path)) as connection:
            table = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
            ).fetchone()
            if table is None:
                return 0
            row = connection.execute(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
            ).fetchone()
            return int(row[0])
    except sqlite3.Error as exc:
        raise DatabaseInitializationError("无法读取数据库版本") from exc
