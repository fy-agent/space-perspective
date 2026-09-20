from pathlib import Path

import pytest

from core.app.config import Settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        database_path=tmp_path / "app-data" / "test.sqlite3",
        allowed_origins=("http://127.0.0.1:5173",),
    )
