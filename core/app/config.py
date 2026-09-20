from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import sys


APP_VERSION = "0.1.0"
DEFAULT_ORIGINS = (
    "http://127.0.0.1:5173",
    "http://localhost:5173",
)


def default_app_data_dir() -> Path:
    """Return a platform-appropriate app data directory outside scan roots."""
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / "ZiliaoGuanjia"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "ZiliaoGuanjia"
    base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "ziliao-guanjia"


@dataclass(frozen=True, slots=True)
class Settings:
    app_name: str = "资料管家 Core"
    version: str = APP_VERSION
    database_path: Path = default_app_data_dir() / "data-butler.sqlite3"
    quarantine_path: Path | None = None
    inventory_report_path: Path | None = None
    allowed_origins: tuple[str, ...] = DEFAULT_ORIGINS

    @property
    def resolved_quarantine_path(self) -> Path:
        return self.quarantine_path or self.database_path.parent / "quarantine"

    @property
    def resolved_inventory_report_path(self) -> Path:
        return self.inventory_report_path or self.database_path.parent / "inventory-reports"


def load_settings() -> Settings:
    database_path = Path(
        os.environ.get("DATA_BUTLER_DB_PATH", default_app_data_dir() / "data-butler.sqlite3")
    ).expanduser()
    origins = tuple(
        item.strip()
        for item in os.environ.get("DATA_BUTLER_ALLOWED_ORIGINS", ",".join(DEFAULT_ORIGINS)).split(",")
        if item.strip()
    )
    quarantine_value = os.environ.get("DATA_BUTLER_QUARANTINE_PATH")
    quarantine_path = Path(quarantine_value).expanduser() if quarantine_value else None
    inventory_report_value = os.environ.get("DATA_BUTLER_INVENTORY_REPORT_PATH")
    inventory_report_path = (
        Path(inventory_report_value).expanduser() if inventory_report_value else None
    )
    return Settings(
        database_path=database_path,
        quarantine_path=quarantine_path,
        inventory_report_path=inventory_report_path,
        allowed_origins=origins,
    )
