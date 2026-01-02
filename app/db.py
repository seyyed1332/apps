import os
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("DB_PATH", BASE_DIR / "app_data.db"))


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    schema = """
    CREATE TABLE IF NOT EXISTS app_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS licenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        status TEXT NOT NULL,
        max_devices INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        last_used_at TEXT,
        note TEXT,
        marzban_username TEXT
    );

    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT NOT NULL,
        install_id TEXT,
        license_code TEXT NOT NULL,
        ip TEXT,
        user_agent TEXT,
        app_version TEXT,
        model TEXT,
        os_version TEXT,
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        seen_count INTEGER NOT NULL DEFAULT 1,
        UNIQUE(device_id, license_code)
    );

    CREATE INDEX IF NOT EXISTS idx_devices_license ON devices(license_code);
    CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen_at);
    """

    with get_db() as conn:
        conn.executescript(schema)
        conn.commit()
