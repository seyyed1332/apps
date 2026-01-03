import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("DB_PATH", BASE_DIR / "app_data.db"))


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = [row["name"] for row in conn.execute(f"PRAGMA table_info({table})")]
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


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

    CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        allowed_inbounds TEXT,
        created_at TEXT NOT NULL,
        is_default INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT NOT NULL,
        install_id TEXT,
        license_code TEXT NOT NULL,
        ip TEXT,
        user_agent TEXT,
        app_version TEXT,
        manufacturer TEXT,
        model TEXT,
        device TEXT,
        os_version TEXT,
        abi TEXT,
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        seen_count INTEGER NOT NULL DEFAULT 1,
        UNIQUE(device_id, license_code)
    );

    CREATE INDEX IF NOT EXISTS idx_devices_license ON devices(license_code);
    CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen_at);
    CREATE INDEX IF NOT EXISTS idx_groups_name ON groups(name);
    """

    with get_db() as conn:
        conn.executescript(schema)
        ensure_column(conn, "licenses", "group_name", "TEXT")
        ensure_column(conn, "licenses", "allowed_inbounds", "TEXT")
        ensure_column(conn, "devices", "manufacturer", "TEXT")
        ensure_column(conn, "devices", "device", "TEXT")
        ensure_column(conn, "devices", "abi", "TEXT")
        # Ensure default groups exist
        rows = conn.execute("SELECT COUNT(*) AS total FROM groups").fetchone()
        if rows and rows["total"] == 0:
            conn.execute(
                "INSERT INTO groups (name, allowed_inbounds, created_at, is_default) VALUES (?, ?, ?, 1)",
                ("free", "", now_iso()),
            )
            conn.execute(
                "INSERT INTO groups (name, allowed_inbounds, created_at, is_default) VALUES (?, ?, ?, 0)",
                ("vip", "", now_iso()),
            )
        # Ensure at least one default group
        default_row = conn.execute(
            "SELECT 1 FROM groups WHERE is_default = 1 LIMIT 1"
        ).fetchone()
        if default_row is None:
            first_group = conn.execute(
                "SELECT id FROM groups ORDER BY id ASC LIMIT 1"
            ).fetchone()
            if first_group:
                conn.execute(
                    "UPDATE groups SET is_default = 1 WHERE id = ?",
                    (first_group["id"],),
                )
        conn.commit()
