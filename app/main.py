import os
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from .db import get_db, init_db

load_dotenv()

APP_TITLE = os.getenv("APP_TITLE", "SeyyedMT Control Panel")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "admin")

security = HTTPBasic()

SETTINGS_FIELDS = [
    {"key": "marzban_base_url", "label": "Marzban Base URL", "type": "text"},
    {"key": "marzban_username", "label": "Marzban Admin Username", "type": "text"},
    {"key": "marzban_password", "label": "Marzban Admin Password", "type": "password"},
    {"key": "allowed_inbounds", "label": "Allowed Inbounds (comma-separated)", "type": "text"},
    {"key": "default_max_devices", "label": "Default Max Devices", "type": "number"},
    {"key": "default_data_limit_gb", "label": "Default Data Limit (GB)", "type": "number"},
    {"key": "default_expire_days", "label": "Default Expire Days", "type": "number"},
    {"key": "user_prefix", "label": "User Prefix", "type": "text"},
]

DEFAULT_SETTINGS = {
    "marzban_base_url": "",
    "marzban_username": "seyyedmt",
    "marzban_password": "koon2030.",
    "allowed_inbounds": "",
    "default_max_devices": "1",
    "default_data_limit_gb": "0",
    "default_expire_days": "0",
    "user_prefix": "app_",
}

app = FastAPI(title=APP_TITLE)
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))


class DeviceHeartbeat(BaseModel):
    license: str
    device_id: str
    install_id: Optional[str] = None
    app_version: Optional[str] = None
    model: Optional[str] = None
    os_version: Optional[str] = None


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def require_admin(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    valid_user = secrets.compare_digest(credentials.username, ADMIN_USER)
    valid_pass = secrets.compare_digest(credentials.password, ADMIN_PASS)
    if not (valid_user and valid_pass):
        raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Basic"})
    return credentials.username


def get_settings() -> Dict[str, str]:
    with get_db() as conn:
        rows = conn.execute("SELECT key, value FROM app_settings").fetchall()
        settings = {row["key"]: row["value"] for row in rows}
        changed = False
        for key, value in DEFAULT_SETTINGS.items():
            current = settings.get(key)
            if current is None or (current == "" and value != ""):
                settings[key] = value
                conn.execute(
                    "INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                    (key, value, now_iso()),
                )
                changed = True
        if changed:
            conn.commit()
        return settings


def update_settings(new_values: Dict[str, str]) -> None:
    with get_db() as conn:
        for key, value in new_values.items():
            conn.execute(
                "INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                (key, value, now_iso()),
            )
        conn.commit()


def get_license(code: str) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM licenses WHERE code = ?", (code,)).fetchone()
        return dict(row) if row else None


def count_devices_for_license(code: str) -> int:
    with get_db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS total FROM devices WHERE license_code = ?",
            (code,),
        ).fetchone()
        return int(row["total"]) if row else 0


def upsert_device(license_code: str, payload: DeviceHeartbeat, ip: str, user_agent: str) -> None:
    with get_db() as conn:
        existing = conn.execute(
            "SELECT id, seen_count FROM devices WHERE device_id = ? AND license_code = ?",
            (payload.device_id, license_code),
        ).fetchone()

        if existing:
            conn.execute(
                "UPDATE devices SET ip=?, user_agent=?, app_version=?, model=?, os_version=?, "
                "install_id=?, last_seen_at=?, seen_count=? WHERE id=?",
                (
                    ip,
                    user_agent,
                    payload.app_version,
                    payload.model,
                    payload.os_version,
                    payload.install_id,
                    now_iso(),
                    int(existing["seen_count"]) + 1,
                    existing["id"],
                ),
            )
        else:
            conn.execute(
                "INSERT INTO devices (device_id, install_id, license_code, ip, user_agent, app_version, model, "
                "os_version, first_seen_at, last_seen_at, seen_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
                (
                    payload.device_id,
                    payload.install_id,
                    license_code,
                    ip,
                    user_agent,
                    payload.app_version,
                    payload.model,
                    payload.os_version,
                    now_iso(),
                    now_iso(),
                ),
            )

        conn.execute(
            "UPDATE licenses SET last_used_at = ? WHERE code = ?",
            (now_iso(), license_code),
        )
        conn.commit()


def generate_license_code() -> str:
    raw = secrets.token_hex(12).upper()
    return "".join([raw[i : i + 4] for i in range(0, len(raw), 4)])


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def dashboard(request: Request, _: str = Depends(require_admin)):
    with get_db() as conn:
        devices_count = conn.execute("SELECT COUNT(*) AS total FROM devices").fetchone()["total"]
        licenses_count = conn.execute("SELECT COUNT(*) AS total FROM licenses").fetchone()["total"]
        installs_count = conn.execute(
            "SELECT COUNT(DISTINCT install_id) AS total FROM devices WHERE install_id IS NOT NULL"
        ).fetchone()["total"]
        recent_devices = conn.execute(
            "SELECT device_id, license_code, ip, app_version, model, last_seen_at "
            "FROM devices ORDER BY last_seen_at DESC LIMIT 6"
        ).fetchall()

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "title": APP_TITLE,
            "devices_count": devices_count,
            "licenses_count": licenses_count,
            "installs_count": installs_count,
            "recent_devices": recent_devices,
        },
    )


@app.get("/devices")
def devices(request: Request, q: str = "", _: str = Depends(require_admin)):
    with get_db() as conn:
        query = (
            "SELECT * FROM devices "
            "WHERE device_id LIKE ? OR license_code LIKE ? OR ip LIKE ? "
            "ORDER BY last_seen_at DESC"
        )
        rows = conn.execute(query, (f"%{q}%", f"%{q}%", f"%{q}%")).fetchall()

    return templates.TemplateResponse(
        "devices.html",
        {
            "request": request,
            "title": APP_TITLE,
            "devices": rows,
            "query": q,
        },
    )


@app.get("/licenses")
def licenses(request: Request, _: str = Depends(require_admin)):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT l.*, COUNT(d.id) AS device_count "
            "FROM licenses l "
            "LEFT JOIN devices d ON d.license_code = l.code "
            "GROUP BY l.id "
            "ORDER BY l.created_at DESC"
        ).fetchall()

    return templates.TemplateResponse(
        "licenses.html",
        {"request": request, "title": APP_TITLE, "licenses": rows},
    )


@app.post("/licenses/new")
def create_license(
    max_devices: int = Form(1),
    note: str = Form(""),
    marzban_username: str = Form(""),
    _: str = Depends(require_admin),
):
    code = generate_license_code()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO licenses (code, status, max_devices, created_at, note, marzban_username) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (code, "active", max_devices, now_iso(), note, marzban_username),
        )
        conn.commit()
    return RedirectResponse(url="/licenses", status_code=303)


@app.post("/licenses/{code}/toggle")
def toggle_license(code: str, _: str = Depends(require_admin)):
    license_row = get_license(code)
    if not license_row:
        raise HTTPException(status_code=404, detail="License not found")
    new_status = "disabled" if license_row["status"] == "active" else "active"
    with get_db() as conn:
        conn.execute("UPDATE licenses SET status = ? WHERE code = ?", (new_status, code))
        conn.commit()
    return RedirectResponse(url="/licenses", status_code=303)


@app.get("/settings")
def settings(request: Request, _: str = Depends(require_admin)):
    settings_data = get_settings()
    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "title": APP_TITLE,
            "settings": settings_data,
            "fields": SETTINGS_FIELDS,
        },
    )


@app.post("/settings")
async def save_settings(request: Request, _: str = Depends(require_admin)):
    form = await request.form()
    settings_data: Dict[str, str] = {}
    for field in SETTINGS_FIELDS:
        key = field["key"]
        value = form.get(key, "")
        settings_data[key] = str(value)
    update_settings(settings_data)
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/api/device/heartbeat")
def device_heartbeat(payload: DeviceHeartbeat, request: Request):
    license_row = get_license(payload.license)
    if not license_row or license_row["status"] != "active":
        raise HTTPException(status_code=403, detail="License invalid")

    device_count = count_devices_for_license(payload.license)
    with get_db() as conn:
        exists = conn.execute(
            "SELECT 1 FROM devices WHERE device_id = ? AND license_code = ?",
            (payload.device_id, payload.license),
        ).fetchone()

    if not exists and device_count >= int(license_row["max_devices"]):
        raise HTTPException(status_code=403, detail="Device limit reached")

    ip = request.client.host if request.client else ""
    user_agent = request.headers.get("user-agent", "")
    upsert_device(payload.license, payload, ip, user_agent)

    return {
        "status": "ok",
        "device_count": count_devices_for_license(payload.license),
        "max_devices": license_row["max_devices"],
    }


@app.get("/api/license/{code}")
def verify_license(code: str):
    license_row = get_license(code)
    if not license_row:
        return JSONResponse(status_code=404, content={"status": "not_found"})
    return {
        "status": license_row["status"],
        "max_devices": license_row["max_devices"],
        "marzban_username": license_row["marzban_username"],
    }


@app.get("/api/settings")
def public_settings():
    settings_data = get_settings()
    payload = {
        "marzban_base_url": settings_data.get("marzban_base_url", ""),
        "allowed_inbounds": [
            item.strip()
            for item in settings_data.get("allowed_inbounds", "").split(",")
            if item.strip()
        ],
        "user_prefix": settings_data.get("user_prefix", "app_"),
    }
    return payload
