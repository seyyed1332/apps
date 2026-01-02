import json
import os
import secrets
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

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
    "marzban_base_url": os.getenv("MARZBAN_BASE_URL", ""),
    "marzban_username": os.getenv("MARZBAN_USERNAME", ""),
    "marzban_password": os.getenv("MARZBAN_PASSWORD", ""),
    "allowed_inbounds": os.getenv("MARZBAN_ALLOWED_INBOUNDS", ""),
    "default_max_devices": os.getenv("MARZBAN_DEFAULT_MAX_DEVICES", "1"),
    "default_data_limit_gb": os.getenv("MARZBAN_DEFAULT_DATA_LIMIT_GB", "0"),
    "default_expire_days": os.getenv("MARZBAN_DEFAULT_EXPIRE_DAYS", "0"),
    "user_prefix": os.getenv("MARZBAN_USER_PREFIX", "app_"),
    "marzban_last_status": "",
    "marzban_last_message": "",
    "marzban_inbounds_cache": "",
}

NUMERIC_SETTING_KEYS = {
    "default_max_devices": 1,
    "default_data_limit_gb": 0,
    "default_expire_days": 0,
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


def normalize_base_url(raw: str) -> str:
    base_url = raw.strip()
    if not base_url:
        return ""
    if not base_url.startswith(("http://", "https://")):
        base_url = f"https://{base_url}"
    return base_url.rstrip("/")


def normalize_settings(values: Dict[str, str]) -> Dict[str, str]:
    normalized: Dict[str, str] = {}
    for field in SETTINGS_FIELDS:
        key = field["key"]
        value = str(values.get(key, "")).strip()
        if key == "marzban_base_url":
            value = normalize_base_url(value)
        if key in NUMERIC_SETTING_KEYS:
            try:
                number = int(value)
            except ValueError:
                number = NUMERIC_SETTING_KEYS[key]
            if key == "default_max_devices":
                number = max(1, number)
            else:
                number = max(0, number)
            value = str(number)
        normalized[key] = value
    return normalized


def request_json(
    url: str,
    method: str = "GET",
    data: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Accept", "application/json")
    request.add_header("User-Agent", "SeyyedMT-Panel")
    if headers:
        for key, value in headers.items():
            request.add_header(key, value)

    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            body = response.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", errors="ignore").strip()
        except Exception:
            detail = ""
        message = f"HTTP {exc.code}"
        if detail:
            message = f"{message}: {detail[:200]}"
        return None, message
    except urllib.error.URLError as exc:
        return None, f"Connection failed: {exc.reason}"

    if not body:
        return {}, None

    try:
        return json.loads(body), None
    except json.JSONDecodeError:
        return None, "Unexpected response from Marzban."


def marzban_token(settings: Dict[str, str]) -> Tuple[Optional[str], str]:
    base_url = normalize_base_url(settings.get("marzban_base_url", ""))
    if not base_url:
        return None, "Marzban base URL is missing."

    username = settings.get("marzban_username", "").strip()
    password = settings.get("marzban_password", "").strip()
    if not username or not password:
        return None, "Marzban username or password is missing."

    token_url = f"{base_url}/api/admin/token"
    form = urllib.parse.urlencode(
        {"grant_type": "password", "username": username, "password": password}
    ).encode("utf-8")
    payload, error = request_json(
        token_url,
        method="POST",
        data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if error:
        return None, error
    if payload and payload.get("access_token"):
        return payload.get("access_token"), "Marzban authenticated successfully."

    detail = ""
    if isinstance(payload, dict):
        detail = payload.get("detail") or payload.get("message") or ""
    return None, detail or "Authentication failed."


def marzban_inbounds(base_url: str, token: str) -> Tuple[Optional[list], Optional[str]]:
    url = f"{base_url}/api/inbounds"
    payload, error = request_json(
        url,
        headers={"Authorization": f"Bearer {token}"},
    )
    if error:
        return None, error
    if not isinstance(payload, dict):
        return None, "Unexpected inbounds response."

    inbounds = []
    seen = set()
    for protocol, items in payload.items():
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            tag = str(item.get("tag") or "").strip()
            if not tag or tag in seen:
                continue
            seen.add(tag)
            inbounds.append(
                {
                    "tag": tag,
                    "protocol": str(item.get("protocol") or protocol or "").strip(),
                    "network": str(item.get("network") or "").strip(),
                    "tls": str(item.get("tls") or "").strip(),
                    "port": str(item.get("port") or "").strip(),
                }
            )

    inbounds.sort(key=lambda inbound: (inbound.get("protocol"), inbound.get("tag")))
    return inbounds, None


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
    normalized = normalize_settings(new_values)
    with get_db() as conn:
        for key, value in normalized.items():
            conn.execute(
                "INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                (key, value, now_iso()),
            )
        conn.commit()


def set_app_setting(key: str, value: str) -> None:
    with get_db() as conn:
        conn.execute(
            "INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (key, value, now_iso()),
        )
        conn.commit()


def parse_allowed(value: Optional[str]) -> set:
    if not value:
        return set()
    return {item.strip() for item in value.split(",") if item.strip()}


def get_groups() -> list:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT name, allowed_inbounds, is_default FROM groups ORDER BY name"
        ).fetchall()
    return [dict(row) for row in rows]


def get_group_allowed_map(groups: list) -> Dict[str, set]:
    allowed_map: Dict[str, set] = {}
    for group in groups:
        allowed_map[group["name"]] = parse_allowed(group.get("allowed_inbounds"))
    return allowed_map


def get_default_group_name(groups: list) -> str:
    for group in groups:
        if group.get("is_default"):
            return group.get("name", "free")
    return groups[0]["name"] if groups else "free"


def load_inbounds_cache(settings_data: Dict[str, str]) -> list:
    inbounds_cache = settings_data.get("marzban_inbounds_cache", "")
    if not inbounds_cache:
        return []
    try:
        parsed = json.loads(inbounds_cache)
        return parsed if isinstance(parsed, list) else []
    except json.JSONDecodeError:
        return []


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
            "SELECT d.device_id, d.license_code, l.marzban_username, l.group_name, d.ip, d.app_version, "
            "d.model, d.last_seen_at "
            "FROM devices d "
            "LEFT JOIN licenses l ON l.code = d.license_code "
            "ORDER BY d.last_seen_at DESC LIMIT 6"
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
            "SELECT d.*, l.marzban_username, l.group_name "
            "FROM devices d "
            "LEFT JOIN licenses l ON l.code = d.license_code "
            "WHERE d.device_id LIKE ? OR d.license_code LIKE ? OR d.ip LIKE ? OR l.marzban_username LIKE ? "
            "ORDER BY d.last_seen_at DESC"
        )
        rows = conn.execute(
            query,
            (f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"),
        ).fetchall()

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
def licenses(request: Request, q: str = "", _: str = Depends(require_admin)):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT l.*, COUNT(d.id) AS device_count "
            "FROM licenses l "
            "LEFT JOIN devices d ON d.license_code = l.code "
            "WHERE l.code LIKE ? OR l.marzban_username LIKE ? OR l.group_name LIKE ? OR l.note LIKE ? "
            "GROUP BY l.id "
            "ORDER BY l.created_at DESC",
            (f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"),
        ).fetchall()

    groups = get_groups()
    default_group = get_default_group_name(groups)
    return templates.TemplateResponse(
        "licenses.html",
        {
            "request": request,
            "title": APP_TITLE,
            "licenses": rows,
            "groups": groups,
            "default_group": default_group,
            "query": q,
        },
    )


@app.post("/licenses/new")
def create_license(
    max_devices: int = Form(1),
    note: str = Form(""),
    marzban_username: str = Form(""),
    group_name: str = Form(""),
    _: str = Depends(require_admin),
):
    code = generate_license_code()
    with get_db() as conn:
        group_row = None
        if group_name:
            group_row = conn.execute(
                "SELECT name, allowed_inbounds FROM groups WHERE name = ?",
                (group_name,),
            ).fetchone()
        if not group_row:
            group_row = conn.execute(
                "SELECT name, allowed_inbounds FROM groups WHERE is_default = 1 LIMIT 1"
            ).fetchone()
        final_group = group_row["name"] if group_row else "free"
        final_inbounds = group_row["allowed_inbounds"] if group_row else ""
        conn.execute(
            "INSERT INTO licenses (code, status, max_devices, created_at, note, marzban_username, group_name, allowed_inbounds) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                code,
                "active",
                max_devices,
                now_iso(),
                note,
                marzban_username,
                final_group,
                final_inbounds,
            ),
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


@app.get("/licenses/{code}")
def edit_license(request: Request, code: str, _: str = Depends(require_admin)):
    license_row = get_license(code)
    if not license_row:
        raise HTTPException(status_code=404, detail="License not found")
    settings_data = get_settings()
    marzban_inbounds = load_inbounds_cache(settings_data)
    groups = get_groups()
    group_allowed = get_group_allowed_map(groups)
    default_group = get_default_group_name(groups)

    group_name = license_row.get("group_name") or default_group
    license_allowed = parse_allowed(license_row.get("allowed_inbounds"))
    selected_inbounds = license_allowed or group_allowed.get(group_name, set())
    inherit_group = len(license_allowed) == 0

    return templates.TemplateResponse(
        "license_edit.html",
        {
            "request": request,
            "title": f"License {code}",
            "license": license_row,
            "groups": groups,
            "group_name": group_name,
            "marzban_inbounds": marzban_inbounds,
            "selected_inbounds": selected_inbounds,
            "inherit_group": inherit_group,
            "default_group": default_group,
        },
    )


@app.post("/licenses/{code}")
async def update_license(request: Request, code: str, _: str = Depends(require_admin)):
    license_row = get_license(code)
    if not license_row:
        raise HTTPException(status_code=404, detail="License not found")

    form = await request.form()
    max_devices_raw = str(form.get("max_devices", "")).strip()
    try:
        max_devices = max(1, int(max_devices_raw))
    except ValueError:
        max_devices = int(license_row.get("max_devices") or 1)

    status = str(form.get("status", "")).strip().lower()
    if status not in {"active", "disabled"}:
        status = license_row.get("status", "active")

    group_name = str(form.get("group_name", "")).strip()
    groups = get_groups()
    group_names = {group["name"] for group in groups}
    default_group = get_default_group_name(groups)
    if group_name not in group_names:
        group_name = license_row.get("group_name") or default_group
    marzban_username = str(form.get("marzban_username", "")).strip()
    note = str(form.get("note", "")).strip()

    inherit_group = form.get("inherit_inbounds") == "on"
    selected = form.getlist("allowed_inbounds")
    tags = sorted({item.strip() for item in selected if item.strip()})
    allowed_inbounds = "" if inherit_group else ",".join(tags)

    with get_db() as conn:
        conn.execute(
            "UPDATE licenses SET status = ?, max_devices = ?, marzban_username = ?, note = ?, "
            "group_name = ?, allowed_inbounds = ? WHERE code = ?",
            (
                status,
                max_devices,
                marzban_username,
                note,
                group_name,
                allowed_inbounds,
                code,
            ),
        )
        conn.commit()
    return RedirectResponse(url=f"/licenses/{code}", status_code=303)


@app.get("/settings")
def settings(request: Request, _: str = Depends(require_admin)):
    settings_data = get_settings()
    marzban_status = request.query_params.get("marzban", "")
    marzban_message = request.query_params.get("message", "")
    if not marzban_status:
        marzban_status = settings_data.get("marzban_last_status", "")
    if not marzban_message:
        marzban_message = settings_data.get("marzban_last_message", "")

    allowed_raw = settings_data.get("allowed_inbounds", "")
    allowed_inbounds = {item.strip() for item in allowed_raw.split(",") if item.strip()}

    marzban_inbounds = load_inbounds_cache(settings_data)
    groups = get_groups()
    group_allowed = get_group_allowed_map(groups)
    default_group = get_default_group_name(groups)
    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "title": APP_TITLE,
            "settings": settings_data,
            "fields": SETTINGS_FIELDS,
            "marzban_status": marzban_status,
            "marzban_message": marzban_message,
            "allowed_inbounds": allowed_inbounds,
            "marzban_inbounds": marzban_inbounds,
            "groups": groups,
            "group_allowed": group_allowed,
            "default_group": default_group,
        },
    )


@app.post("/settings/marzban/test")
def marzban_test(_: str = Depends(require_admin)):
    settings_data = get_settings()
    token, message = marzban_token(settings_data)
    ok = token is not None
    base_url = normalize_base_url(settings_data.get("marzban_base_url", ""))

    if ok and token and base_url:
        inbounds, inbound_error = marzban_inbounds(base_url, token)
        if inbounds is not None:
            set_app_setting("marzban_inbounds_cache", json.dumps(inbounds))
            message = f"{message} Loaded {len(inbounds)} inbounds."
        elif inbound_error:
            message = f"{message} Inbounds fetch failed: {inbound_error}"

    set_app_setting("marzban_last_status", "ok" if ok else "fail")
    set_app_setting("marzban_last_message", message)

    params = urllib.parse.urlencode(
        {"marzban": "ok" if ok else "fail", "message": message}
    )
    return RedirectResponse(url=f"/settings?{params}", status_code=303)


@app.post("/settings/inbounds")
async def save_inbounds(request: Request, _: str = Depends(require_admin)):
    form = await request.form()
    selected = form.getlist("allowed_inbounds")
    tags = sorted({item.strip() for item in selected if item.strip()})
    set_app_setting("allowed_inbounds", ",".join(tags))
    set_app_setting("marzban_last_message", "Allowed inbounds updated.")
    return RedirectResponse(url="/settings?marzban=ok&message=Allowed+inbounds+updated", status_code=303)


@app.post("/groups/new")
async def create_group(request: Request, _: str = Depends(require_admin)):
    form = await request.form()
    name = str(form.get("group_name", "")).strip()
    if not name:
        return RedirectResponse(url="/settings?marzban=fail&message=Group+name+required", status_code=303)
    with get_db() as conn:
        try:
            conn.execute(
                "INSERT INTO groups (name, allowed_inbounds, created_at, is_default) VALUES (?, ?, ?, 0)",
                (name, "", now_iso()),
            )
            conn.commit()
        except Exception:
            return RedirectResponse(
                url="/settings?marzban=fail&message=Group+already+exists",
                status_code=303,
            )
    return RedirectResponse(url="/settings?marzban=ok&message=Group+created", status_code=303)


@app.post("/groups/{name}/default")
def set_default_group(name: str, _: str = Depends(require_admin)):
    with get_db() as conn:
        conn.execute("UPDATE groups SET is_default = 0")
        conn.execute("UPDATE groups SET is_default = 1 WHERE name = ?", (name,))
        conn.commit()
    return RedirectResponse(url="/settings?marzban=ok&message=Default+group+updated", status_code=303)


@app.post("/groups/{name}/inbounds")
async def update_group_inbounds(name: str, request: Request, _: str = Depends(require_admin)):
    form = await request.form()
    selected = form.getlist("allowed_inbounds")
    tags = sorted({item.strip() for item in selected if item.strip()})
    with get_db() as conn:
        conn.execute(
            "UPDATE groups SET allowed_inbounds = ? WHERE name = ?",
            (",".join(tags), name),
        )
        conn.commit()
    return RedirectResponse(url="/settings?marzban=ok&message=Group+inbounds+updated", status_code=303)


@app.post("/settings")
async def save_settings(request: Request, _: str = Depends(require_admin)):
    form = await request.form()
    current = get_settings()
    settings_data: Dict[str, str] = {}
    for field in SETTINGS_FIELDS:
        key = field["key"]
        if key == "allowed_inbounds" and key not in form:
            settings_data[key] = current.get(key, "")
            continue
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
    groups = get_groups()
    group_allowed = get_group_allowed_map(groups)
    default_group = get_default_group_name(groups)
    group_name = license_row.get("group_name") or default_group
    license_allowed = parse_allowed(license_row.get("allowed_inbounds"))
    effective_inbounds = sorted(
        license_allowed if license_allowed else group_allowed.get(group_name, set())
    )
    return {
        "status": license_row["status"],
        "max_devices": license_row["max_devices"],
        "marzban_username": license_row["marzban_username"],
        "group": group_name,
        "allowed_inbounds": effective_inbounds,
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
