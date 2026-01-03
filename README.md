# SeyyedMT Control Panel (Local)

Lightweight local admin panel for app settings, licenses, and device tracking.

## Quick Start (Windows)

```powershell
cd "c:\Users\black\Documents\V2ray project\v2rayNG-1.10.32\panel"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
# Edit .env and set ADMIN_USER / ADMIN_PASS
uvicorn app.main:app --reload --port 8080
```

Open: http://127.0.0.1:8080

## Notes
- Data is stored locally in SQLite (default `app_data.db`).
- Basic auth protects the admin UI. Use the credentials in `.env`.
- Set `APP_PUBLIC_TOKEN` in `.env` to protect app-facing endpoints.
- Optional `MARZBAN_*` values in `.env` prefill the Settings page.
- Use the Settings page to test Marzban connectivity via `/api/admin/token`.
- Manage groups and per-group inbounds after the Marzban test loads inbound tags.
- API endpoints are ready for device heartbeats and license validation.
- App endpoints: `POST /api/license/free` and `GET /api/license/{code}/profile` (require `X-App-Token` if set).
