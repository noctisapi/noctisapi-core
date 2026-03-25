# panel_mvp.py (sin auth, solo protegido por SSH tunnel)
import logging
import os
import time
import threading
import json
import sqlite3
from collections import Counter
from statistics import median
from datetime import datetime, timezone

from fastapi import FastAPI, Request, HTTPException, Body
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from typing import Optional

import urllib.request

from app import status_checks
from app import licensing
from app import api_modular
from app.honeypot_monitor import HoneypotAvailabilityMonitor, get_history as hp_get_history, get_summary as hp_get_summary
from app.server_config import RequestTimeoutMiddleware, get_request_timeout
from app.tls_config import get_ssl_context

_logger = logging.getLogger(__name__)

APP_NAME = "noctisapi-panel"
DB_PATH = os.getenv("HP_DB_PATH", "/data/honeypot.db")
HP_GEOIP_DB = os.getenv("HP_GEOIP_DB", "/data/GeoLite2-Country.mmdb")
_hp_host = os.getenv("HP_PUBLIC_HOST", "").strip().rstrip("/")
HP_PUBLIC_BASE_URL = (
    os.getenv("HP_PUBLIC_BASE_URL") or ("https://" + _hp_host if _hp_host else "")
).strip().rstrip("/")
_HP_MONITOR_SECRET = os.getenv("HP_MONITOR_SECRET", "").strip()
API_CATALOG_LOCK = threading.Lock()
API_CATALOG_CACHE: dict = {"ts": 0, "catalog": [], "source": "none", "error": ""}

app = FastAPI(title=APP_NAME)
app.add_middleware(RequestTimeoutMiddleware, timeout=get_request_timeout())
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
templates.env.globals.update(licensing.feature_flags())


def _license_context() -> dict:
    return licensing.feature_flags()



def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_iso(ts: str):
    try:
        return datetime.fromisoformat((ts or "").replace("Z", "+00:00"))
    except Exception:
        return None


def _env_int(name: str, default: int, min_value: Optional[int] = None) -> int:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    try:
        val = int(raw)
    except Exception:
        return default
    if min_value is not None and val < min_value:
        return min_value
    return val


def _env_float(name: str, default: float, min_value: Optional[float] = None) -> float:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    try:
        val = float(raw)
    except Exception:
        return default
    if min_value is not None and val < min_value:
        return min_value
    return val


def _is_cache_fresh(cache_ts: str, last_seen: str) -> bool:
    """Cache is fresh when it was written after (or at) the actor's last activity."""
    cache_dt = _parse_iso(cache_ts)
    last_dt = _parse_iso(last_seen)
    # If last_seen is unknown we can't safely use the cache.
    if not cache_dt or not last_dt:
        return False
    return cache_dt > last_dt


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_schema(conn: sqlite3.Connection) -> None:
    try:
        conn.execute("SELECT version_num FROM alembic_version LIMIT 1")
    except sqlite3.Error as exc:
        raise RuntimeError(
            "Database schema missing Alembic migrations. Run `alembic upgrade head` before launching the admin panel."
        ) from exc


honeypot_monitor = HoneypotAvailabilityMonitor(db)


# --- Internal Health Endpoints -------------------------------------------------


@app.on_event("startup")
def _start_background_tasks():
    import os as _os
    from app.system_settings import load_settings_overrides, ensure_settings_table

    _conn = db()
    try:
        ensure_settings_table(_conn)
        _overrides = load_settings_overrides(_conn)
        for _k, _v in _overrides.items():
            _os.environ[_k] = _v
        if _overrides:
            _logger.info("startup: applied %d config overrides from DB", len(_overrides))
    finally:
        _conn.close()

    from app.egress import check_egress_hosts
    from app.diagnostics import run_diagnostics

    check_egress_hosts()
    run_diagnostics()
    honeypot_monitor.start()


@app.on_event("shutdown")
def _stop_background_tasks():
    honeypot_monitor.stop()


@app.get("/health", tags=["Health"], response_class=PlainTextResponse)
def internal_health():
    try:
        status_checks.basic_health()
    except Exception as exc:
        raise HTTPException(status_code=503, detail={"status": "error", "reason": str(exc)})
    return PlainTextResponse("OK")


@app.get("/ready", tags=["Health"])
def internal_ready():
    try:
        state = status_checks.ensure_ready()
    except Exception as exc:
        raise HTTPException(status_code=503, detail={"status": "error", "reason": str(exc)})
    return JSONResponse(state)


def _honeypot_snapshot(conn: sqlite3.Connection, limit: int = 20) -> dict:
    summary = hp_get_summary(
        conn,
        honeypot_monitor.display_base_url,
        honeypot_monitor.endpoints,
        limit=limit,
    )
    processed = []
    for endpoint_summary in summary.get("endpoints") or []:
        history = endpoint_summary.get("history") or []
        for item in history:
            item["ts_fmt"] = fmt_ts(item.get("ts") or "")
            item["status_label"] = "UP" if int(item.get("ok") or 0) else "DOWN"
        last = endpoint_summary.get("last") or {}
        if last:
            last["ts_fmt"] = fmt_ts(last.get("ts") or "")
            last["status_label"] = "UP" if int(last.get("ok") or 0) else "DOWN"
            last["status_class"] = "status-ok" if int(last.get("ok") or 0) else "status-fail"
        endpoint_summary["history"] = history
        endpoint_summary["last"] = last or None
        processed.append(endpoint_summary)
    summary["endpoints"] = processed
    summary["configured"] = bool(summary.get("base_url") and honeypot_monitor.endpoints)
    summary["interval_seconds"] = honeypot_monitor.interval
    summary["timeout_seconds"] = honeypot_monitor.timeout
    summary["endpoints_count"] = len(processed)
    return summary


@app.get("/dashboard/honeypot", response_class=HTMLResponse)
def honeypot_availability_page(request: Request, limit: int = 20):
    conn = db()
    try:
        snapshot = _honeypot_snapshot(conn, limit=max(1, min(limit, 200)))
    finally:
        conn.close()
    return templates.TemplateResponse(
        "honeypot_availability.html",
        {"request": request, "availability": snapshot},
    )


@app.get("/admin/health/honeypot")
def honeypot_health(limit: int = 20):
    conn = db()
    try:
        snapshot = _honeypot_snapshot(conn, limit=max(1, min(limit, 200)))
    finally:
        conn.close()
    return snapshot


@app.post("/admin/health/honeypot/recheck")
def honeypot_recheck(endpoint: Optional[str] = None):
    if not honeypot_monitor.configured:
        raise HTTPException(status_code=400, detail="HONEYPOT_MONITOR_BASE_URL is not configured")
    try:
        result = honeypot_monitor.run_check(endpoint=endpoint)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return {"result": result}


@app.get("/admin/health/honeypot/history")
def honeypot_history(endpoint: Optional[str] = None, limit: int = 20):
    target = endpoint or (honeypot_monitor.endpoints[0] if honeypot_monitor.endpoints else None)
    if not target:
        raise HTTPException(status_code=400, detail="endpoint is required")
    conn = db()
    try:
        rows = hp_get_history(conn, endpoint=target, limit=max(1, min(limit, 200)))
    finally:
        conn.close()
    for row in rows:
        row["ts_fmt"] = fmt_ts(row.get("ts") or "")
        row["status_label"] = "UP" if int(row.get("ok") or 0) else "DOWN"
    return {"endpoint": target, "history": rows}


# ensure schema on startup for panel
ensure_schema(db())


def short_id(actor_id: str) -> str:
    return actor_id[:8] + "..." if actor_id and len(actor_id) > 9 else actor_id


def stage_from_score(score: int) -> int:
    if score < 10:
        return 0
    if score < 20:
        return 1
    if score < 32:
        return 2
    if score < 48:
        return 3
    if score < 68:
        return 4
    if score < 92:
        return 5
    if score < 120:
        return 6
    if score < 155:
        return 7
    return 8


def fmt_ts(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.isoformat(timespec="seconds")
    except Exception:
        return iso


def _flag_emoji_from_iso2(iso2: str) -> str:
    """Convierte un código ISO2 de país a emoji bandera"""
    if not iso2 or len(iso2) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in iso2.upper())


def parse_geo_from_extra(extra_json: str):
    """
    Espera algo como:
      {"geo":{"country_iso2":"US","country_name":"United States","flag":"🇺🇸"}, ...}
    """
    try:
        obj = json.loads(extra_json or "{}")
        geo = obj.get("geo") or {}
        iso2 = geo.get("country_iso2") or ""
        flag = geo.get("flag") or _flag_emoji_from_iso2(iso2)
        return {
            "geo_flag": flag,
            "geo_iso2": iso2,
            "geo_name": (geo.get("country_name") or ""),
        }
    except Exception:
        return {"geo_flag": "", "geo_iso2": "", "geo_name": ""}


def _normalize_path(path: str) -> str:
    clean = (path or "/").split("?")[0].strip().lower()
    return clean or "/"


def _path_ngrams(paths):
    grams = []
    if not paths:
        return grams
    for n in (3, 2):
        if len(paths) >= n:
            for i in range(len(paths) - n + 1):
                grams.append(" > ".join(paths[i : i + n]))
    if not grams:
        grams = paths[:]
    return grams[:20]


def _timing_bucket(deltas):
    if not deltas:
        return "unknown"
    med = median(deltas)
    if med < 1:
        return "burst"
    if med < 5:
        return "steady"
    return "slow"


def _stage_flow(stages):
    if not stages:
        return ""
    cleaned = []
    last = None
    for stage in stages:
        if stage is None:
            continue
        try:
            val = int(stage)
        except Exception:
            continue
        if last is None or val != last:
            cleaned.append(f"S{val}")
            last = val
    if not cleaned:
        return ""
    return "-".join(cleaned[:15])


def _sanitize_stage_flow(value: str) -> str:
    if not value:
        return ""
    if any(ch.isdigit() for ch in value):
        return value
    return ""






def _parse_step_ts(ts: str):
    try:
        return datetime.fromisoformat((ts or "").replace("Z", "+00:00"))
    except Exception:
        return None


def _table_exists(cur: sqlite3.Cursor, table_name: str) -> bool:
    cur.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
        (table_name,),
    )
    return cur.fetchone() is not None


def _normalize_catalog_method(method: str) -> str:
    raw = str(method or "*").strip().upper()
    return raw or "*"


def _normalize_catalog_path(path: str) -> str:
    raw = str(path or "").strip()
    if not raw:
        return "/"
    if not raw.startswith("/"):
        return "/" + raw
    return raw


def _honeypot_public_endpoint_catalog() -> tuple:
    now = int(time.time())
    with API_CATALOG_LOCK:
        ts = int(API_CATALOG_CACHE.get("ts") or 0)
        cached = API_CATALOG_CACHE.get("catalog")
        if ts > 0 and (now - ts) < 60 and isinstance(cached, list):
            source = str(API_CATALOG_CACHE.get("source") or "cache")
            err = str(API_CATALOG_CACHE.get("error") or "")
            return list(cached), source, err

    def _catalog_from_openapi_doc(doc: dict) -> list:
        paths = doc.get("paths") if isinstance(doc, dict) else {}
        if not isinstance(paths, dict):
            return []
        seen: set = set()
        out: list = []
        for path, path_item in paths.items():
            pp = _normalize_catalog_path(path)
            if not isinstance(path_item, dict):
                continue
            for method in sorted(path_item.keys()):
                mm = _normalize_catalog_method(method)
                if mm in {"HEAD", "OPTIONS", "TRACE"}:
                    continue
                key = f"{mm} {pp}"
                if key in seen:
                    continue
                seen.add(key)
                out.append({"method": mm, "path": pp, "label": key})
        out.sort(key=lambda item: (item.get("path") or "", item.get("method") or ""))
        return out

    source = "none"
    last_error = ""
    if HP_PUBLIC_BASE_URL:
        url = f"{HP_PUBLIC_BASE_URL}/openapi.json"
        try:
            _fetch_headers: dict = {
                "accept": "application/json",
                "user-agent": "HealthCheck/1.0",
            }
            if _HP_MONITOR_SECRET:
                _fetch_headers["x-internal-monitor"] = _HP_MONITOR_SECRET
            req = urllib.request.Request(url, headers=_fetch_headers)
            with urllib.request.urlopen(req, timeout=3.0, context=get_ssl_context()) as resp:
                raw = resp.read()
            parsed = json.loads(raw.decode("utf-8", errors="ignore") or "{}")
            remote_catalog = _catalog_from_openapi_doc(parsed)
            if remote_catalog:
                with API_CATALOG_LOCK:
                    API_CATALOG_CACHE["ts"] = now
                    API_CATALOG_CACHE["catalog"] = list(remote_catalog)
                    API_CATALOG_CACHE["source"] = "remote_openapi"
                    API_CATALOG_CACHE["error"] = ""
                return remote_catalog, "remote_openapi", ""
        except Exception as exc:
            last_error = f"remote_openapi_failed:{exc.__class__.__name__}"
            source = "remote_openapi_failed"

    try:
        from app.honeypot_public import app as public_api
        local_doc = public_api.openapi()
        local_catalog = _catalog_from_openapi_doc(local_doc if isinstance(local_doc, dict) else {})
        if local_catalog:
            with API_CATALOG_LOCK:
                API_CATALOG_CACHE["ts"] = now
                API_CATALOG_CACHE["catalog"] = list(local_catalog)
                API_CATALOG_CACHE["source"] = "local_openapi"
                API_CATALOG_CACHE["error"] = last_error
            return local_catalog, "local_openapi", last_error
    except Exception:
        if not last_error:
            last_error = "local_openapi_failed"
    with API_CATALOG_LOCK:
        API_CATALOG_CACHE["ts"] = now
        API_CATALOG_CACHE["catalog"] = []
        API_CATALOG_CACHE["source"] = source or "none"
        API_CATALOG_CACHE["error"] = last_error
    return [], (source or "none"), last_error


def _is_real_honeypot_endpoint(path: str, method: str, catalog: list) -> bool:
    target_path = _normalize_catalog_path(path)
    target_method = _normalize_catalog_method(method)
    for item in catalog:
        item_method = _normalize_catalog_method(item.get("method") or "*")
        item_path = _normalize_catalog_path(item.get("path") or "/")
        if target_method != "*" and item_method != target_method:
            continue
        if api_modular.path_matches_pattern(item_path, target_path):
            return True
    return False


def _api_modular_endpoint_catalog(conn: sqlite3.Connection, limit: int = 400) -> list:
    _ = conn
    _ = limit
    catalog, _source, _err = _honeypot_public_endpoint_catalog()
    return catalog


@app.get("/dashboard/api-modular", response_class=HTMLResponse)
def dashboard_api_modular(request: Request):
    return templates.TemplateResponse(
        "api_modular.html",
        {
            "request": request,
            **_license_context(),
        },
    )


@app.get("/dashboard/api-modular/state", response_class=JSONResponse)
def dashboard_api_modular_state():
    conn = db()
    try:
        ensure_schema(conn)
        api_modular.ensure_tables(conn)
        configs = api_modular.list_endpoint_configs(conn)
        endpoint_catalog = _api_modular_endpoint_catalog(conn, limit=600)
        _cat, catalog_source, catalog_error = _honeypot_public_endpoint_catalog()
    finally:
        conn.close()
    return {
        "templates": api_modular.list_templates(),
        "endpoint_configs": configs,
        "endpoint_catalog": endpoint_catalog,
        "endpoint_catalog_source": catalog_source,
        "endpoint_catalog_error": catalog_error,
    }


@app.post("/dashboard/api-modular/config", response_class=JSONResponse)
def dashboard_api_modular_save_config(payload: dict = Body(default={})):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="invalid_payload")
    path = str(payload.get("path") or "").strip()
    if not path:
        raise HTTPException(status_code=400, detail="path_required")
    method = str(payload.get("method") or "*").strip().upper() or "*"
    config_raw = payload.get("config")
    if not isinstance(config_raw, dict):
        raise HTTPException(status_code=400, detail="config_required")
    conn = db()
    try:
        ensure_schema(conn)
        api_modular.ensure_tables(conn)
        route_catalog, _catalog_source, _catalog_error = _honeypot_public_endpoint_catalog()
        if not _is_real_honeypot_endpoint(path, method, route_catalog):
            raise HTTPException(status_code=400, detail="unknown_honeypot_endpoint")
        saved = api_modular.upsert_endpoint_config(conn, path=path, method=method, config=config_raw)
    finally:
        conn.close()
    return {"saved": True, "entry": saved}


@app.post("/dashboard/api-modular/config/delete", response_class=JSONResponse)
def dashboard_api_modular_delete_config(payload: dict = Body(default={})):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="invalid_payload")
    path = str(payload.get("path") or "").strip()
    method = str(payload.get("method") or "*").strip().upper() or "*"
    if not path:
        raise HTTPException(status_code=400, detail="path_required")
    conn = db()
    try:
        ensure_schema(conn)
        api_modular.ensure_tables(conn)
        deleted = api_modular.delete_endpoint_config(conn, path=path, method=method)
    finally:
        conn.close()
    return {"deleted": bool(deleted)}


@app.post("/dashboard/api-modular/template/apply", response_class=JSONResponse)
def dashboard_api_modular_apply_template(payload: dict = Body(default={})):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="invalid_payload")
    template_name = str(payload.get("template_name") or "").strip().lower()
    path = str(payload.get("path") or "").strip()
    method = str(payload.get("method") or "*").strip().upper() or "*"
    if not template_name:
        raise HTTPException(status_code=400, detail="template_name_required")
    if not path:
        raise HTTPException(status_code=400, detail="path_required")
    conn = db()
    try:
        ensure_schema(conn)
        api_modular.ensure_tables(conn)
        route_catalog, _catalog_source, _catalog_error = _honeypot_public_endpoint_catalog()
        if not _is_real_honeypot_endpoint(path, method, route_catalog):
            raise HTTPException(status_code=400, detail="unknown_honeypot_endpoint")
        try:
            saved = api_modular.apply_template(conn, template_name=template_name, path=path, method=method)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    finally:
        conn.close()
    return {"saved": True, "entry": saved}


@app.get("/dashboard/api-modular/analytics", response_class=JSONResponse)
def dashboard_api_modular_analytics(hours: int = 24):
    window_hours = max(1, min(int(hours), 168))
    conn = db()
    try:
        ensure_schema(conn)
        api_modular.ensure_tables(conn)
        endpoints = api_modular.analytics_endpoint_metrics(conn, window_hours=window_hours, limit=20)
        interest = api_modular.analytics_interest_scoring(conn, window_hours=window_hours, limit=20)
        fingerprinting = api_modular.analytics_fingerprinting(conn, window_hours=window_hours, limit=20)
    finally:
        conn.close()
    return {
        "window_hours": window_hours,
        "endpoints": endpoints,
        "interest": interest,
        "fingerprinting": fingerprinting,
    }


@app.get("/dashboard/api-modular/resolve", response_class=JSONResponse)
def dashboard_api_modular_resolve(path: str = "/", method: str = "GET"):
    conn = db()
    try:
        ensure_schema(conn)
        api_modular.ensure_tables(conn)
        resolved = api_modular.resolve_endpoint_config(
            conn,
            path=path,
            method=method,
            ensure_schema=False,
        )
        return {
            "path": str(path or "/"),
            "method": str(method or "GET").upper(),
            "resolved": resolved,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)[:200])
    finally:
        conn.close()


@app.get("/", response_class=HTMLResponse)
def dashboard_root():
    return RedirectResponse(url="/dashboard", status_code=302)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_overview(request: Request):
    conn = db()
    try:
        cur = conn.cursor()
        has_sessions = _table_exists(cur, "sessions")
        has_cases = _table_exists(cur, "cases")
        has_campaigns = _table_exists(cur, "campaigns")

        cur.execute("SELECT COUNT(*) AS cnt FROM actors WHERE last_seen >= datetime('now','-1 day')")
        active_24h = int(cur.fetchone()["cnt"] or 0)
        cur.execute("SELECT COUNT(*) AS cnt FROM actors WHERE last_seen >= datetime('now','-7 day')")
        active_7d = int(cur.fetchone()["cnt"] or 0)
        cur.execute("SELECT COUNT(*) AS cnt FROM events")
        events_total = int(cur.fetchone()["cnt"] or 0)
        cur.execute(
            """
            SELECT COUNT(*) AS cnt FROM events
            WHERE kind IN ('root_console','cloud_metadata','infra_vault')
              AND ts >= datetime('now', '-24 hours')
            """
        )
        critical_alerts_24h = int(cur.fetchone()["cnt"] or 0)

        stage_max = 0
        if has_sessions:
            cur.execute("SELECT COALESCE(MAX(stage_max), 0) AS max_stage FROM sessions")
            stage_max = int(cur.fetchone()["max_stage"] or 0)

        cur.execute(
            """
            SELECT substr(ts,1,10) AS day, COUNT(*) AS cnt
            FROM events
            WHERE ts >= datetime('now','-14 day')
            GROUP BY day
            ORDER BY day
            """
        )
        events_by_day = [dict(r) for r in cur.fetchall()]

        cur.execute(
            """
            SELECT substr(first_seen,1,10) AS day, COUNT(*) AS cnt
            FROM actors
            WHERE first_seen >= datetime('now','-14 day')
            GROUP BY day
            ORDER BY day
            """
        )
        actors_new = [dict(r) for r in cur.fetchall()]

        cur.execute(
            """
            SELECT substr(last_seen,1,10) AS day, COUNT(*) AS cnt
            FROM actors
            WHERE last_seen >= datetime('now','-14 day')
              AND substr(first_seen,1,10) < substr(last_seen,1,10)
            GROUP BY day
            ORDER BY day
            """
        )
        actors_recurrent = [dict(r) for r in cur.fetchall()]

        stage_progress = []
        if has_sessions:
            cur.execute(
                """
                SELECT substr(started_at,1,10) AS day, stage_max AS stage, COUNT(*) AS cnt
                FROM sessions
                WHERE started_at >= datetime('now','-14 day')
                GROUP BY day, stage
                ORDER BY day, stage
                """
            )
            stage_progress = [dict(r) for r in cur.fetchall()]

        fast_escalations = []
        if has_sessions:
            cur.execute(
                """
                SELECT actor_id, session_id, stage_max, started_at, ended_at,
                       CAST((julianday(ended_at) - julianday(started_at)) * 86400 AS INTEGER) AS duration_s
                FROM sessions
                WHERE stage_max >= 6
                  AND ended_at IS NOT NULL
                  AND (julianday(ended_at) - julianday(started_at)) * 86400 <= 900
                ORDER BY ended_at DESC
                LIMIT 5
                """
            )
            fast_escalations = [dict(r) for r in cur.fetchall()]

        return templates.TemplateResponse(
            "dashboard_overview.html",
            {
                "request": request,
                "kpi": {
                    "active_24h": active_24h,
                    "active_7d": active_7d,
                    "events_total": events_total,
                    "stage_max": stage_max,
                    "critical_alerts_24h": critical_alerts_24h,
                },
                "events_by_day": events_by_day,
                "actors_new": actors_new,
                "actors_recurrent": actors_recurrent,
                "stage_progress": stage_progress,
                "fast_escalations": fast_escalations,
                **_license_context(),
            },
        )
    finally:
        conn.close()


_ACTOR_SORT_COLS = {
    "last_seen": "a.last_seen",
    "score":     "a.score",
    "actor_id":  "a.actor_id",
    "last_ip":   "le.ip",
}


@app.get("/dashboard/actors", response_class=HTMLResponse)
def dashboard(request: Request):
    try:
        page = max(1, int(request.query_params.get("page") or 1))
    except (ValueError, TypeError):
        page = 1
    try:
        per_page = min(200, max(10, int(request.query_params.get("per_page") or 50)))
    except (ValueError, TypeError):
        per_page = 50

    sort = request.query_params.get("sort") or "last_seen"
    if sort not in _ACTOR_SORT_COLS:
        sort = "last_seen"
    dir_ = request.query_params.get("dir") or "desc"
    if dir_ not in ("asc", "desc"):
        dir_ = "desc"
    order_sql = f"{_ACTOR_SORT_COLS[sort]} {dir_.upper()}, a.last_seen DESC"

    offset = (page - 1) * per_page

    conn = db()
    try:
        cur = conn.cursor()

        # Count visible actors (within 48h window)
        cur.execute(
            """
            SELECT COUNT(*) AS n FROM actors a
            JOIN (SELECT DISTINCT actor_id FROM events) ae ON ae.actor_id = a.actor_id
            WHERE COALESCE(a.lifecycle_state, 'active') != 'deleted'
              AND a.last_seen >= datetime('now', '-2 days')
            """
        )
        _count_row = cur.fetchone()
        total_actors = int(_count_row["n"] if _count_row else 0)
        total_pages = max(1, (total_actors + per_page - 1) // per_page)
        page = min(page, total_pages)
        offset = (page - 1) * per_page

        # Main query: single GROUP BY replaces correlated subqueries
        cur.execute(
            """
            WITH actor_counts AS (
              SELECT
                actor_id,
                MAX(id) AS max_event_id,
                SUM(CASE WHEN kind = 'token_used'   THEN 1 ELSE 0 END) AS token_used_count,
                SUM(CASE WHEN kind = 'unknown_token' THEN 1 ELSE 0 END) AS unknown_token_count
              FROM events
              GROUP BY actor_id
            ),
            geo_fallback AS (
              SELECT actor_id, MAX(id) AS geo_id
              FROM events
              WHERE extra_json LIKE '%country_iso2%'
              GROUP BY actor_id
            )
            SELECT
              a.actor_id, a.first_seen, a.last_seen, a.score,
              a.err_total, a.err_consecutive, a.last_status, a.last_error_ts,
              le.ip  AS last_ip,
              le.ua  AS last_ua,
              le.extra_json AS last_extra_json,
              gf_ev.extra_json AS last_geo_extra_json,
              ac.token_used_count, ac.unknown_token_count
            FROM actors a
            JOIN actor_counts ac ON ac.actor_id = a.actor_id
            LEFT JOIN events le   ON le.id  = ac.max_event_id
            LEFT JOIN geo_fallback gf    ON gf.actor_id  = a.actor_id
            LEFT JOIN events gf_ev ON gf_ev.id = gf.geo_id
            WHERE COALESCE(a.lifecycle_state, 'active') != 'deleted'
              AND a.last_seen >= datetime('now', '-2 days')
            ORDER BY {order_sql}
            LIMIT ? OFFSET ?
            """.format(order_sql=order_sql),
            (per_page, offset),
        )
        actors = [dict(r) for r in cur.fetchall()]
        # Count actors outside the 48h window so the template can show an upgrade nudge
        cur.execute(
            """
            SELECT COUNT(*) AS cnt FROM actors
            WHERE COALESCE(lifecycle_state, 'active') != 'deleted'
              AND EXISTS (SELECT 1 FROM events e WHERE e.actor_id = actors.actor_id)
              AND last_seen < datetime('now', '-2 days')
            """
        )
        actors_hidden = int(cur.fetchone()["cnt"] or 0)
        cur.execute("SELECT COALESCE(MAX(stage_max), 0) AS max_stage FROM sessions")
        max_stage_row = cur.fetchone()
        max_stage = int(max_stage_row["max_stage"] or 0) if max_stage_row else 0

        for a in actors:
            a["short"] = short_id(a["actor_id"])
            a["stage"] = stage_from_score(int(a.get("score") or 0))
            a["last_seen_fmt"] = fmt_ts(a["last_seen"])

            geo = parse_geo_from_extra(a.get("last_extra_json") or "")
            if not geo.get("geo_iso2"):
                geo = parse_geo_from_extra(a.get("last_geo_extra_json") or "")
            a.update(geo)

            # Si no hay flag pero tenemos IP, intentar resolver la geolocalización
            if not a.get("geo_iso2") and a.get("last_ip"):
                try:
                    import geoip2.database
                    if os.path.exists(HP_GEOIP_DB):
                        reader = geoip2.database.Reader(HP_GEOIP_DB)
                        try:
                            resp = reader.country(a["last_ip"])
                            iso = (resp.country.iso_code or "").strip().upper()
                            name = (resp.country.name or "").strip()
                            if iso:
                                a["geo_iso2"] = iso
                                a["geo_name"] = name
                                a["geo_flag"] = _flag_emoji_from_iso2(iso)
                        finally:
                            reader.close()
                except Exception:
                    pass

            a["badges"] = []
            if int(a.get("token_used_count") or 0) > 0:
                a["badges"].append(f"token_used×{a['token_used_count']}")
            if int(a.get("unknown_token_count") or 0) > 0:
                a["badges"].append(f"unknown_token×{a['unknown_token_count']}")

            # errores (desde tabla actors)
            err_total = int(a.get("err_total") or 0)
            err_consec = int(a.get("err_consecutive") or 0)
            a["err_total"] = err_total
            a["err_consecutive"] = err_consec
            a["err_badge"] = f"err×{err_total}" if err_total > 0 else ""

        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "actors": actors,
                "max_stage": max_stage,
                "actors_hidden": actors_hidden,
                "page": page,
                "per_page": per_page,
                "total_actors": total_actors,
                "total_pages": total_pages,
                "sort": sort,
                "dir": dir_,
            },
        )
    finally:
        conn.close()


# -------- Dashboard management endpoints: Cases / Sessions / Campaigns --------











@app.post("/dashboard/actors/{actor_id}/archive")
def archive_actor(actor_id: str):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE actors SET is_archived=1 WHERE actor_id=?", (actor_id,))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.post("/dashboard/actors/{actor_id}/unarchive")
def unarchive_actor(actor_id: str):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE actors SET is_archived=0 WHERE actor_id=?", (actor_id,))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.post("/dashboard/actors/{actor_id}/trash")
def trash_actor(actor_id: str):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE actors SET lifecycle_state='deleted' WHERE actor_id=?", (actor_id,))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.post("/dashboard/actors/{actor_id}/restore")
def restore_actor(actor_id: str):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE actors SET lifecycle_state='active' WHERE actor_id=?", (actor_id,))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.post("/dashboard/actors/{actor_id}/purge")
def purge_actor(actor_id: str):
    conn = db()
    try:
        cur = conn.cursor()
        _purge_actor_data(cur, actor_id)
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.post("/dashboard/actors/purge_bulk")
async def purge_actors_bulk(request: Request):
    data = None
    try:
        data = await request.json()
    except Exception:
        data = None
    actor_ids: List[str] = []
    try:
        payload = data if isinstance(data, dict) else {}
    except Exception:
        payload = {}
    if payload:
        actor_ids = payload.get("actor_ids") or []
    if not actor_ids:
        raw = (request.query_params.get("actor_ids") or "").strip()
        if raw:
            actor_ids = [a.strip() for a in raw.split(",") if a.strip()]
    if not actor_ids:
        raise HTTPException(status_code=400, detail="actor_ids required")

    conn = db()
    try:
        cur = conn.cursor()
        for actor_id in actor_ids:
            _purge_actor_data(cur, actor_id)
        conn.commit()
        return {"ok": True, "count": len(actor_ids)}
    finally:
        conn.close()


def _purge_actor_data(cur: sqlite3.Cursor, actor_id: str) -> None:
    cur.execute("DELETE FROM tokens WHERE actor_id=?", (actor_id,))
    cur.execute("DELETE FROM issued_secrets WHERE actor_id=?", (actor_id,))
    cur.execute("DELETE FROM events WHERE actor_id=?", (actor_id,))
    cur.execute("DELETE FROM actor_fingerprints WHERE actor_id=?", (actor_id,))
    cur.execute("DELETE FROM actors WHERE actor_id=?", (actor_id,))


@app.get("/dashboard/actors/deleted", response_class=HTMLResponse)
def deleted_actors(request: Request):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT actor_id, first_seen, last_seen, score
            FROM actors
            WHERE COALESCE(lifecycle_state, 'active') = 'deleted'
            ORDER BY last_seen DESC
            LIMIT 500
            """
        )
        rows = [dict(r) for r in cur.fetchall()]
        for a in rows:
            a["short"] = short_id(a["actor_id"])
            a["stage"] = stage_from_score(int(a.get("score") or 0))
            a["last_seen_fmt"] = fmt_ts(a["last_seen"])
            a["first_seen_fmt"] = fmt_ts(a["first_seen"])
        return templates.TemplateResponse(
            "actors_deleted.html", {"request": request, "actors": rows}
        )
    finally:
        conn.close()


@app.get("/dashboard/actors/{actor_id}/sessions", response_class=HTMLResponse)
def actor_sessions(actor_id: str, request: Request):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT actor_id, last_seen, score FROM actors WHERE actor_id=?", (actor_id,))
        actor_row = cur.fetchone()
        if not actor_row:
            raise HTTPException(status_code=404)
        actor = dict(actor_row)
        actor["short"] = short_id(actor["actor_id"])
        actor["last_seen_fmt"] = fmt_ts(actor.get("last_seen") or "")

        cur.execute("SELECT COUNT(*) as cnt FROM events WHERE actor_id=?", (actor_id,))
        event_count = cur.fetchone()["cnt"]

        cur.execute(
            "SELECT session_id, started_at, ended_at, stage_max, summary FROM sessions WHERE actor_id=? ORDER BY started_at DESC",
            (actor_id,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            r["started_fmt"] = fmt_ts(r.get("started_at") or "")
            r["ended_fmt"] = fmt_ts(r.get("ended_at")) if r.get("ended_at") else None

        context = {
            "request": request,
            "actor": actor,
            "sessions": rows,
            "debug": {"event_count": event_count, "sessions_count": len(rows)},
        }
        return templates.TemplateResponse("actor_sessions.html", context)
    finally:
        conn.close()


@app.get("/dashboard/sessions/{session_id}", response_class=HTMLResponse)
def session_detail(session_id: str, request: Request):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,))
        s = cur.fetchone()
        if not s:
            raise HTTPException(status_code=404)
        sess = dict(s)
        sess["started_fmt"] = fmt_ts(sess.get("started_at") or "")
        sess["ended_fmt"] = fmt_ts(sess.get("ended_at")) if sess.get("ended_at") else "-"
        if sess.get("started_at") and sess.get("ended_at"):
            try:
                start_dt = datetime.fromisoformat(sess["started_at"].replace("Z", "+00:00"))
                end_dt = datetime.fromisoformat(sess["ended_at"].replace("Z", "+00:00"))
                sess["duration_seconds"] = max(0, int((end_dt - start_dt).total_seconds()))
            except Exception:
                sess["duration_seconds"] = None
        else:
            sess["duration_seconds"] = None
        cur.execute("SELECT COUNT(*) AS cnt FROM session_steps WHERE session_id=?", (session_id,))
        steps_total = int(cur.fetchone()["cnt"] or 0)
        # Core: show only first 10 steps. Full history available on Pro.
        cur.execute("SELECT * FROM session_steps WHERE session_id=? ORDER BY seq ASC LIMIT 10", (session_id,))
        steps = [dict(r) for r in cur.fetchall()]
        return templates.TemplateResponse(
            "session_detail.html",
            {"request": request, "session": sess, "steps": steps,
             "steps_total": steps_total, "steps_cap": 10},
        )
    finally:
        conn.close()





@app.get("/dashboard/alerts", response_class=HTMLResponse)
def dashboard_alerts(request: Request):
    """Critical-event feed — Core edition (24h, top 10, IP + kind only)."""
    _CRITICAL_KINDS = ("root_console", "cloud_metadata", "infra_vault")
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT e.id, e.ts, e.kind, e.path, e.method, e.ip, e.status, e.extra_json
            FROM events e
            WHERE e.kind IN ('root_console', 'cloud_metadata', 'infra_vault')
              AND e.ts >= datetime('now', '-24 hours')
            ORDER BY e.ts DESC
            LIMIT 10
            """,
        )
        rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            try:
                ex = json.loads(r.get("extra_json") or "{}")
            except Exception:
                ex = {}
            r["points_delta"] = ex.get("points_delta", "—")
            r["scanner"] = ex.get("scanner", False)
        cur.execute(
            """
            SELECT COUNT(*) AS total,
                   COUNT(DISTINCT ip) AS unique_ips
            FROM events
            WHERE kind IN ('root_console', 'cloud_metadata', 'infra_vault')
              AND ts >= datetime('now', '-24 hours')
            """
        )
        stats_row = cur.fetchone()
        stats = dict(stats_row) if stats_row else {"total": 0, "unique_ips": 0}
        return templates.TemplateResponse(
            "alerts.html",
            {"request": request, "events": rows, "stats": stats, **_license_context()},
        )
    finally:
        conn.close()


@app.get("/dashboard/debug/db")
def debug_db():
    conn = db()
    try:
        cur = conn.cursor()
        
        # check actors
        cur.execute("SELECT COUNT(*) as cnt FROM actors")
        actor_count = cur.fetchone()['cnt']
        
        # check events
        cur.execute("SELECT COUNT(*) as cnt FROM events")
        event_count = cur.fetchone()['cnt']
        
        # check sessions
        cur.execute("SELECT COUNT(*) as cnt FROM sessions")
        session_count = cur.fetchone()['cnt']
        
        # check steps
        cur.execute("SELECT COUNT(*) as cnt FROM session_steps")
        step_count = cur.fetchone()['cnt']
        
        # get first actor with events
        cur.execute("SELECT a.actor_id, COUNT(e.id) as event_count FROM actors a LEFT JOIN events e ON a.actor_id=e.actor_id GROUP BY a.actor_id ORDER BY event_count DESC LIMIT 1")
        top_actor = cur.fetchone()
        
        return {
            "actors": actor_count,
            "events": event_count,
            "sessions": session_count,
            "session_steps": step_count,
            "top_actor": dict(top_actor) if top_actor else None
        }
    finally:
        conn.close()




@app.get("/actor/{actor_id}", response_class=HTMLResponse)
def actor(actor_id: str, request: Request):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM actors WHERE actor_id=?", (actor_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404)

        a = dict(row)
        a["short"] = short_id(a["actor_id"])
        a["stage"] = stage_from_score(int(a.get("score") or 0))
        a["first_seen_fmt"] = fmt_ts(a["first_seen"])
        a["last_seen_fmt"] = fmt_ts(a["last_seen"])

        cur.execute(
            """
            SELECT token, created_ts, stage, gift_type, used_count, last_used_ts
            FROM tokens
            WHERE actor_id=?
            ORDER BY created_ts DESC
            LIMIT 300
            """,
            (actor_id,),
        )
        tokens = [dict(r) for r in cur.fetchall()]
        for t in tokens:
            t["created_fmt"] = fmt_ts(t["created_ts"])
            t["last_used_fmt"] = fmt_ts(t["last_used_ts"]) if t.get("last_used_ts") else None

        cur.execute(
            """
            SELECT id, ts, kind, path, method, ip, ua, body_sample, token, extra_json
            FROM events
            WHERE actor_id=?
            ORDER BY id DESC
            LIMIT 300
            """,
            (actor_id,),
        )
        events = [dict(r) for r in cur.fetchall()]

        geo_reader = None
        try:
            import geoip2.database
            if os.path.exists(HP_GEOIP_DB):
                geo_reader = geoip2.database.Reader(HP_GEOIP_DB)
        except Exception:
            geo_reader = None

        icons = {
            "probe": "\N{RIGHT-POINTING MAGNIFYING GLASS}",
            "health": "\N{GREEN HEART}",
            "token_used": "\N{WHITE HEAVY CHECK MARK}",
            "unknown_token": "\N{BLACK QUESTION MARK ORNAMENT}",
            "keys_issued": "\N{KEY}",
            "internal_config": "\N{GEAR}",
            "backup_list": "\N{FILE CABINET}",
            "backup_download": "\N{DOWNWARDS BLACK ARROW}",
            "admin_secrets": "\N{BRAIN}",
            "infra_vault": "\N{CLASSICAL BUILDING}",
            "cloud_metadata": "\N{CLOUD}",
            "root_console": "\N{CROWN}",
        }
        recon_icon = icons["probe"]

        for e in events:
            e["ts_fmt"] = fmt_ts(e["ts"])
            kind = e.get("kind") or ""
            if kind.startswith("recon_"):
                e["icon"] = recon_icon
            else:
                e["icon"] = icons.get(kind, "\N{BULLET}")
            geo = parse_geo_from_extra(e.get("extra_json") or "")
            if not geo.get("geo_iso2") and e.get("ip") and geo_reader:
                try:
                    resp = geo_reader.country(e["ip"])
                    iso = (resp.country.iso_code or "").strip().upper()
                    name = (resp.country.name or "").strip()
                    if iso:
                        geo["geo_iso2"] = iso
                        geo["geo_name"] = name
                        geo["geo_flag"] = _flag_emoji_from_iso2(iso)
                except Exception:
                    pass
            e.update(geo)

        if geo_reader:
            try:
                geo_reader.close()
            except Exception:
                pass

        cur.execute(
            "SELECT session_id, started_at, stage_max FROM sessions WHERE actor_id=? ORDER BY started_at DESC LIMIT 1",
            (actor_id,),
        )
        latest_session_row = cur.fetchone()
        actor_replay = None
        if latest_session_row:
            actor_replay = dict(latest_session_row)
            actor_replay["started_fmt"] = fmt_ts(actor_replay.get("started_at") or "")
            actor_replay["stage_max"] = actor_replay.get("stage_max") or 0
            a["latest_session_id"] = actor_replay["session_id"]
            a["latest_session_started_fmt"] = actor_replay["started_fmt"]
            a["latest_session_stage"] = actor_replay["stage_max"]

        return templates.TemplateResponse(
            "actor.html",
            {
                "request": request,
                "actor": a,
                "tokens": tokens,
                "events": events,
                "actor_replay": actor_replay,
                
            },
        )
    finally:
        conn.close()


@app.get("/dashboard/actors/{actor_id}", response_class=HTMLResponse)
def actor_dashboard_alias(actor_id: str, request: Request):
    return actor(actor_id=actor_id, request=request)


def _mask_proxy_password(value: str) -> str:
    import re

    return re.sub(r"(https?://[^:@/]+:)[^@/]+(@)", r"\1***\2", value)


def _get_env_config(db_overrides: dict[str, str]) -> list[dict]:
    from app.system_settings import KEY_GROUPS, KEY_LABELS

    groups = []
    for group_name, keys in KEY_GROUPS:
        rows = []
        for key in keys:
            db_val = db_overrides.get(key, "")
            env_val = os.environ.get(key, "")
            if db_val:
                effective = db_val
                source = "override"
            elif env_val:
                effective = env_val
                source = "env"
            else:
                effective = ""
                source = "default"
            display = _mask_proxy_password(effective) if effective else ""
            rows.append(
                {
                    "key": key,
                    "label": KEY_LABELS.get(key, key),
                    "effective": display,
                    "source": source,
                    "db_value": db_val,
                    "env_value": env_val,
                }
            )
        groups.append({"name": group_name, "rows": rows})
    return groups


@app.get("/dashboard/environment", response_class=HTMLResponse)
async def environment_page(request: Request):
    from app.system_settings import load_all_settings, ensure_settings_table

    conn = db()
    try:
        ensure_settings_table(conn)
        db_overrides = load_all_settings(conn)
    finally:
        conn.close()
    config_groups = _get_env_config(db_overrides)
    return templates.TemplateResponse(
        "environment.html",
        {
            "request": request,
            "config_groups": config_groups,
            **_license_context(),
        },
    )


@app.post("/dashboard/environment/settings")
async def environment_save_setting(payload: dict = Body(...)):
    from app.system_settings import save_setting, ensure_settings_table, _EDITABLE_KEYS

    key = str(payload.get("key") or "").strip()
    value = str(payload.get("value") or "").strip()
    if not key or key not in _EDITABLE_KEYS:
        raise HTTPException(status_code=400, detail=f"Key {key!r} is not editable")
    conn = db()
    try:
        ensure_settings_table(conn)
        save_setting(conn, key, value)
    finally:
        conn.close()
    return JSONResponse({"ok": True, "restart_required": True})


@app.post("/dashboard/environment/diagnostics")
async def environment_run_diagnostics():
    from app.diagnostics import run_diagnostics

    diag_results = run_diagnostics()
    hidden_labels = {"outbound HTTPS", "proxy"}
    filtered = [r for r in diag_results if str(r.label or "") not in hidden_labels]
    return JSONResponse(
        {
            "diagnostics": [
                {"label": r.label, "status": r.status, "detail": r.detail}
                for r in filtered
            ],
        }
    )
