# honeypot_public.py
import logging
import os
import sys
import json
import hashlib
import secrets
import sqlite3
import time
from datetime import timedelta
import ipaddress
import asyncio
import base64
import random
import re
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple, List

_logger = logging.getLogger(__name__)

from fastapi import FastAPI, Request, HTTPException, Depends, Security
from fastapi.responses import JSONResponse, PlainTextResponse, HTMLResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app import licensing
from app.trusted_proxy import resolve_client_ip
from app.reverse_proxy import ReverseProxyMiddleware, get_static_public_base_url
from app import health as _health
from app.server_config import RequestTimeoutMiddleware, get_request_timeout
from app.structured_logging import set_request_id
from app import alert_dispatcher
from app import api_modular

APP_TITLE = os.getenv("HP_API_TITLE", "Account Service API")
APP_VERSION = os.getenv("HP_API_VERSION", "1.0.0")

DB_PATH = os.getenv("HP_DB_PATH", "/data/honeypot.db")
HP_SEED = os.getenv("HP_SEED", "CHANGE_ME_LONG_RANDOM_SEED")
HP_REQUIRE_SEED = (os.getenv("HP_REQUIRE_SEED", "") or "").strip().lower() in ("1", "true", "yes")
HONEYPOT_MONITOR_UA = os.getenv("HONEYPOT_MONITOR_UA", "HealthCheck/1.0")
_hp_host = os.getenv("HP_PUBLIC_HOST", "").strip().rstrip("/")
HP_PUBLIC_BASE_URL = (
    os.getenv("HP_PUBLIC_BASE_URL")
    or ("https://" + _hp_host if _hp_host else "http://127.0.0.1:8080")
).rstrip("/")
HP_ACTOR_UA_MODE = os.getenv("HP_ACTOR_UA_MODE", "family").strip().lower()
# Monitor bypass requires a secret; if unset the bypass is disabled entirely.
_HP_MONITOR_SECRET = os.getenv("HP_MONITOR_SECRET", "").strip()

SAMPLE_FILE_ID = "sample"
SAMPLE_FILE_NAME = "sample.bin"
SAMPLE_FILE_BYTES = b"Sample payload\n"
SAMPLE_FILE_SHA256 = hashlib.sha256(SAMPLE_FILE_BYTES).hexdigest()
SAMPLE_JOB_ID = "sample"

# GeoIP (optional). Provide a MaxMind GeoLite2 Country mmdb in this path.
HP_GEOIP_DB = os.getenv("HP_GEOIP_DB", "/data/GeoLite2-Country.mmdb")

SCANNER_UA_PATTERNS = (
    "sqlmap",
    "nmap",
    "masscan",
    "nikto",
    "zgrab",
    "dirbuster",
    "gobuster",
    "ffuf",
    "acunetix",
    "nessus",
    "netsparker",
)

DANGEROUS_PAYLOAD_PATTERNS = (
    "rm -rf",
    "drop table",
    "union select",
    "sleep(",
    "wget ",
    "curl ",
    "powershell",
    "<script",
    "chmod +x",
)

SUSPICIOUS_COMMAND_PATTERNS = (
    "whoami",
    "id",
    "uname",
    "cat /etc/passwd",
    "netstat",
    "ifconfig",
    "ip addr",
    "curl ",
    "wget ",
)

security = HTTPBearer(auto_error=False)

tags_metadata = [
    {"name": "Health", "description": "Service health checks"},
    {"name": "Recon", "description": "Reconnaissance and discovery"},
    {"name": "Auth", "description": "Authentication and token issuance"},
    {"name": "Internal", "description": "Internal or admin-only operations"},
    {"name": "DevOps", "description": "CI/CD and automation"},
    {"name": "Business", "description": "Business API surface"},
    {"name": "Files", "description": "File uploads and analysis"},
    {"name": "Console", "description": "Console and shell access"},
    {"name": "Account", "description": "Account operations"},
    {"name": "Admin", "description": "Administrative operations"},
    {"name": "Export", "description": "Export jobs"},
]

_static_public_url = get_static_public_base_url()

app = FastAPI(
    title=APP_TITLE,
    version=APP_VERSION,
    openapi_tags=tags_metadata,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    servers=[{"url": _static_public_url, "description": "Public API"}] if _static_public_url else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)
app.add_middleware(ReverseProxyMiddleware)
app.add_middleware(RequestTimeoutMiddleware, timeout=get_request_timeout())


def _warn_if_default_seed() -> None:
    if HP_SEED == "CHANGE_ME_LONG_RANDOM_SEED":
        msg = "[WARNING] HP_SEED is using the default placeholder. Set a strong, stable value in production."
        print(msg, file=sys.stderr)
        if HP_REQUIRE_SEED:
            raise RuntimeError("HP_SEED must be set (HP_REQUIRE_SEED=1).")


@app.on_event("startup")
async def _startup_checks() -> None:
    _warn_if_default_seed()
    import os as _os
    from app.system_settings import load_settings_overrides, ensure_settings_table

    _conn = _db()
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


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=5.0, isolation_level="IMMEDIATE")
    conn.row_factory = sqlite3.Row
    pragma_statements = (
        "PRAGMA journal_mode=WAL;",
        "PRAGMA synchronous=NORMAL;",
        "PRAGMA busy_timeout=5000;",
        "PRAGMA temp_store=MEMORY;",
    )
    for stmt in pragma_statements:
        try:
            conn.execute(stmt)
        except Exception:
            continue
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    try:
        conn.execute("SELECT version_num FROM alembic_version LIMIT 1")
    except sqlite3.Error as exc:
        raise RuntimeError(
            "Database schema is not initialized. Run `alembic upgrade head` before starting the API."
        ) from exc


def _client_ip(req: Request) -> str:
    return resolve_client_ip(req)


def _user_agent(req: Request) -> str:
    return (req.headers.get("user-agent") or "")[:400]

def _normalize_ua(ua: str) -> str:
    raw = (ua or "").strip().lower()
    if not raw:
        return "unknown"
    if "curl/" in raw:
        return "curl"
    if "python-httpx" in raw:
        return "python-httpx"
    if "python-requests" in raw:
        return "python-requests"
    if "okhttp" in raw:
        return "okhttp"
    if "go-http-client" in raw:
        return "go-http-client"
    if "java/" in raw or "jdk" in raw:
        return "java"
    if "postmanruntime" in raw:
        return "postman"
    if "wget/" in raw:
        return "wget"
    if "httpie" in raw:
        return "httpie"
    if "edge/" in raw or "edg/" in raw:
        return "edge"
    if "firefox/" in raw:
        return "firefox"
    if "chrome/" in raw and "safari/" in raw:
        return "chrome"
    if "safari/" in raw and "chrome/" not in raw:
        return "safari"
    if "mozilla/" in raw:
        return "mozilla"
    return "other"

def _is_monitor(req: Request) -> bool:
    if not _HP_MONITOR_SECRET:
        return False
    return secrets.compare_digest(
        (req.headers.get("x-internal-monitor") or "").strip(),
        _HP_MONITOR_SECRET,
    )


def _require_feature(feature: licensing.Feature) -> None:
    if not licensing.has_feature(feature):
        raise HTTPException(status_code=404, detail="Not found")


def _actor_id_from_request(req: Request) -> str:
    ip = _client_ip(req)
    ua = _user_agent(req)
    if HP_ACTOR_UA_MODE == "ip":
        ua = ""
    elif HP_ACTOR_UA_MODE == "family":
        ua = _normalize_ua(ua)
    raw = f"{ip}|{ua}|{HP_SEED}".encode("utf-8", errors="ignore")
    return hashlib.sha256(raw).hexdigest()


def _short_body_sample(body: bytes) -> str:
    if not body:
        return ""
    s = body.decode("utf-8", errors="ignore").strip()
    return (s[:600] + "…") if len(s) > 600 else s


def _safe_headers(req: Request) -> Dict[str, str]:
    # Full headers, but bounded size to avoid DB bloat
    out: Dict[str, str] = {}
    for k, v in req.headers.items():
        kk = str(k)[:80]
        vv = str(v)[:800]
        out[kk] = vv
    return out


async def _sleep_jitter(min_ms: int = 40, max_ms: int = 180) -> None:
    await asyncio.sleep(random.uniform(min_ms, max_ms) / 1000.0)


def _rand_points(min_points: int, max_points: int) -> int:
    if min_points > max_points:
        min_points, max_points = max_points, min_points
    return int(random.randint(min_points, max_points))


def _seeded_rng(actor_id: str, namespace: str) -> random.Random:
    seed = f"{actor_id}|{namespace}|{HP_SEED}".encode("utf-8", errors="ignore")
    seed_int = int(hashlib.sha256(seed).hexdigest()[:8], 16)
    return random.Random(seed_int)


def _fake_jwt(actor_id: str, scopes: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": f"user_{actor_id[:8]}",
        "scope": scopes,
        "aud": "account-api",
        "iss": "https://login.example.com",
        "iat": int(time.time()),
    }

    def _b64(obj: Dict[str, Any]) -> str:
        raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{_b64(header)}.{_b64(payload)}.{secrets.token_urlsafe(18)}"


def _hash_text(value: str) -> str:
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def _pattern_hits(value: str, patterns: Tuple[str, ...]) -> List[str]:
    if not value:
        return []
    low = value.lower()
    return [p for p in patterns if p in low]


def _is_scanner_ua(ua: str) -> bool:
    low = (ua or "").lower()
    return any(pat in low for pat in SCANNER_UA_PATTERNS)


def _set_hp_event(
    request: Request,
    *,
    kind: str,
    points: Optional[int] = None,
    trap_flags: Optional[List[str]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    request.state.hp_event = {
        "kind": kind,
        "points": points,
        "trap_flags": trap_flags or [],
        "extra": extra or {},
    }


def _is_public_ip(ip_s: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_s)
        return bool(ip_obj.is_global)
    except Exception:
        return False


def _flag_emoji_from_iso2(iso2: str) -> str:
    # ISO2 -> regional indicator symbols
    iso2 = (iso2 or "").strip().upper()
    if len(iso2) != 2 or not iso2.isalpha():
        return ""
    base = 0x1F1E6
    return chr(base + (ord(iso2[0]) - ord("A"))) + chr(base + (ord(iso2[1]) - ord("A")))


def _geoip_country(ip_s: str) -> Dict[str, Any]:
    # Optional, returns {} if no DB or no match
    if not _is_public_ip(ip_s):
        return {}
    if not HP_GEOIP_DB or not os.path.exists(HP_GEOIP_DB):
        return {}

    try:
        import geoip2.database  # type: ignore
    except Exception:
        return {}

    try:
        reader = geoip2.database.Reader(HP_GEOIP_DB)
        try:
            resp = reader.country(ip_s)
            iso = (resp.country.iso_code or "").strip().upper()
            name = (resp.country.name or "").strip()
            return {
                "country_iso2": iso,
                "country_name": name,
                "flag": _flag_emoji_from_iso2(iso),
            }
        finally:
            reader.close()
    except Exception:
        return {}


def _score_for(kind: str) -> int:
    table = {
        "probe": 1,
        "health": 0,
        "auth_token_request": 3,
        "token_issued": 5,
        "token_used": 6,
        "unknown_token": 4,
        "admin_login_attempt": 18,
        "admin_status": 6,
        "admin_rotate": 10,
        "export_users": 14,
        "export_audit": 14,
        "keys_issued": 14,
        "internal_config": 22,
        "backup_list": 26,
        "backup_download": 32,
        "admin_secrets": 48,
        "infra_vault": 60,
        "cloud_metadata": 74,
        "root_console": 90,
        "recon_docs": 2,
        "recon_openapi": 2,
        "recon_swagger": 2,
        "recon_redoc": 2,
        "recon_env": 5,
        "recon_config": 4,
        "recon_security": 2,
        "auth_login": 5,
        "auth_mfa": 2,
        "auth_forgot": 3,
        "auth_reset": 3,
        "auth_me": 3,
        "auth_sessions": 3,
        "auth_apikey": 6,
        "admin_home": 8,
        "admin_users": 10,
        "admin_audit": 10,
        "internal_access": 10,
        "internal_reload": 15,
        "internal_migrate": 15,
        "devops_webhook": 10,
        "devops_build": 12,
        "devops_pipeline": 6,
        "devops_artifact": 6,
        "business_users": 3,
        "business_accounts": 3,
        "business_transactions": 3,
        "business_payments": 3,
        "business_reports": 3,
        "console_exec": 5,
        "console_upload": 10,
        "console_history": 3,
        "root_shell": 20,
        "files_upload": 10,
        "files_meta": 2,
        "files_analysis": 5,
        "files_download": 3,
        "files_lookup": 3,
        "pipeline_job": 2,
        "upload_trap": 15,
    }
    return int(table.get(kind, 1))


def _bump_actor(conn: sqlite3.Connection, actor_id: str, score_delta: int = 0) -> None:
    now = _utc_now_iso()
    row = conn.execute("SELECT actor_id FROM actors WHERE actor_id=?", (actor_id,)).fetchone()
    if row:
        conn.execute(
            "UPDATE actors SET last_seen=?, score=score+? WHERE actor_id=?",
            (now, int(score_delta), actor_id),
        )
    else:
        conn.execute(
            "INSERT INTO actors(actor_id, first_seen, last_seen, score) VALUES(?,?,?,?)",
            (actor_id, now, now, int(score_delta)),
        )


def _update_actor_error_counters(conn: sqlite3.Connection, actor_id: str, status: int) -> None:
    # Count errors: 4xx/5xx. Track consecutive errors.
    now = _utc_now_iso()
    is_err = int(status >= 400)
    row = conn.execute(
        "SELECT err_total, err_consecutive FROM actors WHERE actor_id=?",
        (actor_id,),
    ).fetchone()
    if not row:
        # ensure actor exists
        _bump_actor(conn, actor_id, score_delta=0)
        row = conn.execute(
            "SELECT err_total, err_consecutive FROM actors WHERE actor_id=?",
            (actor_id,),
        ).fetchone()

    err_total = int(row["err_total"] or 0)
    err_consec = int(row["err_consecutive"] or 0)

    if is_err:
        err_total += 1
        err_consec += 1
        conn.execute(
            "UPDATE actors SET err_total=?, err_consecutive=?, last_status=?, last_error_ts=? WHERE actor_id=?",
            (err_total, err_consec, int(status), now, actor_id),
        )
    else:
        # reset consecutive on success
        conn.execute(
            "UPDATE actors SET err_consecutive=0, last_status=? WHERE actor_id=?",
            (int(status), actor_id),
        )


def _insert_event(
    conn: sqlite3.Connection,
    *,
    req: Request,
    kind: str,
    status: int,
    body: bytes = b"",
    token: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
    points_delta: Optional[int] = None,
    trap_flags: Optional[List[str]] = None,
) -> Optional[int]:
    # auto-migration for old DBs
    cols = [r[1] for r in conn.execute("PRAGMA table_info(events)").fetchall()]
    if "status" not in cols:
        conn.execute("ALTER TABLE events ADD COLUMN status INTEGER")
        conn.commit()

    actor_id = _actor_id_from_request(req)
    ip = _client_ip(req)
    ua = _user_agent(req)
    ts = _utc_now_iso()
    path = req.url.path
    method = req.method

    body_sample = _short_body_sample(body)
    score_before = _actor_score(conn, actor_id)
    stage_before = _stage_from_actor_score(score_before)

    base_points = points_delta if points_delta is not None else _score_for(kind)

    cur = conn.cursor()
    try:
        fp = f"{ip}|{ua}|{token or ''}"

        reuse_session = False
        session_id = None
        row = cur.execute(
            "SELECT session_id, ended_at FROM sessions WHERE actor_id=? AND fingerprint=? ORDER BY ended_at DESC LIMIT 1",
            (actor_id, fp),
        ).fetchone()
        if row:
            ended_at = row[1]
            try:
                from datetime import datetime

                dt_prev = datetime.fromisoformat((ended_at or "").replace("Z", "+00:00"))
                dt_now = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                gap = (dt_now - dt_prev).total_seconds()
                if gap <= (15 * 60):
                    reuse_session = True
                    session_id = row[0]
            except Exception:
                reuse_session = False

        if not reuse_session:
            # create new session id
            session_id = secrets.token_hex(8)
            cur.execute(
                "INSERT OR REPLACE INTO sessions(session_id, actor_id, started_at, ended_at, stage_max, summary, fingerprint) VALUES(?,?,?,?,?,?,?)",
                (session_id, actor_id, ts, ts, stage_before, None, fp),
            )
        else:
            # update ended_at
            cur.execute("UPDATE sessions SET ended_at=? WHERE session_id=?", (ts, session_id))

        multiplier = 1.5 if reuse_session else 1.0
        points_awarded = int(round(base_points * multiplier))
        _bump_actor(conn, actor_id, score_delta=points_awarded)
        score_after = score_before + points_awarded
        stage_after = _stage_from_actor_score(score_after)

        # update stage_max for the session
        row = cur.execute(
            "SELECT stage_max FROM sessions WHERE session_id=?",
            (session_id,),
        ).fetchone()
        stage_max = int(row[0] or 0) if row else 0
        if stage_after > stage_max:
            cur.execute("UPDATE sessions SET stage_max=? WHERE session_id=?", (stage_after, session_id))

        extra_payload = dict(extra or {})
        extra_payload.update(
            {
                "points_delta": points_awarded,
                "stage_before": stage_before,
                "stage_after": stage_after,
                "replay_id": session_id if reuse_session else None,
                "replay_multiplier": multiplier,
                "trap_flags": trap_flags or [],
            }
        )
        extra_json = json.dumps(extra_payload, ensure_ascii=False)

        # Insert event (legacy table)
        cur.execute(
            """
            INSERT INTO events(ts, actor_id, kind, path, method, ip, ua, status, body_sample, token, extra_json)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """,
            (ts, actor_id, kind, path, method, ip, ua, int(status), body_sample, token, extra_json),
        )
        event_id: Optional[int] = cur.lastrowid

        # insert session_step
        seq_row = cur.execute("SELECT COALESCE(MAX(seq),0) AS m FROM session_steps WHERE session_id=?", (session_id,)).fetchone()
        seq = int(seq_row[0] or 0) + 1
        headers_json = json.dumps(_safe_headers(req), ensure_ascii=False)
        query_json = json.dumps(dict(req.query_params), ensure_ascii=False)
        body_json = None
        try:
            body_json = body.decode("utf-8", errors="ignore") if body else None
        except Exception:
            body_json = None

        cur.execute(
            "INSERT INTO session_steps(session_id, seq, ts, method, path, query_json, headers_json, body_json, response_status, response_json, stage_before, stage_after) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                session_id,
                seq,
                ts,
                method,
                path,
                query_json,
                headers_json,
                body_json,
                int(status),
                None,
                stage_before,
                stage_after,
            ),
        )

        conn.commit()
        return event_id
    except Exception as e:
        # Log error but never fail the public API
        _logger.warning("Session bookkeeping error: %s", e)
        try:
            conn.rollback()
        except Exception:
            pass
    return None


def _token_lookup(conn: sqlite3.Connection, token: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT token, actor_id, used_count, last_used_ts, stage, gift_type, created_ts FROM tokens WHERE token=?",
        (token,),
    ).fetchone()


def _token_mark_used(conn: sqlite3.Connection, token: str) -> None:
    now = _utc_now_iso()
    conn.execute(
        "UPDATE tokens SET used_count=used_count+1, last_used_ts=? WHERE token=?",
        (now, token),
    )


def _mint_token() -> str:
    return secrets.token_urlsafe(24)


def _actor_score(conn: sqlite3.Connection, actor_id: str) -> int:
    r = conn.execute("SELECT score FROM actors WHERE actor_id=?", (actor_id,)).fetchone()
    return int(r["score"]) if r else 0


def _stage_from_actor_score(score: int) -> int:
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


def _get_or_create_secret(conn: sqlite3.Connection, actor_id: str, kind: str, prefix: str) -> str:
    row = conn.execute(
        "SELECT value FROM issued_secrets WHERE actor_id=? AND kind=?",
        (actor_id, kind),
    ).fetchone()
    if row:
        return str(row["value"])

    raw = f"{actor_id}|{kind}|{HP_SEED}".encode("utf-8", errors="ignore")
    h = hashlib.sha256(raw).hexdigest()[:24]
    value = f"{prefix}_{h}"

    conn.execute(
        "INSERT INTO issued_secrets(actor_id, kind, value, created_ts) VALUES(?,?,?,?)",
        (actor_id, kind, value, _utc_now_iso()),
    )
    conn.commit()
    return value


def _issued_lookup(conn: sqlite3.Connection, kind: str, value: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT actor_id, kind, value FROM issued_secrets WHERE kind=? AND value=?",
        (kind, value),
    ).fetchone()


# -------------------------
# Auth layers
# -------------------------
def require_bearer(
    request: Request,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> str:
    if _is_monitor(request):
        if creds and creds.credentials:
            return creds.credentials[:200]
        return "monitor-token"
    if not creds or not creds.credentials:
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = creds.credentials[:200]

    conn = _db()
    try:
        _ensure_schema(conn)
        row = _token_lookup(conn, token)
        if not row:
            raise HTTPException(status_code=401, detail="Unauthorized")
        _token_mark_used(conn, token)
        conn.commit()
    finally:
        conn.close()

    return token


def require_api_key(request: Request) -> str:
    api_key = (request.headers.get("x-api-key") or "").strip()[:200]
    if _is_monitor(request):
        return api_key or "ak_live_monitor"
    if not api_key:
        raise HTTPException(status_code=401, detail="Unauthorized")

    conn = _db()
    try:
        _ensure_schema(conn)
        row = _issued_lookup(conn, "api_key", api_key)
        if not row:
            raise HTTPException(status_code=401, detail="Unauthorized")
    finally:
        conn.close()

    return api_key


def require_backup_token(request: Request) -> str:
    bkp = (request.headers.get("x-backup-token") or "").strip()[:200]
    if _is_monitor(request):
        return bkp or "bkp_monitor"
    if not bkp:
        raise HTTPException(status_code=401, detail="Unauthorized")

    conn = _db()
    try:
        _ensure_schema(conn)
        row = _issued_lookup(conn, "backup_token", bkp)
        if not row:
            raise HTTPException(status_code=401, detail="Unauthorized")
    finally:
        conn.close()

    return bkp


def require_admin_secret(request: Request) -> str:
    adm = (request.headers.get("x-admin-secret") or "").strip()[:200]
    if _is_monitor(request):
        return adm or "adm_monitor"
    if not adm:
        raise HTTPException(status_code=401, detail="Unauthorized")

    conn = _db()
    try:
        _ensure_schema(conn)
        row = _issued_lookup(conn, "admin_secret", adm)
        if not row:
            raise HTTPException(status_code=401, detail="Unauthorized")
    finally:
        conn.close()

    return adm


def require_vault_token(request: Request) -> str:
    v = (request.headers.get("x-vault-token") or "").strip()[:200]
    if _is_monitor(request):
        return v or "vault_monitor"
    if not v:
        raise HTTPException(status_code=401, detail="Unauthorized")

    conn = _db()
    try:
        _ensure_schema(conn)
        row = _issued_lookup(conn, "vault_token", v)
        if not row:
            raise HTTPException(status_code=401, detail="Unauthorized")
    finally:
        conn.close()

    return v


def require_cloud_token(request: Request) -> str:
    c = (request.headers.get("x-cloud-token") or "").strip()[:200]
    if _is_monitor(request):
        return c or "cloud_monitor"
    if not c:
        raise HTTPException(status_code=401, detail="Unauthorized")

    conn = _db()
    try:
        _ensure_schema(conn)
        row = _issued_lookup(conn, "cloud_token", c)
        if not row:
            raise HTTPException(status_code=401, detail="Unauthorized")
    finally:
        conn.close()

    return c


def require_root_token(request: Request) -> str:
    r = (request.headers.get("x-root-token") or "").strip()[:200]
    if _is_monitor(request):
        return r or "root_monitor"
    if not r:
        raise HTTPException(status_code=401, detail="Unauthorized")

    conn = _db()
    try:
        _ensure_schema(conn)
        row = _issued_lookup(conn, "root_token", r)
        if not row:
            raise HTTPException(status_code=401, detail="Unauthorized")
    finally:
        conn.close()

    return r


def _extract_bearer_token(request: Request) -> str:
    auth = (request.headers.get("authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()[:200]
    return ""


def _token_actor(conn: sqlite3.Connection, token: str) -> Optional[str]:
    if not token:
        return None
    row = _token_lookup(conn, token)
    if not row:
        return None
    return str(row["actor_id"])


def _token_is_valid(conn: sqlite3.Connection, token: str) -> bool:
    return bool(_token_lookup(conn, token))


def _issued_is_valid(conn: sqlite3.Connection, kind: str, value: str) -> bool:
    if not value:
        return False
    return bool(_issued_lookup(conn, kind, value))


def _ensure_playground_tables(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS honeypot_jobs (
          job_id TEXT PRIMARY KEY,
          created_ts TEXT NOT NULL,
          updated_ts TEXT,
          actor_id TEXT,
          kind TEXT,
          status TEXT,
          payload_json TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_hp_jobs_created ON honeypot_jobs(created_ts)")
    conn.commit()


def _ensure_sample_assets(conn: sqlite3.Connection) -> None:
    _ensure_playground_tables(conn)
    now = _utc_now_iso()

    # sample job
    row = conn.execute(
        "SELECT job_id FROM honeypot_jobs WHERE job_id=?",
        (SAMPLE_JOB_ID,),
    ).fetchone()
    if not row:
        payload = {"duration_s": 5}
        created_ts = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat(timespec="seconds").replace("+00:00", "Z")
        conn.execute(
            "INSERT INTO honeypot_jobs(job_id, created_ts, updated_ts, actor_id, kind, status, payload_json) VALUES(?,?,?,?,?,?,?)",
            (SAMPLE_JOB_ID, created_ts, created_ts, "system", "sample", "completed", json.dumps(payload, ensure_ascii=False)),
        )
    conn.commit()


def _job_status(created_ts: str, duration_s: int) -> str:
    try:
        dt_created = datetime.fromisoformat(created_ts.replace("Z", "+00:00"))
    except Exception:
        return "queued"
    elapsed = (datetime.now(timezone.utc) - dt_created).total_seconds()
    if elapsed < duration_s * 0.3:
        return "queued"
    if elapsed < duration_s:
        return "running"
    return "completed"


def _create_job(conn: sqlite3.Connection, actor_id: str, kind: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    _ensure_playground_tables(conn)
    job_id = f"job_{secrets.token_hex(8)}"
    now = _utc_now_iso()
    duration = int(payload.get("duration_s") or random.randint(8, 25))
    payload = dict(payload or {})
    payload["duration_s"] = duration
    conn.execute(
        "INSERT INTO honeypot_jobs(job_id, created_ts, updated_ts, actor_id, kind, status, payload_json) VALUES(?,?,?,?,?,?,?)",
        (job_id, now, now, actor_id, kind, "queued", json.dumps(payload, ensure_ascii=False)),
    )
    conn.commit()
    return {"job_id": job_id, "status": "queued", "eta_s": duration}


def _job_snapshot(conn: sqlite3.Connection, job_id: str) -> Optional[Dict[str, Any]]:
    _ensure_playground_tables(conn)
    row = conn.execute(
        "SELECT job_id, created_ts, updated_ts, actor_id, kind, status, payload_json FROM honeypot_jobs WHERE job_id=?",
        (job_id,),
    ).fetchone()
    if not row:
        return None
    payload = {}
    try:
        payload = json.loads(row["payload_json"] or "{}")
    except Exception:
        payload = {}
    duration = int(payload.get("duration_s") or 15)
    status = _job_status(row["created_ts"], duration)
    if status != row["status"]:
        conn.execute("UPDATE honeypot_jobs SET status=?, updated_ts=? WHERE job_id=?", (status, _utc_now_iso(), job_id))
        conn.commit()
    return {
        "job_id": row["job_id"],
        "created_ts": row["created_ts"],
        "status": status,
        "kind": row["kind"],
        "payload": payload,
    }


async def _read_json_or_form(request: Request) -> Dict[str, Any]:
    ct = (request.headers.get("content-type") or "").lower()
    if "application/json" in ct:
        try:
            data = await request.json()
            if isinstance(data, dict):
                return data
        except Exception:
            return {}
    if "application/x-www-form-urlencoded" in ct or "multipart/form-data" in ct:
        try:
            form = await request.form()
            return {k: v for k, v in form.items()}
        except Exception:
            return {}
    body = await request.body()
    try:
        data = json.loads(body.decode("utf-8", errors="ignore") or "{}")
        if isinstance(data, dict):
            return data
    except Exception:
        return {}
    return {}

@app.middleware("http")
async def log_all_requests(request: Request, call_next):
    body = await request.body()
    _request_id = (request.headers.get("x-request-id") or secrets.token_hex(16)).strip()[:128]
    set_request_id(_request_id)

    # --- endpoint enabled check ---
    # Paths that are never subject to endpoint config (infrastructure).
    _SKIP_POLICY_PREFIXES = (
        "/health", "/ready", "/version",
        "/docs", "/redoc", "/openapi.json", "/static/",
    )
    _rpath = request.url.path
    if not _is_monitor(request) and not any(
        _rpath == p or _rpath.startswith(p) for p in _SKIP_POLICY_PREFIXES
    ):
        try:
            _conn_p = _db()
            try:
                api_modular.ensure_tables(_conn_p)
                _ec = api_modular.resolve_endpoint_config(
                    _conn_p,
                    path=_rpath,
                    method=request.method,
                    ensure_schema=False,
                )
            finally:
                _conn_p.close()
            if not bool(_ec["config"].get("enabled", True)):
                _fs = int(_ec["config"].get("fixed_status") or 404)
                return JSONResponse(
                    status_code=_fs,
                    content={"detail": "Not found"},
                )
        except Exception:
            pass  # never block requests due to config lookup failure

    t0 = time.perf_counter()
    response = None
    exc = None
    skip_log = False
    try:
        response = await call_next(request)
    except Exception as e:
        exc = e
        raise
    finally:
        if request.url.path.startswith("/static/"):
            skip_log = True
        if _is_monitor(request):
            skip_log = True
        # Skip internal probes identified by User-Agent (e.g. Docker healthchecks).
        # HONEYPOT_MONITOR_UA can be a comma-separated list of substrings.
        if not skip_log and HONEYPOT_MONITOR_UA:
            req_ua_lower = _user_agent(request).lower()
            for _mua in HONEYPOT_MONITOR_UA.split(","):
                _mua = _mua.strip().lower()
                if _mua and _mua in req_ua_lower:
                    skip_log = True
                    break

        if not skip_log:
            latency_ms = int((time.perf_counter() - t0) * 1000.0)

            kind = "probe"
            if request.url.path == "/health":
                kind = "health"

            token = None
            auth = (request.headers.get("authorization") or "").strip()
            if auth.lower().startswith("bearer "):
                token = auth.split(" ", 1)[1].strip()[:200]

            status_code = 0
            if response is not None:
                status_code = getattr(response, "status_code", 0) or 0
            elif exc is not None:
                status_code = 500

            actor_id = _actor_id_from_request(request)
            ip = _client_ip(request)
            ua = _user_agent(request)

            # extras requested:
            # - full headers
            # - latency per request
            # - geoip for public IP (flag)
            # - error counters per actor (stored in actors table; also surface snapshot here)
            req_headers = _safe_headers(request)
            geo = _geoip_country(ip)

            conn = _db()
            try:
                _ensure_schema(conn)

                hp_event = getattr(request.state, "hp_event", None)
                path = request.url.path
                if not hp_event:
                    recon_map = {
                        "/docs": "recon_docs",
                        "/openapi.json": "recon_openapi",
                        "/redoc": "recon_redoc",
                        "/swagger": "recon_swagger",
                        "/.env": "recon_env",
                        "/config.json": "recon_config",
                        "/.well-known/security.txt": "recon_security",
                    }
                    if path in recon_map:
                        recon_kind = recon_map[path]
                        points = _rand_points(1, 3)
                        if recon_kind in ("recon_env", "recon_config"):
                            points = _rand_points(3, 6)
                        hp_event = {
                            "kind": recon_kind,
                            "points": points,
                            "trap_flags": ["recon"],
                            "extra": {
                                "recon": True,
                                "openapi": path == "/openapi.json",
                                "scanner": _is_scanner_ua(ua),
                                "endpoint_count": len(app.routes),
                            },
                        }

                token_valid = False
                if token:
                    if _token_lookup(conn, token):
                        token_valid = True
                        if not hp_event:
                            kind = "token_used"
                    else:
                        if not hp_event:
                            kind = "unknown_token"

                if hp_event:
                    kind = hp_event.get("kind", kind)

                _insert_event(
                    conn,
                    req=request,
                    kind=kind,
                    status=status_code,
                    body=body,
                    token=token,
                    points_delta=hp_event.get("points") if hp_event else None,
                    trap_flags=hp_event.get("trap_flags") if hp_event else None,
                    extra={
                        "rt": "mw",
                        "latency_ms": latency_ms,
                        "headers": req_headers,
                        "geo": geo,
                        "token_valid": token_valid,
                        **(hp_event.get("extra") if hp_event else {}),
                    },
                )

                _update_actor_error_counters(conn, actor_id, int(status_code))

                # add counters snapshot to this event (optional, but helps dashboards)
                row = conn.execute(
                    "SELECT err_total, err_consecutive, last_status, last_error_ts FROM actors WHERE actor_id=?",
                    (actor_id,),
                ).fetchone()
                if row:
                    # update the just-inserted event's extra_json with counter snapshot
                    # (keep it lightweight; do not rewrite headers)
                    last_event_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
                    try:
                        existing = conn.execute("SELECT extra_json FROM events WHERE id=?", (last_event_id,)).fetchone()
                        extra_obj = json.loads(existing["extra_json"] or "{}")
                    except Exception:
                        extra_obj = {}
                    extra_obj["err_total"] = int(row["err_total"] or 0)
                    extra_obj["err_consecutive"] = int(row["err_consecutive"] or 0)
                    extra_obj["last_status"] = row["last_status"]
                    extra_obj["last_error_ts"] = row["last_error_ts"]
                    conn.execute(
                        "UPDATE events SET extra_json=? WHERE id=?",
                        (json.dumps(extra_obj, ensure_ascii=False), int(last_event_id)),
                    )

                conn.commit()

                # Critical-event webhook alert (non-blocking, never raises)
                # Core edition: fires only for root_console, cloud_metadata, infra_vault
                _event_score_delta = int((hp_event.get("points") if hp_event else None) or _score_for(kind))
                _current_actor_score = _actor_score(conn, actor_id)
                alert_dispatcher.fire_if_high_signal(
                    kind=kind,
                    actor_id=actor_id,
                    ip=_client_ip(request),
                    ua=_user_agent(request),
                    path=request.url.path,
                    score_delta=_event_score_delta,
                    trap_flags=(hp_event.get("trap_flags") if hp_event else None) or [],
                    current_score=_current_actor_score,
                )
            finally:
                conn.close()

    if response is None:
        response = JSONResponse(status_code=500, content={"detail": "Internal Server Error"})
    response.headers["X-Request-ID"] = _request_id
    return response


@app.get("/health", tags=["Health"], response_class=JSONResponse)
async def health(request: Request):
    """Liveness check."""
    return JSONResponse(_health.liveness())


@app.get("/ready", tags=["Health"], response_class=JSONResponse)
async def ready(request: Request):
    """Readiness check (database + schema)."""
    payload = _health.readiness(DB_PATH)
    status_code = 200 if payload["status"] == "ok" else 503
    return JSONResponse(payload, status_code=status_code)


@app.get("/version", tags=["Health"], response_class=JSONResponse)
async def version(request: Request):
    """Version/build metadata."""
    return JSONResponse(_health.version_info())


@app.get("/status", tags=["Health"], response_class=JSONResponse)
async def status(request: Request):
    await _sleep_jitter()
    actor = _actor_id_from_request(request)
    payload = {
        "status": "ok",
        "service": "noctisapi",
        "instance": actor[:12],
        "version": APP_VERSION,
    }
    return JSONResponse(payload)


@app.get("/", tags=["Health"], response_class=JSONResponse)
async def root():
    return {"service": "api", "status": "ok", "version": APP_VERSION}


@app.post(
    "/v1/auth/token",
    tags=["Auth"],
    response_class=JSONResponse,
    summary="Issue an access token",
)
async def issue_token(request: Request):
    body = await request.body()

    username = ""
    password = ""
    grant_type = ""

    ct = (request.headers.get("content-type") or "").lower()
    if "application/json" in ct:
        try:
            data = json.loads(body.decode("utf-8", errors="ignore") or "{}")
        except Exception:
            data = {}
        username = str(data.get("username") or data.get("user") or "")
        password = str(data.get("password") or data.get("pass") or "")
        grant_type = str(data.get("grant_type") or "")
    else:
        form = await request.form()
        username = str(form.get("username") or form.get("user") or "")
        password = str(form.get("password") or form.get("pass") or "")
        grant_type = str(form.get("grant_type") or "")

    if _is_monitor(request):
        token = _mint_token()
    else:
        conn = _db()
        try:
            _ensure_schema(conn)

            actor_id = _actor_id_from_request(request)
            score = _actor_score(conn, actor_id)
            stage = _stage_from_actor_score(score)

            token = _mint_token()
            conn.execute(
                """
                INSERT INTO tokens(actor_id, token, created_ts, stage, gift_type, used_count, last_used_ts)
                VALUES(?,?,?,?,?,?,?)
                """,
                (actor_id, token, _utc_now_iso(), int(stage), "standard", 0, None),
            )
            conn.commit()
        finally:
            conn.close()

    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "read",
    }


@app.get(
    "/v1/account",
    tags=["Account"],
    response_class=JSONResponse,
    summary="Get current account",
)
async def account_me(request: Request, token: str = Depends(require_bearer)):
    if _is_monitor(request):
        return {
            "id": "acc_monitor",
            "plan": "standard",
            "status": "active",
            "risk": {"score": 0, "tier": 0},
        }

    conn = _db()
    try:
        _ensure_schema(conn)
        row = _token_lookup(conn, token)
        actor_id = str(row["actor_id"])
        score = _actor_score(conn, actor_id)
        stage = _stage_from_actor_score(score)
    finally:
        conn.close()

    return {
        "id": "acc_" + actor_id[:12],
        "plan": "standard",
        "status": "active",
        "risk": {"score": score, "tier": stage},
    }


@app.get("/v1/keys", tags=["Account"], response_class=JSONResponse, summary="List API keys")
async def list_keys(request: Request, token: str = Depends(require_bearer)):
    if _is_monitor(request):
        api_key = "ak_live_" + secrets.token_hex(8)
        return {
            "api_key": api_key,
            "scope": "internal",
            "hint": "Use X-API-Key header for /internal/*",
            "backup_token": None,
            "backup_hint": "Backup token appears after more activity",
        }

    conn = _db()
    try:
        _ensure_schema(conn)
        if _is_monitor(request):
            api_key = "ak_live_" + secrets.token_hex(8)
            backup_token = None
        else:
            row = _token_lookup(conn, token)
            actor_id = str(row["actor_id"])
            score = _actor_score(conn, actor_id)
            stage = _stage_from_actor_score(score)

            api_key = _get_or_create_secret(conn, actor_id, "api_key", "ak_live")

            backup_token = None
            if stage >= 3:
                backup_token = _get_or_create_secret(conn, actor_id, "backup_token", "bkp")

            _bump_actor(conn, actor_id, score_delta=_score_for("keys_issued"))
            conn.commit()
    finally:
        conn.close()

    return {
        "api_key": api_key,
        "scope": "internal",
        "hint": "Use X-API-Key header for /internal/*",
        "backup_token": backup_token,
        "backup_hint": "Backup token appears after more activity",
    }


@app.get("/internal/config", include_in_schema=False, response_class=JSONResponse)
async def internal_config(request: Request, api_key: str = Depends(require_api_key)):
    conn = _db()
    try:
        _ensure_schema(conn)
        actor_id = _actor_id_from_request(request)

        payload = {
            "service": "account-api",
            "region": "eu",
            "db_host": "db.internal",
            "db_user": "service",
            "db_pass": _get_or_create_secret(conn, actor_id, "db_pass", "svc"),
            "backup_hint": "Use X-Backup-Token for /backup/*",
        }

        _bump_actor(conn, actor_id, score_delta=_score_for("internal_config"))
        conn.commit()
    finally:
        conn.close()

    return payload


# --- Honeypot playground endpoints ---
def _fake_users(actor_id: str, limit: int = 20, offset: int = 0) -> List[Dict[str, Any]]:
    rng = _seeded_rng(actor_id, f"users:{offset}")
    users = []
    for _ in range(limit):
        uid = f"u_{rng.randint(10000, 99999)}"
        users.append(
            {
                "id": uid,
                "email": f"user{rng.randint(100, 999)}@example.com",
                "name": f"User {rng.randint(100, 999)}",
                "status": rng.choice(["active", "pending", "locked"]),
                "created_at": _utc_now_iso(),
            }
        )
    return users


def _fake_accounts(actor_id: str, limit: int = 20, offset: int = 0) -> List[Dict[str, Any]]:
    rng = _seeded_rng(actor_id, f"accounts:{offset}")
    accounts = []
    for _ in range(limit):
        accounts.append(
            {
                "id": f"acc_{rng.randint(1000, 9999)}",
                "type": rng.choice(["card", "bank", "wallet"]),
                "currency": rng.choice(["USD", "EUR", "GBP"]),
                "balance": round(rng.uniform(120.0, 9400.0), 2),
                "status": rng.choice(["active", "hold"]),
            }
        )
    return accounts


def _fake_transactions(actor_id: str, limit: int = 20, offset: int = 0) -> List[Dict[str, Any]]:
    rng = _seeded_rng(actor_id, f"tx:{offset}")
    txs = []
    for _ in range(limit):
        txs.append(
            {
                "id": f"tx_{rng.randint(100000, 999999)}",
                "amount": round(rng.uniform(4.0, 1200.0), 2),
                "currency": rng.choice(["USD", "EUR", "GBP"]),
                "status": rng.choice(["settled", "pending", "rejected"]),
                "merchant": rng.choice(["Acme Corp", "Globex", "Initrode", "Umbrella"]),
                "timestamp": _utc_now_iso(),
            }
        )
    return txs


def _pagination_from_request(request: Request) -> Tuple[int, int, bool]:
    limit = int(request.query_params.get("limit", "20") or 20)
    offset = int(request.query_params.get("offset", "0") or 0)
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    aggressive = limit > 100 or offset > 500
    return limit, offset, aggressive


@app.get("/swagger", tags=["Recon"], response_class=HTMLResponse)
async def swagger_decoy(request: Request):
    await _sleep_jitter()
    _set_hp_event(
        request,
        kind="recon_swagger",
        points=_rand_points(1, 3),
        trap_flags=["recon"],
        extra={"scanner": _is_scanner_ua(_user_agent(request))},
    )
    html = """
    <html>
      <head><title>Platform API - Swagger UI</title></head>
      <body style="font-family: sans-serif; padding: 20px;">
        <h2>Platform API - Swagger UI</h2>
        <p>OpenAPI spec: <a href="/openapi.json">/openapi.json</a></p>
      </body>
    </html>
    """
    return HTMLResponse(html)


@app.get("/.env", tags=["Recon"], response_class=PlainTextResponse)
async def recon_env(request: Request):
    await _sleep_jitter()
    _set_hp_event(
        request,
        kind="recon_env",
        points=_rand_points(3, 6),
        trap_flags=["recon", "secrets"],
        extra={"scanner": _is_scanner_ua(_user_agent(request))},
    )
    payload = "\n".join(
        [
            "APP_ENV=production",
            "APP_NAME=Platform API",
            "DB_HOST=10.12.0.8",
            "DB_PORT=5432",
            "DB_NAME=platform",
            "DB_USER=platform_svc",
            "DB_PASSWORD=SuperSecret123!",
            "JWT_ISSUER=https://example.com",
            "JWT_AUDIENCE=noctisapi",
            "JWT_SECRET=dev_only_change_me",
            "REDIS_URL=redis://10.12.0.9:6379/0",
            "S3_BUCKET=platform-assets",
            "S3_REGION=eu-west-1",
            "PUBLIC_BASE_URL=https://example.com",
            "SUPPORT_EMAIL=support@example.com",
        ]
    )
    return PlainTextResponse(payload)


@app.get("/config.json", tags=["Recon"], response_class=JSONResponse)
async def recon_config(request: Request):
    await _sleep_jitter()
    _set_hp_event(
        request,
        kind="recon_config",
        points=_rand_points(3, 6),
        trap_flags=["recon", "config"],
        extra={"scanner": _is_scanner_ua(_user_agent(request))},
    )
    return JSONResponse(
        {
            "service": "noctisapi",
            "region": "eu-west-1",
            "auth": {
                "issuer": "https://example.com",
                "jwks": "/.well-known/jwks.json",
                "audience": "noctisapi",
            },
            "features": {"beta_access": True, "sandbox_mode": False, "webhooks": True},
            "contact": {"support": "support@example.com"},
        }
    )


@app.get("/.well-known/security.txt", tags=["Recon"], response_class=PlainTextResponse)
async def recon_security(request: Request):
    await _sleep_jitter()
    _set_hp_event(
        request,
        kind="recon_security",
        points=_rand_points(1, 3),
        trap_flags=["recon"],
        extra={"scanner": _is_scanner_ua(_user_agent(request))},
    )
    payload = "\n".join(
        [
            "Contact: security@example.com",
            "Encryption: https://example.com/pgp.txt",
            "Preferred-Languages: en, es",
            "Policy: https://example.com/security",
        ]
    )
    return PlainTextResponse(payload)


@app.post("/auth/login", tags=["Auth"], response_class=JSONResponse)
async def auth_login(request: Request):
    await _sleep_jitter()
    data = await _read_json_or_form(request)
    username = str(data.get("username") or data.get("user") or "")
    password = str(data.get("password") or data.get("pass") or "")
    scopes = str(data.get("scope") or data.get("scopes") or "read write")

    if _is_monitor(request):
        token_issued = True
        token = _fake_jwt("monitor", scopes)
    else:
        conn = _db()
        try:
            _ensure_schema(conn)
            actor_id = _actor_id_from_request(request)
            token_issued = random.random() < 0.7
            token = None
            if token_issued:
                token = _fake_jwt(actor_id, scopes)[:200]
                stage = _stage_from_actor_score(_actor_score(conn, actor_id))
                conn.execute(
                    """
                    INSERT INTO tokens(actor_id, token, created_ts, stage, gift_type, used_count, last_used_ts)
                    VALUES(?,?,?,?,?,?,?)
                    """,
                    (actor_id, token, _utc_now_iso(), int(stage), "login", 0, None),
                )
                conn.commit()

            points = 5 + (8 if token_issued else 0)
            _set_hp_event(
                request,
                kind="auth_login",
                points=points,
                trap_flags=["auth"],
                extra={
                    "username": username,
                    "password_hash": _hash_text(password),
                    "scopes": scopes,
                    "token_fingerprint": _hash_text(token or ""),
                    "token_issued": token_issued,
                },
            )
        finally:
            conn.close()

    if not token_issued:
        return JSONResponse(status_code=401, content={"error": "invalid_credentials"})

    return JSONResponse(
        {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": scopes,
            "mfa_required": random.random() < 0.4,
        }
    )


@app.post("/auth/mfa", tags=["Auth"], response_class=JSONResponse)
async def auth_mfa(request: Request):
    await _sleep_jitter()
    data = await _read_json_or_form(request)
    code = str(data.get("code") or data.get("otp") or "")
    success = code == "000000" or random.random() < 0.1

    if _is_monitor(request):
        token = _fake_jwt("monitor", "read write") if success else None
    else:
        conn = _db()
        try:
            _ensure_schema(conn)
            actor_id = _actor_id_from_request(request)
            token = None
            if success:
                token = _fake_jwt(actor_id, "read write")[:200]
                stage = _stage_from_actor_score(_actor_score(conn, actor_id))
                conn.execute(
                    """
                    INSERT INTO tokens(actor_id, token, created_ts, stage, gift_type, used_count, last_used_ts)
                    VALUES(?,?,?,?,?,?,?)
                    """,
                    (actor_id, token, _utc_now_iso(), int(stage), "mfa", 0, None),
                )
                conn.commit()

            _set_hp_event(
                request,
                kind="auth_mfa",
                points=2 + (8 if success else 0),
                trap_flags=["auth"],
                extra={"mfa_code": code, "mfa_passed": success, "token_fingerprint": _hash_text(token or "")},
            )
        finally:
            conn.close()

    if not success:
        return JSONResponse(status_code=401, content={"error": "mfa_failed"})
    return JSONResponse({"access_token": token, "token_type": "Bearer", "expires_in": 3600})


@app.post("/auth/forgot", tags=["Auth"], response_class=JSONResponse)
async def auth_forgot(request: Request):
    await _sleep_jitter()
    data = await _read_json_or_form(request)
    email = str(data.get("email") or data.get("user") or "")
    if not _is_monitor(request):
        _set_hp_event(
            request,
            kind="auth_forgot",
            points=3,
            trap_flags=["auth"],
            extra={"email": email},
        )
    return JSONResponse({"status": "ok", "reset_hint": "Check your email for a reset link."})


@app.post("/auth/reset", tags=["Auth"], response_class=JSONResponse)
async def auth_reset(request: Request):
    await _sleep_jitter()
    data = await _read_json_or_form(request)
    token = str(data.get("token") or data.get("reset_token") or "")
    password = str(data.get("password") or "")
    if not _is_monitor(request):
        _set_hp_event(
            request,
            kind="auth_reset",
            points=3,
            trap_flags=["auth"],
            extra={"reset_token": token, "password_hash": _hash_text(password)},
        )
    return JSONResponse({"status": "ok", "message": "Password updated."})


@app.get("/me", tags=["Auth"], response_class=JSONResponse)
async def auth_me(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Security(security)):
    await _sleep_jitter()
    if _is_monitor(request):
        return JSONResponse({"id": "user_me", "name": "Service User", "role": "member"})
    conn = _db()
    try:
        _ensure_schema(conn)
        token = (creds.credentials if creds else "").strip()[:200]
        if not _token_is_valid(conn, token):
            if not _is_monitor(request):
                _set_hp_event(request, kind="auth_me", points=0, trap_flags=["auth"], extra={"token_valid": False})
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
        if not _is_monitor(request):
            _set_hp_event(
                request,
                kind="auth_me",
                points=3,
                trap_flags=["auth"],
                extra={"token_fingerprint": _hash_text(token)},
            )
    finally:
        conn.close()
    return JSONResponse({"id": "user_me", "name": "Service User", "role": "member"})


@app.get("/sessions", tags=["Auth"], response_class=JSONResponse)
async def auth_sessions(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Security(security)):
    await _sleep_jitter()
    if _is_monitor(request):
        return JSONResponse({"sessions": []})
    conn = _db()
    try:
        _ensure_schema(conn)
        token = (creds.credentials if creds else "").strip()[:200]
        if not _token_is_valid(conn, token):
            if not _is_monitor(request):
                _set_hp_event(request, kind="auth_sessions", points=0, trap_flags=["auth"], extra={"token_valid": False})
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
        actor_id = _token_actor(conn, token) or _actor_id_from_request(request)
        rows = conn.execute(
            "SELECT session_id, started_at, ended_at, stage_max FROM sessions WHERE actor_id=? ORDER BY started_at DESC LIMIT 10",
            (actor_id,),
        ).fetchall()
        sessions = [
            {"id": r["session_id"], "started_at": r["started_at"], "ended_at": r["ended_at"], "stage": r["stage_max"]}
            for r in rows
        ]
        if not _is_monitor(request):
            _set_hp_event(
                request,
                kind="auth_sessions",
                points=3,
                trap_flags=["auth"],
                extra={"session_count": len(sessions)},
            )
    finally:
        conn.close()
    return JSONResponse({"sessions": sessions})


@app.delete("/sessions/{session_id}", tags=["Auth"], response_class=JSONResponse)
async def auth_sessions_delete(
    session_id: str,
    request: Request,
    creds: Optional[HTTPAuthorizationCredentials] = Security(security),
):
    await _sleep_jitter()
    if _is_monitor(request):
        return JSONResponse({"status": "deleted", "id": session_id})
    conn = _db()
    try:
        _ensure_schema(conn)
        token = (creds.credentials if creds else "").strip()[:200]
        if not _token_is_valid(conn, token):
            if not _is_monitor(request):
                _set_hp_event(request, kind="auth_sessions", points=0, trap_flags=["auth"], extra={"token_valid": False})
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
        if not _is_monitor(request):
            _set_hp_event(
                request,
                kind="auth_sessions",
                points=3,
                trap_flags=["auth"],
                extra={"deleted_session": session_id},
            )
    finally:
        conn.close()
    return JSONResponse({"status": "deleted", "id": session_id})


@app.post("/apikeys", tags=["Auth"], response_class=JSONResponse)
async def auth_apikeys_post(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Security(security)):
    await _sleep_jitter()
    if _is_monitor(request):
        api_key = "ak_live_" + secrets.token_hex(8)
        return JSONResponse({"api_key": api_key, "scopes": ["read", "write"]})
    conn = _db()
    try:
        _ensure_schema(conn)
        token = (creds.credentials if creds else "").strip()[:200]
        if not _token_is_valid(conn, token):
            if not _is_monitor(request):
                _set_hp_event(request, kind="auth_apikey", points=0, trap_flags=["auth"], extra={"token_valid": False})
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
        actor_id = _token_actor(conn, token) or _actor_id_from_request(request)
        if _is_monitor(request):
            api_key = "ak_live_" + secrets.token_hex(8)
        else:
            api_key = _get_or_create_secret(conn, actor_id, "api_key", "ak_live")
            _set_hp_event(
                request,
                kind="auth_apikey",
                points=6,
                trap_flags=["auth"],
                extra={"api_key_fingerprint": _hash_text(api_key)},
            )
    finally:
        conn.close()
    return JSONResponse({"api_key": api_key, "scopes": ["read", "write"]})


@app.get("/apikeys", tags=["Auth"], response_class=JSONResponse)
async def auth_apikeys_get(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Security(security)):
    await _sleep_jitter()
    if _is_monitor(request):
        api_key = "ak_live_" + secrets.token_hex(8)
        return JSONResponse({"api_key": api_key, "scopes": ["read", "write"]})
    conn = _db()
    try:
        _ensure_schema(conn)
        token = (creds.credentials if creds else "").strip()[:200]
        if not _token_is_valid(conn, token):
            if not _is_monitor(request):
                _set_hp_event(request, kind="auth_apikey", points=0, trap_flags=["auth"], extra={"token_valid": False})
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
        actor_id = _token_actor(conn, token) or _actor_id_from_request(request)
        if _is_monitor(request):
            api_key = "ak_live_" + secrets.token_hex(8)
        else:
            api_key = _get_or_create_secret(conn, actor_id, "api_key", "ak_live")
            _set_hp_event(
                request,
                kind="auth_apikey",
                points=3,
                trap_flags=["auth"],
                extra={"api_key_fingerprint": _hash_text(api_key)},
            )
    finally:
        conn.close()
    return JSONResponse({"data": [{"id": "key_primary", "value": api_key, "status": "active"}]})


@app.get("/admin", tags=["Internal"], response_class=JSONResponse)
async def admin_home(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Security(security)):
    await _sleep_jitter()
    if _is_monitor(request):
        return JSONResponse({"admin": "ok", "version": "2.8.1", "features": ["audit", "users", "flags"]})
    conn = _db()
    try:
        _ensure_schema(conn)
        token = (creds.credentials if creds else "").strip()[:200]
        if not _token_is_valid(conn, token):
            _set_hp_event(request, kind="admin_home", points=0, trap_flags=["internal"], extra={"token_valid": False})
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
        _set_hp_event(request, kind="admin_home", points=8, trap_flags=["internal"])
    finally:
        conn.close()
    return JSONResponse({"admin": "ok", "version": "2.8.1", "features": ["audit", "users", "flags"]})


@app.get("/admin/users", tags=["Internal"], response_class=JSONResponse)
async def admin_users(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Security(security)):
    await _sleep_jitter()
    if _is_monitor(request):
        return JSONResponse({"users": _fake_users("monitor", 5, 0)})
    conn = _db()
    try:
        _ensure_schema(conn)
        token = (creds.credentials if creds else "").strip()[:200]
        if not _token_is_valid(conn, token):
            _set_hp_event(request, kind="admin_users", points=0, trap_flags=["internal"], extra={"token_valid": False})
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
        _set_hp_event(request, kind="admin_users", points=10, trap_flags=["internal", "enum"])
    finally:
        conn.close()
    return JSONResponse({"users": _fake_users(_actor_id_from_request(request), 5, 0)})


@app.post("/admin/users", tags=["Internal"], response_class=JSONResponse)
async def admin_users_post(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Security(security)):
    await _sleep_jitter()
    data = await _read_json_or_form(request)
    if _is_monitor(request):
        return JSONResponse({"status": "created", "id": "user_" + secrets.token_hex(4)})
    conn = _db()
    try:
        _ensure_schema(conn)
        token = (creds.credentials if creds else "").strip()[:200]
        if not _token_is_valid(conn, token):
            _set_hp_event(request, kind="admin_users", points=0, trap_flags=["internal"], extra={"token_valid": False})
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
        _set_hp_event(
            request,
            kind="admin_users",
            points=10,
            trap_flags=["internal", "write"],
            extra={"new_user": data.get("email") or data.get("username")},
        )
    finally:
        conn.close()
    return JSONResponse({"status": "created", "id": "user_" + secrets.token_hex(4)})


@app.get("/admin/audit", tags=["Internal"], response_class=JSONResponse)
async def admin_audit(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Security(security)):
    await _sleep_jitter()
    if _is_monitor(request):
        return JSONResponse(
            {
                "events": [
                    {"ts": _utc_now_iso(), "actor": "system", "action": "policy_update"},
                    {"ts": _utc_now_iso(), "actor": "svc-backup", "action": "snapshot"},
                ]
            }
        )
    conn = _db()
    try:
        _ensure_schema(conn)
        token = (creds.credentials if creds else "").strip()[:200]
        if not _token_is_valid(conn, token):
            _set_hp_event(request, kind="admin_audit", points=0, trap_flags=["internal"], extra={"token_valid": False})
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
        _set_hp_event(request, kind="admin_audit", points=10, trap_flags=["internal", "audit"])
    finally:
        conn.close()
    return JSONResponse(
        {
            "events": [
                {"ts": _utc_now_iso(), "actor": "system", "action": "policy_update"},
                {"ts": _utc_now_iso(), "actor": "svc-backup", "action": "snapshot"},
            ]
        }
    )


@app.get("/internal/feature-flags", tags=["Internal"], response_class=JSONResponse)
async def internal_flags(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Security(security)):
    await _sleep_jitter()
    if _is_monitor(request):
        return JSONResponse({"flags": {"enable_shadow": True, "enable_migration": True}})
    conn = _db()
    try:
        _ensure_schema(conn)
        token = (creds.credentials if creds else "").strip()[:200]
        if not _token_is_valid(conn, token):
            _set_hp_event(request, kind="internal_access", points=0, trap_flags=["internal"], extra={"token_valid": False})
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
        actor_id = _actor_id_from_request(request)
        score = _actor_score(conn, actor_id)
        stage = _stage_from_actor_score(score)
        _set_hp_event(
            request,
            kind="internal_access",
            points=10,
            trap_flags=["internal"],
            extra={"stage": stage},
        )
    finally:
        conn.close()
    return JSONResponse({"flags": {"enable_shadow": True, "enable_migration": True}})


@app.post("/internal/reload", tags=["Internal"], response_class=JSONResponse)
async def internal_reload(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Security(security)):
    await _sleep_jitter()
    data = await _read_json_or_form(request)
    if _is_monitor(request):
        return JSONResponse({"job_id": "job_" + secrets.token_hex(6), "status": "queued"})
    conn = _db()
    try:
        _ensure_schema(conn)
        token = (creds.credentials if creds else "").strip()[:200]
        if not _token_is_valid(conn, token):
            _set_hp_event(request, kind="internal_reload", points=0, trap_flags=["internal"], extra={"token_valid": False})
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
        actor_id = _actor_id_from_request(request)
        score = _actor_score(conn, actor_id)
        stage = _stage_from_actor_score(score)
        job = _create_job(conn, actor_id, "reload", {"payload": data})
        _set_hp_event(
            request,
            kind="internal_reload",
            points=15,
            trap_flags=["internal", "reload"],
            extra={"job_id": job["job_id"], "stage": stage},
        )
    finally:
        conn.close()
    return JSONResponse({"job_id": job["job_id"], "status": job["status"]})


@app.post("/internal/migrate", tags=["Internal"], response_class=JSONResponse)
async def internal_migrate(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Security(security)):
    await _sleep_jitter()
    data = await _read_json_or_form(request)
    if _is_monitor(request):
        return JSONResponse({"job_id": "job_" + secrets.token_hex(6), "status": "queued"})
    conn = _db()
    try:
        _ensure_schema(conn)
        token = (creds.credentials if creds else "").strip()[:200]
        if not _token_is_valid(conn, token):
            _set_hp_event(request, kind="internal_migrate", points=0, trap_flags=["internal"], extra={"token_valid": False})
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
        actor_id = _actor_id_from_request(request)
        score = _actor_score(conn, actor_id)
        stage = _stage_from_actor_score(score)
        job = _create_job(conn, actor_id, "migrate", {"payload": data})
        _set_hp_event(
            request,
            kind="internal_migrate",
            points=15,
            trap_flags=["internal", "migrate"],
            extra={"job_id": job["job_id"], "stage": stage},
        )
    finally:
        conn.close()
    return JSONResponse({"job_id": job["job_id"], "status": job["status"]})


@app.post("/webhooks/github", tags=["DevOps"], response_class=JSONResponse)
async def webhook_github(request: Request):
    await _sleep_jitter()
    body = await request.body()
    payload = await _read_json_or_form(request)
    signature = request.headers.get("x-hub-signature-256") or ""
    inj = _pattern_hits(body.decode("utf-8", errors="ignore"), DANGEROUS_PAYLOAD_PATTERNS)
    _set_hp_event(
        request,
        kind="devops_webhook",
        points=10,
        trap_flags=["devops"],
        extra={"signature": signature[:200], "injection": inj, "event": payload.get("action")},
    )
    return JSONResponse(status_code=202, content={"status": "accepted", "job_id": "job_" + secrets.token_hex(6)})


@app.post("/webhooks/gitlab", tags=["DevOps"], response_class=JSONResponse)
async def webhook_gitlab(request: Request):
    await _sleep_jitter()
    body = await request.body()
    payload = await _read_json_or_form(request)
    token = request.headers.get("x-gitlab-token") or ""
    inj = _pattern_hits(body.decode("utf-8", errors="ignore"), DANGEROUS_PAYLOAD_PATTERNS)
    _set_hp_event(
        request,
        kind="devops_webhook",
        points=10,
        trap_flags=["devops"],
        extra={"gitlab_token": token[:200], "injection": inj, "event": payload.get("object_kind")},
    )
    return JSONResponse(status_code=202, content={"status": "accepted", "job_id": "job_" + secrets.token_hex(6)})


@app.post("/ci/build", tags=["DevOps"], response_class=JSONResponse)
async def ci_build(request: Request):
    await _sleep_jitter()
    data = await _read_json_or_form(request)
    conn = _db()
    try:
        _ensure_schema(conn)
        actor_id = _actor_id_from_request(request)
        job = _create_job(conn, actor_id, "build", {"payload": data})
        _set_hp_event(
            request,
            kind="devops_build",
            points=12,
            trap_flags=["devops", "ci"],
            extra={"job_id": job["job_id"]},
        )
    finally:
        conn.close()
    return JSONResponse(status_code=202, content={"job_id": job["job_id"], "status": job["status"]})


@app.get("/ci/pipelines", tags=["DevOps"], response_class=JSONResponse)
async def ci_pipelines(request: Request):
    await _sleep_jitter()
    conn = _db()
    try:
        _ensure_schema(conn)
        _ensure_playground_tables(conn)
        rows = conn.execute(
            "SELECT job_id, created_ts, status, kind FROM honeypot_jobs ORDER BY created_ts DESC LIMIT 20"
        ).fetchall()
        pipelines = [
            {"id": r["job_id"], "created_ts": r["created_ts"], "status": r["status"], "type": r["kind"]}
            for r in rows
        ]
        _set_hp_event(request, kind="devops_pipeline", points=6, trap_flags=["devops"])
    finally:
        conn.close()
    return JSONResponse({"pipelines": pipelines})


@app.get("/artifacts/{artifact_id}", tags=["DevOps"], response_class=JSONResponse)
async def ci_artifact(artifact_id: str, request: Request):
    await _sleep_jitter()
    _set_hp_event(
        request,
        kind="devops_artifact",
        points=6,
        trap_flags=["devops"],
        extra={"artifact_id": artifact_id},
    )
    return JSONResponse(
        {
            "artifact_id": artifact_id,
            "status": "ready",
            "download_url": f"{HP_PUBLIC_BASE_URL}/artifacts/{artifact_id}/download",
        }
    )


@app.get("/api/v1/users", tags=["Business"], response_class=JSONResponse)
async def business_users(request: Request):
    await _sleep_jitter()
    limit, offset, aggressive = _pagination_from_request(request)
    actor_id = _actor_id_from_request(request)
    users = _fake_users(actor_id, limit, offset)
    points = 3 + (3 if aggressive else 0)
    _set_hp_event(
        request,
        kind="business_users",
        points=points,
        trap_flags=["business"],
        extra={"limit": limit, "offset": offset, "aggressive": aggressive},
    )
    return JSONResponse({"data": users, "next_offset": offset + limit})


@app.get("/api/v1/accounts", tags=["Business"], response_class=JSONResponse)
async def business_accounts(request: Request):
    await _sleep_jitter()
    limit, offset, aggressive = _pagination_from_request(request)
    actor_id = _actor_id_from_request(request)
    accounts = _fake_accounts(actor_id, limit, offset)
    points = 3 + (3 if aggressive else 0)
    _set_hp_event(
        request,
        kind="business_accounts",
        points=points,
        trap_flags=["business"],
        extra={"limit": limit, "offset": offset, "aggressive": aggressive},
    )
    return JSONResponse({"data": accounts, "next_offset": offset + limit})


@app.get("/api/v1/transactions", tags=["Business"], response_class=JSONResponse)
async def business_transactions(request: Request):
    await _sleep_jitter()
    limit, offset, aggressive = _pagination_from_request(request)
    actor_id = _actor_id_from_request(request)
    txs = _fake_transactions(actor_id, limit, offset)
    points = 3 + (3 if aggressive else 0)
    _set_hp_event(
        request,
        kind="business_transactions",
        points=points,
        trap_flags=["business"],
        extra={"limit": limit, "offset": offset, "aggressive": aggressive},
    )
    return JSONResponse({"data": txs, "next_offset": offset + limit})


@app.post("/api/v1/payments", tags=["Business"], response_class=JSONResponse)
async def business_payments(request: Request):
    await _sleep_jitter()
    data = await _read_json_or_form(request)
    _set_hp_event(
        request,
        kind="business_payments",
        points=3,
        trap_flags=["business"],
        extra={"amount": data.get("amount"), "currency": data.get("currency")},
    )
    return JSONResponse({"status": "accepted", "payment_id": "pay_" + secrets.token_hex(6)})


@app.get("/api/v1/reports/{report_id}", tags=["Business"], response_class=JSONResponse)
async def business_report(report_id: str, request: Request):
    await _sleep_jitter()
    rng = _seeded_rng(report_id, "report")
    _set_hp_event(
        request,
        kind="business_reports",
        points=3,
        trap_flags=["business"],
        extra={"report_id": report_id},
    )
    return JSONResponse(
        {
            "id": report_id,
            "status": "ready",
            "summary": {
                "users": rng.randint(40, 120),
                "transactions": rng.randint(400, 2200),
                "risk_score": rng.randint(20, 90),
            },
        }
    )


@app.post("/console/exec", tags=["Console"], response_class=JSONResponse)
async def console_exec(request: Request):
    await _sleep_jitter()
    data = await _read_json_or_form(request)
    cmd = str(data.get("cmd") or data.get("command") or "")
    hits = _pattern_hits(cmd, SUSPICIOUS_COMMAND_PATTERNS)
    _set_hp_event(
        request,
        kind="console_exec",
        points=5,
        trap_flags=["console"],
        extra={"command": cmd, "command_hash": _hash_text(cmd), "ioc_hits": hits},
    )
    output = "command not found"
    if "whoami" in cmd:
        output = "svc-app"
    elif cmd.strip() == "id":
        output = "uid=1001(app) gid=1001(app) groups=1001(app)"
    return JSONResponse({"ok": True, "output": output})


@app.get("/console/history", tags=["Console"], response_class=JSONResponse)
async def console_history(request: Request):
    await _sleep_jitter()
    _set_hp_event(request, kind="console_history", points=3, trap_flags=["console"])
    return JSONResponse(
        {
            "history": [
                {"ts": _utc_now_iso(), "cmd": "whoami"},
                {"ts": _utc_now_iso(), "cmd": "cat /etc/passwd"},
                {"ts": _utc_now_iso(), "cmd": "ls -la"},
            ]
        }
    )


@app.post("/root/shell", tags=["Console"], response_class=JSONResponse)
async def root_shell(request: Request):
    await _sleep_jitter()
    if _is_monitor(request):
        return JSONResponse({"shell": "ready", "prompt": "root@prod:/#"})
    conn = _db()
    try:
        _ensure_schema(conn)
        token = (request.headers.get("x-root-token") or "").strip()[:200]
        if not _issued_is_valid(conn, "root_token", token):
            _set_hp_event(request, kind="root_shell", points=0, trap_flags=["root"], extra={"token_valid": False})
            return JSONResponse(status_code=403, content={"detail": "Forbidden"})
        _set_hp_event(
            request,
            kind="root_shell",
            points=20,
            trap_flags=["root"],
            extra={"token_fingerprint": _hash_text(token)},
        )
    finally:
        conn.close()
    return JSONResponse({"shell": "ready", "prompt": "root@prod:/#"})








@app.get("/jobs/{job_id}", tags=["DevOps"], response_class=JSONResponse)
async def jobs_status(job_id: str, request: Request):
    await _sleep_jitter()
    conn = _db()
    try:
        _ensure_schema(conn)
        _ensure_sample_assets(conn)
        job = _job_snapshot(conn, job_id)
        if not job:
            _set_hp_event(request, kind="pipeline_job", points=0, trap_flags=["devops"])
            return JSONResponse(status_code=404, content={"detail": "Not found"})
        _set_hp_event(request, kind="pipeline_job", points=2, trap_flags=["devops"], extra={"job_id": job_id})
    finally:
        conn.close()
    return JSONResponse({"job_id": job_id, "status": job["status"], "kind": job["kind"]})






@app.get("/backup/list", include_in_schema=False, response_class=JSONResponse)
async def backup_list(request: Request, bkp: str = Depends(require_backup_token)):
    if _is_monitor(request):
        items = [
            {"id": "snap_2025_11_02", "size": "184MB", "type": "sqlite"},
            {"id": "env_prod", "size": "4KB", "type": "dotenv"},
            {"id": "audit_legacy", "size": "12MB", "type": "jsonl"},
        ]
        return {"items": items}
    conn = _db()
    try:
        _ensure_schema(conn)
        actor_id = _actor_id_from_request(request)

        items = [
            {"id": "snap_2025_11_02", "size": "184MB", "type": "sqlite"},
            {"id": "env_prod", "size": "4KB", "type": "dotenv"},
            {"id": "audit_legacy", "size": "12MB", "type": "jsonl"},
        ]

        _bump_actor(conn, actor_id, score_delta=_score_for("backup_list"))
        conn.commit()
    finally:
        conn.close()

    return {"items": items}


@app.get("/backup/download/{item_id}", include_in_schema=False, response_class=PlainTextResponse)
async def backup_download(item_id: str, request: Request, bkp: str = Depends(require_backup_token)):
    if _is_monitor(request):
        if item_id == "env_prod":
            return "APP_ENV=production\nADMIN_SECRET=adm_monitor\nLOG_LEVEL=debug\nREGION=eu\n"
        if item_id == "audit_legacy":
            return "[]\n"
        return "binary blob not available\n"
    conn = _db()
    try:
        _ensure_schema(conn)
        actor_id = _actor_id_from_request(request)

        admin_secret = _get_or_create_secret(conn, actor_id, "admin_secret", "adm")

        _bump_actor(conn, actor_id, score_delta=_score_for("backup_download"))
        conn.commit()
    finally:
        conn.close()

    if item_id == "env_prod":
        return (
            f"APP_ENV=production\n"
            f"ADMIN_SECRET={admin_secret}\n"
            f"LOG_LEVEL=debug\n"
            f"REGION=eu\n"
        )

    if item_id == "audit_legacy":
        return "[]\n"

    return "binary blob not available\n"


@app.get("/admin/secrets", include_in_schema=False, response_class=JSONResponse)
async def admin_secrets(request: Request, adm: str = Depends(require_admin_secret)):
    if _is_monitor(request):
        return {
            "jwt_signing_key_id": "kid_monitor",
            "root_password": "root_monitor",
            "vault_token": "vault_monitor",
            "vault_hint": "Use X-Vault-Token for /infra/*",
        }
    conn = _db()
    try:
        _ensure_schema(conn)
        actor_id = _actor_id_from_request(request)

        vault_token = _get_or_create_secret(conn, actor_id, "vault_token", "vault")

        payload = {
            "jwt_signing_key_id": _get_or_create_secret(conn, actor_id, "jwt_kid", "kid"),
            "root_password": _get_or_create_secret(conn, actor_id, "root_pass", "root"),
            "vault_token": vault_token,
            "vault_hint": "Use X-Vault-Token for /infra/*",
        }

        _bump_actor(conn, actor_id, score_delta=_score_for("admin_secrets"))
        conn.commit()
    finally:
        conn.close()

    return payload


@app.get("/infra/vault", include_in_schema=False, response_class=JSONResponse)
async def infra_vault(request: Request, v: str = Depends(require_vault_token)):
    if _is_monitor(request):
        return {
            "k8s_cluster": "prod-eu-1",
            "namespace": "accounts",
            "cloud_token": "cloud_monitor",
            "cloud_hint": "Use X-Cloud-Token for /cloud/*",
        }
    conn = _db()
    try:
        _ensure_schema(conn)
        actor_id = _actor_id_from_request(request)

        cloud_token = _get_or_create_secret(conn, actor_id, "cloud_token", "cloud")

        payload = {
            "k8s_cluster": "prod-eu-1",
            "namespace": "accounts",
            "cloud_token": cloud_token,
            "cloud_hint": "Use X-Cloud-Token for /cloud/*",
        }

        _bump_actor(conn, actor_id, score_delta=_score_for("infra_vault"))
        conn.commit()
    finally:
        conn.close()

    _set_hp_event(request, kind="infra_vault", points=0, trap_flags=["critical"])
    return payload


@app.get("/cloud/metadata", include_in_schema=False, response_class=JSONResponse)
async def cloud_metadata(request: Request, c: str = Depends(require_cloud_token)):
    if _is_monitor(request):
        return {
            "project": "acct-prod",
            "iam": {"role": "Owner", "principal": "svc-accounts@acct-prod"},
            "root_token": "root_monitor",
            "root_hint": "Use X-Root-Token for /root/*",
        }
    conn = _db()
    try:
        _ensure_schema(conn)
        actor_id = _actor_id_from_request(request)

        root_token = _get_or_create_secret(conn, actor_id, "root_token", "rootk")

        payload = {
            "project": "acct-prod",
            "iam": {"role": "Owner", "principal": "svc-accounts@acct-prod"},
            "root_token": root_token,
            "root_hint": "Use X-Root-Token for /root/*",
        }

        _bump_actor(conn, actor_id, score_delta=_score_for("cloud_metadata"))
        conn.commit()
    finally:
        conn.close()

    _set_hp_event(request, kind="cloud_metadata", points=0, trap_flags=["critical"])
    return payload


@app.get("/root/console", include_in_schema=False, response_class=JSONResponse)
async def root_console(request: Request, r: str = Depends(require_root_token)):
    if _is_monitor(request):
        return {
            "console": "enabled",
            "session_id": "sess_" + secrets.token_hex(12),
            "actions": ["export_all", "rotate_keys", "impersonate_user"],
        }
    conn = _db()
    try:
        _ensure_schema(conn)
        actor_id = _actor_id_from_request(request)

        payload = {
            "console": "enabled",
            "session_id": "sess_" + secrets.token_hex(12),
            "actions": ["export_all", "rotate_keys", "impersonate_user"],
        }

        _bump_actor(conn, actor_id, score_delta=_score_for("root_console"))
        conn.commit()
    finally:
        conn.close()

    _set_hp_event(request, kind="root_console", points=0, trap_flags=["critical"])
    return payload


# --- Legacy endpoints (hidden) ---
@app.post("/v1/admin/login", include_in_schema=False, response_class=JSONResponse)
async def admin_login(request: Request):
    return {"ok": False, "error": "invalid_credentials"}


@app.get("/v1/admin/status", include_in_schema=False, response_class=JSONResponse)
async def admin_status(token: str = Depends(require_bearer)):
    return {"status": "ok", "uptime": 123456, "region": "eu"}


@app.post("/v1/admin/rotate", include_in_schema=False, response_class=JSONResponse)
async def admin_rotate(token: str = Depends(require_bearer)):
    return {"ok": True, "rotation_id": "rot_" + secrets.token_hex(8)}


@app.post("/v1/export/users", include_in_schema=False, response_class=JSONResponse)
async def export_users(token: str = Depends(require_bearer)):
    return {
        "job_id": "job_" + secrets.token_hex(10),
        "status": "queued",
        "download_url": f"{HP_PUBLIC_BASE_URL}/v1/export/jobs/" + secrets.token_hex(6),
    }


@app.post("/v1/export/audit", include_in_schema=False, response_class=JSONResponse)
async def export_audit(token: str = Depends(require_bearer)):
    return {
        "job_id": "job_" + secrets.token_hex(10),
        "status": "queued",
        "download_url": f"{HP_PUBLIC_BASE_URL}/v1/export/jobs/" + secrets.token_hex(6),
    }


@app.exception_handler(404)
async def not_found(request: Request, exc: Exception):
    return JSONResponse(status_code=404, content={"detail": "Not Found"})
