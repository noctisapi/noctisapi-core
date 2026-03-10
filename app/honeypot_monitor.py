import os
import re
import sqlite3
import threading
import time
import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx

from app.proxy_config import build_httpx_mounts
from app.tls_config import get_ssl_context

HoneypotDBFactory = Callable[[], sqlite3.Connection]

HONEYPOT_PUBLIC_BASE_URL = os.getenv("HONEYPOT_PUBLIC_BASE_URL", "").strip().rstrip("/")
HONEYPOT_MONITOR_BASE_URL = os.getenv("HONEYPOT_MONITOR_BASE_URL", "").strip().rstrip("/")
HONEYPOT_CHECK_INTERVAL = max(15, int(os.getenv("HONEYPOT_CHECK_INTERVAL", "60")))
HONEYPOT_CHECK_TIMEOUT = float(os.getenv("HONEYPOT_CHECK_TIMEOUT", "5"))
HONEYPOT_CHECK_RETENTION_SECONDS = int(os.getenv("HONEYPOT_CHECK_RETENTION_SECONDS", str(7 * 24 * 3600)))
HONEYPOT_CHECK_MAX_ROWS = int(os.getenv("HONEYPOT_CHECK_MAX_ROWS", "10000"))
HONEYPOT_MONITORED_ENDPOINTS_RAW = os.getenv("HONEYPOT_MONITORED_ENDPOINTS", "")
HONEYPOT_MONITOR_UA = os.getenv("HONEYPOT_MONITOR_UA", "HealthCheck/1.0")
HONEYPOT_MONITOR_XFF = os.getenv("HONEYPOT_MONITOR_XFF", "127.0.0.1")


def _utc_now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sanitize_base(base: str) -> str:
    base = (base or "").strip()
    if base.endswith("/"):
        base = base[:-1]
    return base


def _normalize_endpoint(endpoint: str) -> str:
    endpoint = (endpoint or "").strip()
    if not endpoint:
        return "/health"
    if re.match(r"^[A-Z]+\s+/", endpoint):
        return endpoint
    if endpoint.startswith("/"):
        return endpoint
    return "/" + endpoint


def _parse_endpoints(raw: str) -> List[str]:
    cleaned = (raw or "").strip()
    if not cleaned:
        return []
    chunks = [c.strip() for c in re.split(r"[,\n]+", cleaned) if c.strip()]
    endpoints: List[str] = []
    for chunk in chunks:
        chunk = re.sub(r"\s+", " ", chunk)
        if re.match(r"^[A-Z]+\s+/", chunk):
            endpoints.append(chunk)
            continue
        if " " in chunk:
            endpoints.extend([c for c in chunk.split(" ") if c])
        else:
            endpoints.append(chunk)
    normalized = [_normalize_endpoint(ep) for ep in endpoints]
    return sorted(set(normalized))


def _replace_path_params(path: str) -> str:
    def _repl(match: re.Match) -> str:
        name = (match.group(1) or "").lower()
        if "session" in name:
            return "__SESSION_ID__"
        if "file" in name:
            return "__FILE_ID__"
        if "job" in name:
            return "sample"
        if "report" in name:
            return "rpt_demo_001"
        return "sample"

    return re.sub(r"\{([^/]+)\}", _repl, path)


def _discover_endpoints() -> List[str]:
    try:
        from fastapi.routing import APIRoute
        from app import honeypot_public
    except Exception:
        return []

    endpoints: List[str] = []
    for route in honeypot_public.app.routes:
        if not isinstance(route, APIRoute):
            continue
        endpoint = _replace_path_params(route.path or "")
        if not endpoint:
            continue
        endpoints.append(_normalize_endpoint(endpoint))
    return sorted(set(endpoints))


def _sample_lookup_endpoint() -> Optional[str]:
    try:
        from app import honeypot_public
        sha = getattr(honeypot_public, "SAMPLE_FILE_SHA256", "") or ""
        if sha:
            return f"/files/lookup?sha256={sha}"
    except Exception:
        return None
    return None


def _infer_auth(path: str) -> str:
    if path.startswith("/internal/config"):
        return "api_key"
    if path.startswith("/backup/"):
        return "backup"
    if path.startswith("/admin/secrets"):
        return "admin_secret"
    if path.startswith("/infra/vault"):
        return "vault"
    if path.startswith("/cloud/metadata"):
        return "cloud"
    if path.startswith("/root/"):
        return "root"
    if path.startswith("/admin") or path.startswith("/internal"):
        return "bearer"
    if path.startswith("/me") or path.startswith("/sessions") or path.startswith("/apikeys"):
        return "bearer"
    if path.startswith("/v1/account") or path.startswith("/v1/keys"):
        return "bearer"
    if path.startswith("/v1/admin") or path.startswith("/v1/export"):
        return "bearer"
    return "none"


def _default_body_for(path: str, method: str) -> Tuple[Optional[bytes], Optional[str]]:
    if method != "POST":
        return None, None
    if path.startswith("/auth/login"):
        return b'{"username":"monitor","password":"monitor","scope":"read write"}', "application/json"
    if path.startswith("/auth/mfa"):
        return b'{"code":"000000"}', "application/json"
    if path.startswith("/auth/forgot"):
        return b'{"email":"monitor@example.com"}', "application/json"
    if path.startswith("/auth/reset"):
        return b'{"token":"reset_123","password":"NewPass123!"}', "application/json"
    if path.startswith("/internal/reload") or path.startswith("/internal/migrate"):
        return b'{"reason":"monitor"}', "application/json"
    if path.startswith("/admin/users"):
        return b'{"email":"monitor@example.com"}', "application/json"
    if path.startswith("/webhooks/github"):
        return b'{"action":"push","repository":"demo","ref":"main"}', "application/json"
    if path.startswith("/webhooks/gitlab"):
        return b'{"object_kind":"pipeline","project":{"path":"demo"}}', "application/json"
    if path.startswith("/ci/build"):
        return b'{"branch":"main","commit":"deadbeef"}', "application/json"
    if path.startswith("/api/v1/payments"):
        return b'{"amount": 12.34, "currency":"USD"}', "application/json"
    if path.startswith("/console/exec"):
        return b'{"cmd":"whoami"}', "application/json"
    # binary upload endpoints
    if (
        path.startswith("/files")
        or path.startswith("/console/upload")
        or path.startswith("/import")
        or path.startswith("/admin/restore")
        or path.startswith("/plugins/install")
        or path.startswith("/themes/upload")
    ):
        return b"monitor payload", "application/octet-stream"
    return b"{}", "application/json"


def _make_check(method: str, path: str) -> Dict[str, Any]:
    auth = _infer_auth(path)
    body, content_type = _default_body_for(path, method)
    query = None
    if path == "/files/lookup":
        query = "sha256=__FILE_SHA__"
    if path.startswith("/files") and method == "POST":
        query = "filename=monitor.bin"
    if path.startswith("/console/upload") and method == "POST":
        query = "filename=console.bin"
    if path in {"/import", "/admin/restore", "/plugins/install", "/themes/upload"} and method == "POST":
        query = "filename=upload.bin"
    label = f"{method} {path}" + (f"?{query}" if query else "")
    expected = {200, 201, 202, 204}
    if path == "/auth/login" and method == "POST":
        expected = {200, 401}
    return {
        "method": method,
        "path": path,
        "query": query,
        "auth": auth,
        "body": body,
        "content_type": content_type,
        "expected": expected,
        "label": label,
    }


def _default_checks() -> List[Dict[str, Any]]:
    explicit = _parse_endpoints(HONEYPOT_MONITORED_ENDPOINTS_RAW)
    if explicit:
        checks: List[Dict[str, Any]] = []
        for item in explicit:
            if re.match(r"^[A-Z]+\s+/", item):
                method, path = item.split(" ", 1)
                checks.append(_make_check(method, path))
            else:
                checks.append(_make_check("GET", item))
        return checks
    try:
        from fastapi.routing import APIRoute
        from app import honeypot_public
    except Exception:
        return [_make_check("GET", "/health")]

    checks: List[Dict[str, Any]] = []
    for route in honeypot_public.app.routes:
        if not isinstance(route, APIRoute):
            continue
        path = _normalize_endpoint(route.path or "")
        if not path:
            continue
        path = _replace_path_params(path)
        methods = sorted([m for m in (route.methods or []) if m not in {"HEAD", "OPTIONS"}])
        for method in methods:
            checks.append(_make_check(method, path))
    # replace /files/lookup with query placeholder
    return checks or [_make_check("GET", "/health")]


DEFAULT_CHECKS = _default_checks()


def _safe_json(resp: httpx.Response) -> Dict[str, Any]:
    try:
        data = resp.json()
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}




def _render_path(path: str, ctx: Dict[str, Any]) -> str:
    if "__SESSION_ID__" in path:
        session_id = ctx.get("session_id") or "sample"
        path = path.replace("__SESSION_ID__", session_id)
    if "__FILE_ID__" in path:
        file_id = ctx.get("file_id") or "sample"
        path = path.replace("__FILE_ID__", file_id)
    return path


def _render_query(query: Optional[str], ctx: Dict[str, Any]) -> Dict[str, str]:
    if not query:
        return {}
    rendered = query
    if "__FILE_SHA__" in rendered:
        rendered = rendered.replace("__FILE_SHA__", ctx.get("file_sha") or "")
    params: Dict[str, str] = {}
    for key, value in urllib.parse.parse_qsl(rendered, keep_blank_values=False):
        if value:
            params[key] = value
    return params


class HoneypotAvailabilityMonitor:
    def __init__(self, db_factory: HoneypotDBFactory, base_url: Optional[str] = None, endpoints: Optional[List[str]] = None, checks: Optional[List[Dict[str, Any]]] = None) -> None:
        self.db_factory = db_factory
        chosen = base_url if base_url is not None else (HONEYPOT_MONITOR_BASE_URL or HONEYPOT_PUBLIC_BASE_URL)
        self.base_url = _sanitize_base(chosen)
        self.public_base_url = _sanitize_base(HONEYPOT_PUBLIC_BASE_URL)
        self.checks = checks or DEFAULT_CHECKS
        self.endpoints = endpoints or [c["label"] for c in self.checks]
        self._check_map = {c["label"]: c for c in self.checks}
        self.interval = HONEYPOT_CHECK_INTERVAL
        self.timeout = HONEYPOT_CHECK_TIMEOUT
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.checks)

    @property
    def display_base_url(self) -> str:
        return self.public_base_url or self.base_url

    def start(self) -> None:
        if not self.configured or self._thread is not None:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, name="honeypot-checker", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._thread = None

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.run_check()
            except Exception:
                pass
            self._stop_event.wait(self.interval)

    def run_check(self, endpoint: Optional[str] = None) -> List[Dict[str, Any]] | Dict[str, Any]:
        if not self.configured:
            raise RuntimeError(
                "HONEYPOT_MONITOR_BASE_URL/HONEYPOT_PUBLIC_BASE_URL are not configured"
            )

        ssl_ctx = get_ssl_context()
        with httpx.Client(
            timeout=self.timeout,
            follow_redirects=True,
            verify=ssl_ctx,
            mounts=build_httpx_mounts(ssl_ctx),
        ) as client:
            ctx = self._prepare_context(client)
            if endpoint:
                check = self._resolve_check(endpoint)
                if not check:
                    raise ValueError(f"Unknown endpoint: {endpoint}")
                result = self._run_single(client, check, ctx)
                return result

            results: List[Dict[str, Any]] = []
            for check in self.checks:
                results.append(self._run_single(client, check, ctx))
            return results if len(results) > 1 else results[0]

    def _run_single(self, client: httpx.Client, check: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
        path = _render_path(check["path"], ctx)
        params = _render_query(check.get("query"), ctx)
        url = f"{self.base_url}{path}"
        started = time.perf_counter()
        status_code: Optional[int] = None
        error: Optional[str] = None
        ok = False
        try:
            headers = self._base_headers()
            headers.update(self._auth_headers(check.get("auth") or "none", ctx))
            body = check.get("body")
            content_type = check.get("content_type")
            if content_type and body is not None:
                headers.setdefault("Content-Type", content_type)
            resp = client.request(
                check.get("method") or "GET",
                url,
                params=params or None,
                content=body,
                headers=headers,
            )
            status_code = resp.status_code
            expected = check.get("expected") or {200}
            ok = status_code is not None and status_code in expected
            if not ok and not error:
                error = f"HTTP {status_code}" if status_code is not None else "No response"
        except Exception as exc:
            error = str(exc)

        latency_ms = int((time.perf_counter() - started) * 1000)
        result = {
            "ts": _utc_now_iso(),
            "ok": 1 if ok else 0,
            "status_code": status_code,
            "latency_ms": latency_ms,
            "error": error,
            "endpoint": check.get("label") or f"{check.get('method')} {check.get('path')}",
        }
        self._persist_result(result)
        return result

    def _base_headers(self) -> Dict[str, str]:
        headers = {"User-Agent": HONEYPOT_MONITOR_UA, "X-Internal-Monitor": "1"}
        if HONEYPOT_MONITOR_XFF:
            headers["X-Forwarded-For"] = HONEYPOT_MONITOR_XFF
        return headers

    def _auth_headers(self, auth: str, ctx: Dict[str, Any]) -> Dict[str, str]:
        if auth == "bearer" and ctx.get("token"):
            return {"Authorization": f"Bearer {ctx['token']}"}
        if auth == "api_key" and ctx.get("api_key"):
            return {"X-API-Key": ctx["api_key"]}
        if auth == "backup" and ctx.get("backup_token"):
            return {"X-Backup-Token": ctx["backup_token"]}
        if auth == "admin_secret" and ctx.get("admin_secret"):
            return {"X-Admin-Secret": ctx["admin_secret"]}
        if auth == "vault" and ctx.get("vault_token"):
            return {"X-Vault-Token": ctx["vault_token"]}
        if auth == "cloud" and ctx.get("cloud_token"):
            return {"X-Cloud-Token": ctx["cloud_token"]}
        if auth == "root" and ctx.get("root_token"):
            return {"X-Root-Token": ctx["root_token"]}
        return {}

    def _resolve_check(self, endpoint: str) -> Optional[Dict[str, Any]]:
        if not endpoint:
            return None
        endpoint = endpoint.strip()
        if endpoint in self._check_map:
            return self._check_map[endpoint]
        for label, check in self._check_map.items():
            if label.lower() == endpoint.lower():
                return check
        if endpoint.startswith("/"):
            for check in self.checks:
                if check["path"] == endpoint and check["method"] == "GET":
                    return check
            for check in self.checks:
                if check["path"] == endpoint:
                    return check
        return None

    def _prepare_context(self, client: httpx.Client) -> Dict[str, Any]:
        ctx: Dict[str, Any] = {
            "token": None,
            "session_id": None,
            "api_key": None,
            "backup_token": None,
            "admin_secret": None,
            "vault_token": None,
            "cloud_token": None,
            "root_token": None,
            "file_sha": None,
            "file_id": None,
        }
        if not self.base_url:
            return ctx

        base_headers = self._base_headers()

        def _request(
            method: str,
            path: str,
            *,
            headers: Optional[Dict[str, str]] = None,
            body: Optional[bytes] = None,
            content_type: Optional[str] = None,
            params: Optional[Dict[str, str]] = None,
        ) -> Optional[httpx.Response]:
            url = f"{self.base_url}{path}"
            req_headers = dict(base_headers)
            if headers:
                req_headers.update(headers)
            if content_type and body is not None:
                req_headers.setdefault("Content-Type", content_type)
            try:
                return client.request(method, url, headers=req_headers, params=params, content=body)
            except Exception:
                return None

        token_resp = _request(
            "POST",
            "/v1/auth/token",
            body=b'{"username":"monitor","password":"monitor","grant_type":"client_credentials"}',
            content_type="application/json",
        )
        if token_resp and token_resp.status_code < 400:
            ctx["token"] = _safe_json(token_resp).get("access_token")

        if ctx["token"]:
            bearer = {"Authorization": f"Bearer {ctx['token']}"}
            sessions_resp = _request("GET", "/sessions", headers=bearer)
            if sessions_resp and sessions_resp.status_code < 400:
                sessions = _safe_json(sessions_resp).get("sessions") or []
                if sessions:
                    ctx["session_id"] = sessions[0].get("id")

            _request("GET", "/admin/users", headers=bearer)
            _request("GET", "/admin/audit", headers=bearer)
            _request("POST", "/internal/reload", headers=bearer, body=b'{"reason":"monitor"}', content_type="application/json")
            _request("POST", "/internal/migrate", headers=bearer, body=b'{"reason":"monitor"}', content_type="application/json")

            keys_resp = _request("GET", "/v1/keys", headers=bearer)
            if keys_resp and keys_resp.status_code < 400:
                keys = _safe_json(keys_resp)
                ctx["api_key"] = keys.get("api_key") or ctx["api_key"]
                ctx["backup_token"] = keys.get("backup_token") or ctx["backup_token"]

            if not ctx["backup_token"]:
                _request("GET", "/admin", headers=bearer)
                _request("GET", "/internal/feature-flags", headers=bearer)
                keys_resp = _request("GET", "/v1/keys", headers=bearer)
                if keys_resp and keys_resp.status_code < 400:
                    keys = _safe_json(keys_resp)
                    ctx["api_key"] = keys.get("api_key") or ctx["api_key"]
                    ctx["backup_token"] = keys.get("backup_token") or ctx["backup_token"]

        if ctx["backup_token"]:
            bkp_headers = {"X-Backup-Token": ctx["backup_token"]}
            env_resp = _request("GET", "/backup/download/env_prod", headers=bkp_headers)
            if env_resp and env_resp.status_code < 400:
                match = re.search(r"ADMIN_SECRET=([^\r\n]+)", env_resp.text or "")
                if match:
                    ctx["admin_secret"] = match.group(1).strip()

        if ctx["admin_secret"]:
            adm_headers = {"X-Admin-Secret": ctx["admin_secret"]}
            adm_resp = _request("GET", "/admin/secrets", headers=adm_headers)
            if adm_resp and adm_resp.status_code < 400:
                ctx["vault_token"] = _safe_json(adm_resp).get("vault_token")

        if ctx["vault_token"]:
            vault_headers = {"X-Vault-Token": ctx["vault_token"]}
            vault_resp = _request("GET", "/infra/vault", headers=vault_headers)
            if vault_resp and vault_resp.status_code < 400:
                ctx["cloud_token"] = _safe_json(vault_resp).get("cloud_token")

        if ctx["cloud_token"]:
            cloud_headers = {"X-Cloud-Token": ctx["cloud_token"]}
            cloud_resp = _request("GET", "/cloud/metadata", headers=cloud_headers)
            if cloud_resp and cloud_resp.status_code < 400:
                ctx["root_token"] = _safe_json(cloud_resp).get("root_token")

        samples_resp = _request("GET", "/files/samples")
        if samples_resp and samples_resp.status_code < 400:
            samples = _safe_json(samples_resp).get("samples") or []
            if samples:
                ctx["file_sha"] = samples[0].get("sha256") or ctx["file_sha"]
                ctx["file_id"] = samples[0].get("file_id") or ctx["file_id"]

        if not ctx["file_sha"]:
            try:
                from app import honeypot_public
                ctx["file_sha"] = getattr(honeypot_public, "SAMPLE_FILE_SHA256", None) or ctx["file_sha"]
            except Exception:
                pass

        return ctx

    def _persist_result(self, result: Dict[str, Any]) -> None:
        conn = self.db_factory()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO honeypot_checks(ts, ok, status_code, latency_ms, error, endpoint) VALUES(?,?,?,?,?,?)",
                (
                    result["ts"],
                    result["ok"],
                    result["status_code"],
                    result["latency_ms"],
                    result["error"],
                    result["endpoint"],
                ),
            )
            cur.execute(
                "DELETE FROM honeypot_checks WHERE ts < datetime('now', ?)",
                (f"-{HONEYPOT_CHECK_RETENTION_SECONDS} seconds",),
            )
            cur.execute(
                """
                DELETE FROM honeypot_checks
                WHERE id NOT IN (
                    SELECT id FROM honeypot_checks ORDER BY ts DESC LIMIT ?
                )
                """,
                (HONEYPOT_CHECK_MAX_ROWS,),
            )
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _normalize_endpoint(endpoint: Optional[str]) -> str:
        return _normalize_endpoint(endpoint or "/health")

def _row_to_dict(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    return dict(row)


def get_history(conn: sqlite3.Connection, endpoint: str, limit: int = 20) -> List[Dict[str, Any]]:
    cur = conn.cursor()
    cur.execute(
        "SELECT id, ts, ok, status_code, latency_ms, error, endpoint FROM honeypot_checks WHERE endpoint=? ORDER BY ts DESC LIMIT ?",
        (_normalize_endpoint(endpoint), max(1, int(limit))),
    )
    rows = [_row_to_dict(r) for r in cur.fetchall()]
    return rows


def _summarize_endpoint(conn: sqlite3.Connection, endpoint: str, limit: int) -> Dict[str, Any]:
    cur = conn.cursor()
    cur.execute(
        "SELECT id, ts, ok, status_code, latency_ms, error, endpoint FROM honeypot_checks WHERE endpoint=? ORDER BY ts DESC LIMIT 1",
        (_normalize_endpoint(endpoint),),
    )
    last = _row_to_dict(cur.fetchone())

    cur.execute(
        "SELECT ok FROM honeypot_checks WHERE endpoint=? ORDER BY ts DESC LIMIT 200",
        (_normalize_endpoint(endpoint),),
    )
    fail_streak = 0
    for row in cur.fetchall():
        if int(row["ok"] or 0):
            break
        fail_streak += 1

    history = get_history(conn, endpoint, limit)
    status_label = "No data"
    status_class = "status-unknown"
    if last is not None:
        if int(last["ok"]):
            status_label = "UP"
            status_class = "status-ok"
        else:
            status_label = "DOWN"
            status_class = "status-fail"

    return {
        "endpoint": endpoint,
        "last": last,
        "history": history,
        "status_label": status_label,
        "status_class": status_class,
        "fail_streak": fail_streak,
    }


def get_summary(conn: sqlite3.Connection, base_url: str, endpoints: List[str], limit: int = 20) -> Dict[str, Any]:
    endpoints = endpoints or [c["label"] for c in DEFAULT_CHECKS]
    summaries = [_summarize_endpoint(conn, endpoint, limit) for endpoint in endpoints]
    return {
        "configured": bool(base_url and endpoints),
        "base_url": base_url,
        "endpoints": summaries,
    }
