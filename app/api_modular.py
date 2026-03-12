from __future__ import annotations

import fnmatch
import json
import re
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

_ALLOWED_TABLES: frozenset[str] = frozenset({"api_endpoint_configs"})
_SAFE_IDENTIFIER_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


RESPONSE_MODES = {"normal", "minimal", "error_bias"}
MUTATION_POLICIES = {"none", "daily", "weekly"}

DEFAULT_ENDPOINT_CONFIG: Dict[str, Any] = {
    "enabled": True,
    "response_mode": "normal",
    "fixed_status": None,
    "richness_level": 2,
}

CORE_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "balanced": {
        "enabled": True,
        "response_mode": "normal",
        "fixed_status": None,
        "richness_level": 2,
    },
    "minimal": {
        "enabled": True,
        "response_mode": "minimal",
        "fixed_status": None,
        "richness_level": 0,
    },
    "error_trap": {
        "enabled": True,
        "response_mode": "error_bias",
        "fixed_status": None,
        "richness_level": 1,
    },
    "disabled": {
        "enabled": False,
        "response_mode": "normal",
        "fixed_status": 404,
        "richness_level": 0,
    },
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().isoformat(timespec="seconds").replace("+00:00", "Z")


def _clamp_int(value: Any, low: int, high: int, default: int) -> int:
    try:
        parsed = int(value)
    except Exception:
        parsed = int(default)
    return max(low, min(high, parsed))


def _parse_ts(ts: str) -> Optional[datetime]:
    raw = str(ts or "").strip()
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except Exception:
        return None


def _normalize_method(method: Any) -> str:
    raw = str(method or "*").strip().upper()
    if not raw:
        return "*"
    return raw


def _normalize_path(path: Any) -> str:
    raw = str(path or "").strip()
    if not raw:
        return "/"
    if not raw.startswith("/"):
        return "/" + raw
    return raw


def _path_segment_match(config_segment: str, actual_segment: str) -> bool:
    cfg = str(config_segment or "")
    act = str(actual_segment or "")
    if not cfg:
        return cfg == act
    if cfg.startswith("{") and cfg.endswith("}") and len(cfg) > 2:
        return bool(act)
    return cfg == act


def path_matches_pattern(config_path: str, request_path: str) -> bool:
    cfg = _normalize_path(config_path)
    req = _normalize_path(request_path)
    if cfg == req:
        return True
    if "*" in cfg or "?" in cfg:
        return bool(fnmatch.fnmatch(req, cfg))

    cfg_parts = cfg.strip("/").split("/") if cfg != "/" else []
    req_parts = req.strip("/").split("/") if req != "/" else []
    if len(cfg_parts) != len(req_parts):
        return False
    for cfg_seg, req_seg in zip(cfg_parts, req_parts):
        if not _path_segment_match(cfg_seg, req_seg):
            return False
    return True


def _path_specificity_score(path_pattern: str) -> tuple[int, int, int, int]:
    path = _normalize_path(path_pattern)
    if path == "/":
        return (0, 1, 0, 1)
    parts = path.strip("/").split("/")
    literal_count = 0
    template_count = 0
    wildcard_count = 0
    for part in parts:
        if "*" in part or "?" in part:
            wildcard_count += 1
        elif part.startswith("{") and part.endswith("}") and len(part) > 2:
            template_count += 1
        else:
            literal_count += 1
    return (literal_count, -template_count, -wildcard_count, len(path))


def _normalize_response_mode(value: Any) -> str:
    raw = str(value or DEFAULT_ENDPOINT_CONFIG["response_mode"]).strip().lower()
    if raw not in RESPONSE_MODES:
        return str(DEFAULT_ENDPOINT_CONFIG["response_mode"])
    return raw


def _normalize_policy(value: Any) -> str:
    raw = str(value or "none").strip().lower()
    if raw not in MUTATION_POLICIES:
        return "none"
    return raw


def _assert_safe_identifier(name: str, kind: str = "identifier") -> None:
    if not _SAFE_IDENTIFIER_RE.match(name):
        raise ValueError(f"Unsafe SQL {kind}: {name!r}")


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    if table not in _ALLOWED_TABLES:
        raise ValueError(f"Unknown table: {table!r}")
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    except Exception:
        return set()
    out: set[str] = set()
    for row in rows:
        try:
            out.add(str(row["name"]))
        except Exception:
            try:
                out.add(str(row[1]))
            except Exception:
                continue
    return out


def _ensure_columns(conn: sqlite3.Connection, table: str, expected: Dict[str, str]) -> None:
    if table not in _ALLOWED_TABLES:
        raise ValueError(f"Unknown table: {table!r}")
    existing = _table_columns(conn, table)
    for column, ddl in expected.items():
        _assert_safe_identifier(column, "column")
        if column in existing:
            continue
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def ensure_tables(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS api_endpoint_configs (
          method TEXT NOT NULL,
          path TEXT NOT NULL,
          enabled INTEGER NOT NULL DEFAULT 1,
          response_mode TEXT NOT NULL DEFAULT 'normal',
          fixed_status INTEGER,
          richness_level INTEGER NOT NULL DEFAULT 2,
          updated_ts TEXT NOT NULL,
          PRIMARY KEY(method, path)
        )
        """
    )
    _ensure_columns(
        conn,
        "api_endpoint_configs",
        {
            "method": "TEXT NOT NULL DEFAULT '*'",
            "path": "TEXT NOT NULL DEFAULT '/'",
            "enabled": "INTEGER NOT NULL DEFAULT 1",
            "response_mode": "TEXT NOT NULL DEFAULT 'normal'",
            "fixed_status": "INTEGER",
            "richness_level": "INTEGER NOT NULL DEFAULT 2",
            "updated_ts": "TEXT NOT NULL DEFAULT ''",
        },
    )
    conn.commit()


def sanitize_endpoint_config(raw: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(raw or {})
    enabled = bool(payload.get("enabled", True))
    response_mode = _normalize_response_mode(payload.get("response_mode"))
    richness_level = _clamp_int(payload.get("richness_level"), 0, 2, 2)
    fixed_status_raw = payload.get("fixed_status")
    fixed_status = None
    if fixed_status_raw is not None and str(fixed_status_raw).strip() != "":
        fixed_status = _clamp_int(fixed_status_raw, 100, 599, 500)
    return {
        "enabled": enabled,
        "response_mode": response_mode,
        "fixed_status": fixed_status,
        "richness_level": richness_level,
    }


def list_templates() -> Dict[str, Dict[str, Any]]:
    return {name: dict(cfg) for name, cfg in CORE_TEMPLATES.items()}


def list_endpoint_configs(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    ensure_tables(conn)
    rows = conn.execute(
        """
        SELECT method, path, enabled, response_mode, fixed_status, richness_level, updated_ts
        FROM api_endpoint_configs
        ORDER BY path ASC, method ASC
        """
    ).fetchall()
    items: List[Dict[str, Any]] = []
    for row in rows:
        items.append(
            {
                "method": str(row["method"] or "*"),
                "path": str(row["path"] or "/"),
                "config": {
                    "enabled": bool(int(row["enabled"] or 0)),
                    "response_mode": _normalize_response_mode(row["response_mode"]),
                    "fixed_status": int(row["fixed_status"]) if row["fixed_status"] is not None else None,
                    "richness_level": _clamp_int(row["richness_level"], 0, 2, 2),
                },
                "updated_ts": row["updated_ts"],
            }
        )
    return items


def upsert_endpoint_config(conn: sqlite3.Connection, *, path: str, method: str = "*", config: Dict[str, Any]) -> Dict[str, Any]:
    ensure_tables(conn)
    normalized_path = _normalize_path(path)
    normalized_method = _normalize_method(method)
    cfg = sanitize_endpoint_config(config)
    now = _utc_now_iso()
    cur = conn.execute(
        """
        UPDATE api_endpoint_configs
        SET enabled=?, response_mode=?, fixed_status=?, richness_level=?, updated_ts=?
        WHERE method=? AND path=?
        """,
        (
            1 if cfg["enabled"] else 0,
            cfg["response_mode"],
            cfg["fixed_status"],
            int(cfg["richness_level"]),
            now,
            normalized_method,
            normalized_path,
        ),
    )
    if int(cur.rowcount or 0) <= 0:
        conn.execute(
            """
            INSERT INTO api_endpoint_configs(method, path, enabled, response_mode, fixed_status, richness_level, updated_ts)
            VALUES(?,?,?,?,?,?,?)
            """,
            (
                normalized_method,
                normalized_path,
                1 if cfg["enabled"] else 0,
                cfg["response_mode"],
                cfg["fixed_status"],
                int(cfg["richness_level"]),
                now,
            ),
        )
    conn.commit()
    return {"method": normalized_method, "path": normalized_path, "config": cfg, "updated_ts": now}


def delete_endpoint_config(conn: sqlite3.Connection, *, path: str, method: str = "*") -> bool:
    ensure_tables(conn)
    normalized_path = _normalize_path(path)
    normalized_method = _normalize_method(method)
    cur = conn.execute(
        "DELETE FROM api_endpoint_configs WHERE method=? AND path=?",
        (normalized_method, normalized_path),
    )
    conn.commit()
    return bool(cur.rowcount)


def apply_template(
    conn: sqlite3.Connection,
    *,
    template_name: str,
    path: str,
    method: str = "*",
) -> Dict[str, Any]:
    template = CORE_TEMPLATES.get(str(template_name or "").strip().lower())
    if not template:
        raise ValueError("unknown_template")
    return upsert_endpoint_config(conn, path=path, method=method, config=template)


def resolve_endpoint_config(
    conn: sqlite3.Connection,
    *,
    path: str,
    method: str,
    ensure_schema: bool = True,
) -> Dict[str, Any]:
    if ensure_schema:
        ensure_tables(conn)
    normalized_path = _normalize_path(path)
    normalized_method = _normalize_method(method)
    rows = conn.execute(
        """
        SELECT method, path, enabled, response_mode, fixed_status, richness_level
        FROM api_endpoint_configs
        WHERE method IN (?, '*')
        """,
        (normalized_method,),
    ).fetchall()
    best_row: Optional[sqlite3.Row] = None
    best_key: Optional[tuple[Any, ...]] = None
    best_match_type = "default"
    for row in rows:
        row_method = _normalize_method(row["method"] or "*")
        row_path = _normalize_path(row["path"] or "/")
        if not path_matches_pattern(row_path, normalized_path):
            continue
        method_rank = 0 if row_method == normalized_method else 1
        path_rank = 0 if row_path == normalized_path else 1
        spec = _path_specificity_score(row_path)
        key = (method_rank, path_rank, -spec[0], -spec[1], -spec[2], -spec[3])
        if best_key is None or key < best_key:
            best_key = key
            best_row = row
            if path_rank == 0 and method_rank == 0:
                best_match_type = "exact"
            elif path_rank == 0:
                best_match_type = "exact_path_any_method"
            elif method_rank == 0:
                best_match_type = "pattern_same_method"
            else:
                best_match_type = "pattern_any_method"

    if not best_row:
        return {
            "config": dict(DEFAULT_ENDPOINT_CONFIG),
            "match_type": "default",
        }
    return {
        "config": {
            "enabled": bool(int(best_row["enabled"] or 0)),
            "response_mode": _normalize_response_mode(best_row["response_mode"]),
            "fixed_status": int(best_row["fixed_status"]) if best_row["fixed_status"] is not None else None,
            "richness_level": _clamp_int(best_row["richness_level"], 0, 2, 2),
        },
        "match_type": best_match_type,
    }


# ── OSS stubs: PRO mutation/rules not available ────────────────────────────────

def mutation_bucket(policy: str, *, now: Optional[datetime] = None) -> str:  # noqa: ARG001
    return "none"


def compute_status(
    *,
    original_status: int,
    response_mode: str,  # noqa: ARG001
    fixed_status: Optional[int],  # noqa: ARG001
    mutation_policy: str,  # noqa: ARG001
    mutation_intensity: int,  # noqa: ARG001
    path: str,  # noqa: ARG001
    method: str,  # noqa: ARG001
    actor_id: str,  # noqa: ARG001
) -> int:
    return int(original_status or 200)


def _reduce_dict_richness(payload: Dict[str, Any], richness_level: int) -> Dict[str, Any]:  # noqa: ARG001
    return dict(payload)


def _minimize_payload(payload: Any, richness_level: int) -> Any:  # noqa: ARG001
    return payload


def mutate_json_payload(
    payload: Any,
    *,
    response_mode: str,  # noqa: ARG001
    richness_level: int,  # noqa: ARG001
    mutation_policy: str,  # noqa: ARG001
    mutation_intensity: int,  # noqa: ARG001
    path: str,  # noqa: ARG001
    method: str,  # noqa: ARG001
    actor_id: str,  # noqa: ARG001
) -> Any:
    return payload


def mutation_headers(
    *,
    mutation_policy: str,  # noqa: ARG001
    mutation_intensity: int,  # noqa: ARG001
    matched_rule_ids: List[int],  # noqa: ARG001
    path: str,  # noqa: ARG001
    method: str,  # noqa: ARG001
    actor_id: str,  # noqa: ARG001
) -> Dict[str, str]:
    return {}


def get_mutation_config(conn: sqlite3.Connection, *, ensure_schema: bool = True) -> Dict[str, Any]:  # noqa: ARG001
    return {"mutation_policy": "none", "mutation_intensity": 0, "updated_ts": _utc_now_iso()}


def set_mutation_config(conn: sqlite3.Connection, *, mutation_policy: str, mutation_intensity: int) -> Dict[str, Any]:  # noqa: ARG001
    raise ValueError("not_available_in_oss")


def resolve_request_policy(
    conn: sqlite3.Connection,
    *,
    path: str,
    method: str,
    user_agent: str,  # noqa: ARG001
    pro_enabled: bool,  # noqa: ARG001
    ensure_schema: bool = True,
) -> Dict[str, Any]:
    if ensure_schema:
        ensure_tables(conn)
    base = resolve_endpoint_config(conn, path=path, method=method, ensure_schema=False)
    return {
        "endpoint_config": sanitize_endpoint_config(base["config"]),
        "endpoint_match_type": base.get("match_type", "default"),
        "rules": {
            "matched_rule_ids": [],
            "richness_delta": 0,
            "extra_latency_ms": 0,
            "force_status": None,
        },
        "latency_ms": 0,
        "mutation": {"mutation_policy": "none", "mutation_intensity": 0},
        "pro_enabled": False,
    }


# ── Analytics ──────────────────────────────────────────────────────────────────

def _safe_json_loads(raw: str) -> Dict[str, Any]:
    text = str(raw or "").strip()
    if not text:
        return {}
    try:
        parsed = json.loads(text)
    except Exception:
        return {}
    if isinstance(parsed, dict):
        return parsed
    return {}


def _iter_recent_events(
    conn: sqlite3.Connection,
    *,
    window_hours: int,
    max_rows: int,
) -> List[sqlite3.Row]:
    rows = conn.execute(
        """
        SELECT id, ts, actor_id, kind, path, method, ip, ua, status, extra_json
        FROM events
        ORDER BY id DESC
        LIMIT ?
        """,
        (max(1, int(max_rows)),),
    ).fetchall()
    now = _utc_now()
    lower_bound = now - timedelta(hours=max(1, int(window_hours)))
    filtered: List[sqlite3.Row] = []
    for row in rows:
        ts = _parse_ts(row["ts"])
        if ts is None:
            continue
        if ts < lower_bound:
            continue
        filtered.append(row)
    return filtered


def analytics_endpoint_metrics(
    conn: sqlite3.Connection,
    *,
    window_hours: int = 24,
    limit: int = 25,
    max_rows: int = 5000,
) -> List[Dict[str, Any]]:
    rows = _iter_recent_events(conn, window_hours=window_hours, max_rows=max_rows)
    buckets: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        path = _normalize_path(row["path"] or "/")
        method = _normalize_method(row["method"] or "*")
        key = f"{method} {path}"
        bucket = buckets.setdefault(
            key,
            {
                "method": method,
                "path": path,
                "hits": 0,
                "errors": 0,
                "status_sum": 0,
                "status_count": 0,
                "latency_sum": 0,
                "latency_count": 0,
                "actors": set(),
            },
        )
        bucket["hits"] += 1
        status = int(row["status"] or 0)
        if status >= 400:
            bucket["errors"] += 1
        if status > 0:
            bucket["status_sum"] += status
            bucket["status_count"] += 1
        extra = _safe_json_loads(row["extra_json"])
        latency = extra.get("latency_ms")
        if latency is not None:
            try:
                lat_val = int(latency)
            except Exception:
                lat_val = 0
            if lat_val >= 0:
                bucket["latency_sum"] += lat_val
                bucket["latency_count"] += 1
        actor_id = str(row["actor_id"] or "").strip()
        if actor_id:
            bucket["actors"].add(actor_id)

    items: List[Dict[str, Any]] = []
    for bucket in buckets.values():
        hits = int(bucket["hits"])
        errors = int(bucket["errors"])
        items.append(
            {
                "method": bucket["method"],
                "path": bucket["path"],
                "hits": hits,
                "errors": errors,
                "error_rate": round((errors / hits), 4) if hits else 0.0,
                "avg_status": round(bucket["status_sum"] / max(1, int(bucket["status_count"])), 2),
                "avg_latency_ms": round(bucket["latency_sum"] / max(1, int(bucket["latency_count"])), 2),
                "unique_actors": len(bucket["actors"]),
            }
        )
    items.sort(key=lambda x: (-int(x["hits"]), -int(x["errors"]), x["path"]))
    return items[: max(1, int(limit))]


def analytics_interest_scoring(
    conn: sqlite3.Connection,
    *,
    window_hours: int = 24,
    limit: int = 25,
    max_rows: int = 5000,
) -> List[Dict[str, Any]]:
    metrics = analytics_endpoint_metrics(
        conn,
        window_hours=window_hours,
        limit=max(1, max(limit, 50)),
        max_rows=max_rows,
    )
    sensitive_tokens = ["/admin", "/internal", "/root", "/backup", "/infra", "/cloud", "/.env"]
    for item in metrics:
        score = 0.0
        hits = float(item["hits"])
        errors = float(item["errors"])
        actors = float(item["unique_actors"])
        score += hits * 1.0
        score += errors * 2.5
        score += actors * 1.8
        path = str(item["path"] or "").lower()
        if any(tok in path for tok in sensitive_tokens):
            score += 20.0
        if item["error_rate"] >= 0.5:
            score += 8.0
        item["interest_score"] = round(score, 2)
    metrics.sort(key=lambda x: (-float(x["interest_score"]), -int(x["hits"])))
    return metrics[: max(1, int(limit))]


def analytics_fingerprinting(
    conn: sqlite3.Connection,
    *,
    window_hours: int = 24,
    limit: int = 25,
    max_rows: int = 8000,
) -> List[Dict[str, Any]]:
    rows = _iter_recent_events(conn, window_hours=window_hours, max_rows=max_rows)
    by_ip: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        ip = str(row["ip"] or "").strip() or "unknown"
        item = by_ip.setdefault(
            ip,
            {
                "ip": ip,
                "hits": 0,
                "user_agents": set(),
                "paths": set(),
                "methods": set(),
                "errors": 0,
                "actors": set(),
                "kinds": set(),
            },
        )
        item["hits"] += 1
        ua = str(row["ua"] or "").strip()
        path = _normalize_path(row["path"] or "/")
        method = _normalize_method(row["method"] or "*")
        status = int(row["status"] or 0)
        kind = str(row["kind"] or "").strip().lower()
        actor_id = str(row["actor_id"] or "").strip()

        if ua:
            item["user_agents"].add(ua)
        item["paths"].add(path)
        item["methods"].add(method)
        item["kinds"].add(kind)
        if status >= 400:
            item["errors"] += 1
        if actor_id:
            item["actors"].add(actor_id)

    findings: List[Dict[str, Any]] = []
    for item in by_ip.values():
        hits = int(item["hits"])
        ua_count = len(item["user_agents"])
        path_count = len(item["paths"])
        method_count = len(item["methods"])
        error_count = int(item["errors"])
        actor_count = len(item["actors"])
        kinds = item["kinds"]

        score = 0.0
        score += max(0, ua_count - 1) * 12.0
        score += max(0, path_count - 5) * 4.5
        score += max(0, method_count - 2) * 4.0
        score += (error_count / max(1, hits)) * 20.0
        score += max(0, actor_count - 1) * 3.0
        if any(str(kind).startswith("recon_") for kind in kinds):
            score += 10.0

        if score < 20.0:
            continue

        findings.append(
            {
                "ip": item["ip"],
                "fingerprint_score": round(score, 2),
                "hits": hits,
                "unique_user_agents": ua_count,
                "unique_paths": path_count,
                "unique_methods": method_count,
                "error_rate": round(error_count / max(1, hits), 4),
                "unique_actors": actor_count,
                "sample_paths": sorted(list(item["paths"]))[:6],
            }
        )

    findings.sort(key=lambda x: (-float(x["fingerprint_score"]), -int(x["hits"])))
    return findings[: max(1, int(limit))]
