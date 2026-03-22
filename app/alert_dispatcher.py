"""
Core edition — critical-only webhook alerts.
Fires only for the 3 most severe event kinds: root_console, cloud_metadata, infra_vault.
Full alerting (all high-signal kinds, configurable threshold) available on Pro.

Designed to never block the public API:
  - HTTP POST fires in a daemon thread
  - Deduplication prevents alert storms (one alert per actor+kind per hour)
  - All exceptions are silently swallowed

Configuration
-------------
  HP_ALERT_WEBHOOK_URL   : Webhook URL (Slack, Discord, or generic HTTP endpoint)
  HP_ALERT_WEBHOOK_FORMAT: "slack" (default) | "discord" | "json"
  HP_ALERT_MIN_SCORE     : Minimum score_delta to trigger (default: 20)

Discord: append /slack to your Discord webhook URL to use Slack format,
         OR set HP_ALERT_WEBHOOK_FORMAT=discord for native Discord embeds.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# High-signal kinds — always alert regardless of score threshold
# ---------------------------------------------------------------------------
_CRITICAL_KINDS: frozenset[str] = frozenset(
    {
        "root_console",       # 90 pts — root shell access attempt
        "cloud_metadata",     # 74 pts — cloud IMDS access
        "infra_vault",        # 60 pts — vault credential dump
    }
)

# Trap flags that always trigger an alert
_CRITICAL_FLAGS: frozenset[str] = frozenset({"exploit", "upload", "exfil"})

# ---------------------------------------------------------------------------
# In-memory dedup: (actor_id, kind) → unix timestamp of last alert
# ---------------------------------------------------------------------------
_dedup: dict[tuple[str, str], float] = {}
_dedup_lock = threading.Lock()
_DEDUP_WINDOW_S: int = 3600  # 1 alert per actor per kind per hour


def _is_deduplicated(actor_id: str, kind: str) -> bool:
    key = (actor_id, kind)
    now = time.monotonic()
    with _dedup_lock:
        last = _dedup.get(key, 0.0)
        if now - last < _DEDUP_WINDOW_S:
            return True
        _dedup[key] = now
        # Evict old entries to prevent unbounded growth
        if len(_dedup) > 10_000:
            cutoff = now - _DEDUP_WINDOW_S * 2
            to_del = [k for k, v in _dedup.items() if v < cutoff]
            for k in to_del:
                del _dedup[k]
    return False


# ---------------------------------------------------------------------------
# Score threshold
# ---------------------------------------------------------------------------
def _min_score() -> int:
    try:
        return int(os.getenv("HP_ALERT_MIN_SCORE", "20") or "20")
    except (ValueError, TypeError):
        return 20


# ---------------------------------------------------------------------------
# Webhook URL + format
# ---------------------------------------------------------------------------
def _webhook_url() -> str:
    return (os.getenv("HP_ALERT_WEBHOOK_URL") or "").strip()


def _webhook_format() -> str:
    return (os.getenv("HP_ALERT_WEBHOOK_FORMAT", "slack") or "slack").strip().lower()


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------
_STAGE_LABELS = {0: "0–Idle", 1: "1–Curious", 2: "2–Exploring", 3: "3–Probing",
                 4: "4–Targeting", 5: "5–Aggressive", 6: "6–Exploiting",
                 7: "7–Persistent", 8: "8–Critical"}


def _stage_label(score: int) -> str:
    if score < 10:   stage = 0
    elif score < 20: stage = 1
    elif score < 32: stage = 2
    elif score < 48: stage = 3
    elif score < 68: stage = 4
    elif score < 92: stage = 5
    elif score < 120: stage = 6
    elif score < 155: stage = 7
    else:             stage = 8
    return _STAGE_LABELS.get(stage, str(stage))


def _severity_emoji(kind: str, score_delta: int) -> str:
    if kind in ("root_console", "cloud_metadata", "infra_vault"):
        return "🔴"
    if kind in ("admin_secrets", "backup_download", "admin_login_attempt"):
        return "🟠"
    if score_delta >= 20:
        return "🟡"
    return "⚪"


def _build_slack_payload(
    *,
    kind: str,
    actor_id: str,
    ip: str,
    ua: str,
    path: str,
    score_delta: int,
    trap_flags: List[str],
    current_score: int,
) -> dict:
    emoji = _severity_emoji(kind, score_delta)
    stage = _stage_label(current_score)
    flags_str = ", ".join(trap_flags) if trap_flags else "—"
    short_actor = actor_id[:12] if actor_id else "unknown"

    return {
        "text": f"{emoji} High-signal event on NoctisAPI: `{kind}` from `{ip}`",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} High-Signal Event Detected",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Kind*\n`{kind}`"},
                    {"type": "mrkdwn", "text": f"*Source IP*\n`{ip}`"},
                    {"type": "mrkdwn", "text": f"*Path*\n`{path}`"},
                    {"type": "mrkdwn", "text": f"*Score +{score_delta}*\nActor total: {current_score}"},
                    {"type": "mrkdwn", "text": f"*Stage*\n{stage}"},
                    {"type": "mrkdwn", "text": f"*Trap Flags*\n{flags_str}"},
                ],
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Actor `{short_actor}` · UA: `{ua[:80] if ua else '—'}`",
                    }
                ],
            },
        ],
    }


def _build_discord_payload(
    *,
    kind: str,
    actor_id: str,
    ip: str,
    ua: str,
    path: str,
    score_delta: int,
    trap_flags: List[str],
    current_score: int,
) -> dict:
    emoji = _severity_emoji(kind, score_delta)
    stage = _stage_label(current_score)
    flags_str = ", ".join(trap_flags) if trap_flags else "—"
    short_actor = actor_id[:12] if actor_id else "unknown"

    # Discord color: red for critical, orange for high, yellow for medium
    color = 0xFF0000 if kind in ("root_console", "cloud_metadata", "infra_vault") else \
            0xFF6600 if kind in ("admin_secrets", "backup_download") else \
            0xFFCC00

    return {
        "embeds": [
            {
                "title": f"{emoji} High-Signal Event: `{kind}`",
                "color": color,
                "fields": [
                    {"name": "Source IP", "value": f"`{ip}`", "inline": True},
                    {"name": "Path", "value": f"`{path}`", "inline": True},
                    {"name": "Score", "value": f"+{score_delta} (total: {current_score})", "inline": True},
                    {"name": "Stage", "value": stage, "inline": True},
                    {"name": "Trap Flags", "value": flags_str, "inline": True},
                    {"name": "Actor", "value": f"`{short_actor}`", "inline": True},
                ],
                "footer": {"text": f"UA: {ua[:100] if ua else '—'}"},
            }
        ]
    }


def _build_json_payload(
    *,
    kind: str,
    actor_id: str,
    ip: str,
    ua: str,
    path: str,
    score_delta: int,
    trap_flags: List[str],
    current_score: int,
) -> dict:
    """Generic JSON format for custom webhook consumers."""
    return {
        "event": "high_signal",
        "kind": kind,
        "actor_id": actor_id,
        "source_ip": ip,
        "path": path,
        "user_agent": ua,
        "score_delta": score_delta,
        "actor_score": current_score,
        "stage": _stage_label(current_score),
        "trap_flags": trap_flags,
    }


# ---------------------------------------------------------------------------
# HTTP POST (runs in daemon thread)
# ---------------------------------------------------------------------------
def _post_webhook(url: str, payload: dict) -> None:
    try:
        import httpx
        with httpx.Client(timeout=8.0) as client:
            resp = client.post(url, json=payload, headers={"Content-Type": "application/json"})
            if resp.status_code >= 400:
                logger.warning(
                    "alert_dispatcher.webhook_failed",
                    extra={"status": resp.status_code, "body": resp.text[:200]},
                )
    except Exception as exc:
        logger.debug("alert_dispatcher.post_error: %s", exc)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def fire_if_high_signal(
    *,
    kind: str,
    actor_id: str,
    ip: str,
    ua: str,
    path: str,
    score_delta: int,
    trap_flags: Optional[List[str]] = None,
    current_score: int = 0,
) -> None:
    """
    Fire a webhook alert if the event is high-signal.
    Non-blocking. Never raises.

    Parameters
    ----------
    kind          : honeypot event kind (e.g. "root_console", "recon_env")
    actor_id      : stable actor identifier
    ip            : source IP
    ua            : User-Agent string
    path          : request path
    score_delta   : points awarded for this event
    trap_flags    : trap flags from the event (optional)
    current_score : actor's total score AFTER this event (optional, used for stage label)
    """
    try:
        url = _webhook_url()
        if not url:
            return

        flags = trap_flags or []

        # Decide if high-signal
        is_critical_kind = kind in _CRITICAL_KINDS
        is_critical_flag = bool(set(flags) & _CRITICAL_FLAGS)
        is_high_score = score_delta >= _min_score()

        if not (is_critical_kind or is_critical_flag or is_high_score):
            return

        # Dedup
        if _is_deduplicated(actor_id, kind):
            return

        # Build payload
        fmt = _webhook_format()
        kw = dict(
            kind=kind,
            actor_id=actor_id,
            ip=ip,
            ua=ua,
            path=path,
            score_delta=score_delta,
            trap_flags=flags,
            current_score=current_score,
        )
        if fmt == "discord":
            payload = _build_discord_payload(**kw)
        elif fmt == "json":
            payload = _build_json_payload(**kw)
        else:
            payload = _build_slack_payload(**kw)

        # Fire in background thread — never block the API
        t = threading.Thread(target=_post_webhook, args=(url, payload), daemon=True)
        t.start()

    except Exception:
        pass  # Never propagate into the API path
