"""System settings: DB-persisted overrides for environment variables.

Operators may edit a safe subset of env vars from the admin panel without
SSH access.  Values are stored in the ``system_settings`` SQLite table and
applied to ``os.environ`` early in startup, before any lazy modules (proxy,
TLS, egress, diagnostics) read them.

A container restart is required for changes to take effect â€” the panel
shows a "restart required" banner after any save.

Only keys listed in ``_EDITABLE_KEYS`` are readable or writable through
this module.  Secrets (HP_SEED, HP_OFFLINE_PUBLIC_KEYS_JSON, HP_DB_PATH, ...) are never
exposed here.
"""

from __future__ import annotations

import sqlite3

# ---------------------------------------------------------------------------
# Editable keys whitelist
# ---------------------------------------------------------------------------

_EDITABLE_KEYS: frozenset[str] = frozenset(
    {
        # Outbound proxy
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NO_PROXY",
        # TLS
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "HP_EXTRA_CERTS_DIR",
        # Egress
        "EGRESS_REQUIRED_HOSTS",
        "EGRESS_CONNECT_TIMEOUT",
        # Logging
        "LOG_LEVEL",
        "LOG_FORMAT",
        "LOG_SYSLOG_HOST",
        "LOG_SYSLOG_PORT",
        "LOG_SYSLOG_SOCKTYPE",
        "LOG_SYSLOG_FACILITY",
        # Reverse proxy
        "PUBLIC_BASE_URL",
        "TRUSTED_PROXIES",
        # Timeouts
        "REQUEST_TIMEOUT",
        "KEEPALIVE_TIMEOUT",
        # Critical-event alerting (Core: fires only for root_console, cloud_metadata, infra_vault)
        "HP_ALERT_WEBHOOK_URL",
        "HP_ALERT_WEBHOOK_FORMAT",
    }
)

# Human-readable labels for each key (used in the UI)
KEY_LABELS: dict[str, str] = {
    "HTTPS_PROXY": "HTTPS Proxy",
    "HTTP_PROXY": "HTTP Proxy",
    "NO_PROXY": "No Proxy (bypass list)",
    "SSL_CERT_FILE": "SSL Certificate File",
    "REQUESTS_CA_BUNDLE": "Requests CA Bundle",
    "HP_EXTRA_CERTS_DIR": "Extra Certs Directory",
    "EGRESS_REQUIRED_HOSTS": "Egress Required Hosts",
    "EGRESS_CONNECT_TIMEOUT": "Egress Connect Timeout (s)",
    "LOG_LEVEL": "Log Level",
    "LOG_FORMAT": "Log Format",
    "LOG_SYSLOG_HOST": "Syslog Host",
    "LOG_SYSLOG_PORT": "Syslog Port",
    "LOG_SYSLOG_SOCKTYPE": "Syslog Socket Type",
    "LOG_SYSLOG_FACILITY": "Syslog Facility",
    "PUBLIC_BASE_URL": "Public Base URL",
    "TRUSTED_PROXIES": "Trusted Proxies",
    "REQUEST_TIMEOUT": "Request Timeout (s)",
    "KEEPALIVE_TIMEOUT": "Keepalive Timeout (s)",
    "HP_ALERT_WEBHOOK_URL": "Alert Webhook URL (critical events only)",
    "HP_ALERT_WEBHOOK_FORMAT": "Alert Webhook Format (slack / discord / json)",
}

# Group keys by category for ordered display in the UI
KEY_GROUPS: list[tuple[str, list[str]]] = [
    ("TLS Trust Store", ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "HP_EXTRA_CERTS_DIR"]),
    ("Logging", ["LOG_LEVEL", "LOG_FORMAT", "LOG_SYSLOG_HOST", "LOG_SYSLOG_PORT", "LOG_SYSLOG_SOCKTYPE", "LOG_SYSLOG_FACILITY"]),
    ("Reverse Proxy", ["PUBLIC_BASE_URL", "TRUSTED_PROXIES"]),
    ("Timeouts", ["REQUEST_TIMEOUT", "KEEPALIVE_TIMEOUT"]),
    ("Alerting", ["HP_ALERT_WEBHOOK_URL", "HP_ALERT_WEBHOOK_FORMAT"]),
]


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def ensure_settings_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS system_settings (
            key        TEXT PRIMARY KEY,
            value      TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        )
        """
    )
    conn.commit()


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


def load_settings_overrides(conn: sqlite3.Connection) -> dict[str, str]:
    """Return only keys in _EDITABLE_KEYS that have a non-empty DB override."""
    rows = conn.execute("SELECT key, value FROM system_settings").fetchall()
    return {
        row[0]: row[1]
        for row in rows
        if row[0] in _EDITABLE_KEYS and str(row[1] or "").strip()
    }


def load_all_settings(conn: sqlite3.Connection) -> dict[str, str]:
    """Return all DB settings (including empty overrides) for editable keys."""
    rows = conn.execute("SELECT key, value FROM system_settings").fetchall()
    return {row[0]: row[1] for row in rows if row[0] in _EDITABLE_KEYS}


def save_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    """Upsert a setting.  Empty value clears the override (same as delete_setting)."""
    if key not in _EDITABLE_KEYS:
        raise ValueError(f"Key {key!r} is not editable")
    value = str(value or "").strip()
    if not value:
        delete_setting(conn, key)
        return
    conn.execute(
        """
        INSERT INTO system_settings(key, value)
        VALUES(?, ?)
        ON CONFLICT(key) DO UPDATE
            SET value      = excluded.value,
                updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
        """,
        (key, value),
    )
    conn.commit()


def delete_setting(conn: sqlite3.Connection, key: str) -> None:
    """Remove the DB override for *key*, reverting to the env-var value."""
    if key not in _EDITABLE_KEYS:
        raise ValueError(f"Key {key!r} is not editable")
    conn.execute("DELETE FROM system_settings WHERE key=?", (key,))
    conn.commit()

