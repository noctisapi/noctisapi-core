"""Trusted proxy handling and real client IP extraction.

The real client IP is resolved using the following header priority, but
*only* when the direct TCP connection originates from a trusted proxy:

  1. CF-Connecting-IP   – set by Cloudflare; authoritative when CF is trusted
  2. X-Forwarded-For    – rightmost non-trusted IP (secure multi-hop walk)
  3. X-Real-IP          – single-value header set by nginx / Traefik
  4. remote_addr        – direct socket IP (always the fallback)

When the direct connection is NOT from a trusted proxy all forwarding
headers are ignored and the raw socket IP is returned.  A warning is
emitted when an untrusted connection carries forwarding headers, which
indicates a header-injection / spoofing attempt.

Configuration
-------------
Set ``TRUSTED_PROXIES`` to a comma- or newline-separated list of CIDRs:

    TRUSTED_PROXIES=173.245.48.0/20,103.21.244.0/22,10.0.0.0/8

When ``TRUSTED_PROXIES`` is *not* set the module falls back to a default
list of private / loopback ranges (RFC 1918, loopback, ULA) so that
existing Docker deployments behind Traefik / nginx continue to work
without any configuration change.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import threading
from typing import Optional, Union

from fastapi import Request

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default trusted networks (used when TRUSTED_PROXIES is unset)
# ---------------------------------------------------------------------------

_DEFAULT_TRUSTED_CIDRS: list[str] = [
    "127.0.0.0/8",    # IPv4 loopback
    "::1/128",         # IPv6 loopback
    "10.0.0.0/8",     # RFC 1918
    "172.16.0.0/12",  # RFC 1918
    "192.168.0.0/16", # RFC 1918
    "fc00::/7",        # IPv6 ULA
    "169.254.0.0/16", # link-local
    "fe80::/10",       # IPv6 link-local
]

_TrustedNet = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# ---------------------------------------------------------------------------
# Singleton cache
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_cached_networks: Optional[list[_TrustedNet]] = None


def _parse_cidr_list(raw: str) -> list[_TrustedNet]:
    """Parse a comma/newline/space-separated CIDR list into network objects."""
    nets: list[_TrustedNet] = []
    for token in raw.replace(",", " ").replace("\n", " ").split():
        token = token.strip()
        if not token:
            continue
        try:
            nets.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            _logger.warning("trusted_proxy: ignoring invalid CIDR %r", token)
    return nets


def get_trusted_networks() -> list[_TrustedNet]:
    """Return the configured trusted proxy networks.

    Parsed once from the environment and cached for the process lifetime.
    Call ``_reset_cache()`` in tests to force a fresh parse.
    """
    global _cached_networks
    if _cached_networks is not None:
        return _cached_networks
    with _lock:
        if _cached_networks is None:
            raw = (os.environ.get("TRUSTED_PROXIES") or "").strip()
            if raw:
                _cached_networks = _parse_cidr_list(raw)
            else:
                _cached_networks = _parse_cidr_list(" ".join(_DEFAULT_TRUSTED_CIDRS))
    return _cached_networks


def _reset_cache() -> None:
    """Clear the trusted-network cache (tests only)."""
    global _cached_networks
    with _lock:
        _cached_networks = None


# ---------------------------------------------------------------------------
# IP helpers
# ---------------------------------------------------------------------------


def _is_trusted(ip_str: str, networks: list[_TrustedNet]) -> bool:
    """Return True if *ip_str* falls within any of *networks*."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in networks)
    except ValueError:
        return False


def _first_untrusted_from_xff(
    xff: str, networks: list[_TrustedNet]
) -> Optional[str]:
    """Return the rightmost non-trusted IP from an X-Forwarded-For value.

    Walking right-to-left skips IPs added by trusted proxies and returns
    the first IP that was not injected by a known-trusted hop — i.e. the
    real client.  If every IP in the chain is trusted (fully internal
    traffic) the leftmost (origin) IP is returned instead.
    """
    ips = [ip.strip() for ip in xff.split(",") if ip.strip()]
    if not ips:
        return None
    for ip in reversed(ips):
        try:
            ipaddress.ip_address(ip)  # validate before trusting
        except ValueError:
            continue
        if not _is_trusted(ip, networks):
            return ip
    # All hops are trusted — return the leftmost as the origin.
    return ips[0]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def resolve_client_ip(request: Request) -> str:
    """Determine the real client IP, honouring trusted proxy headers.

    Returns the direct socket IP unchanged when the connection does not
    come from a trusted proxy, preventing header injection by external
    clients.

    The result is cached in ``request.state._client_ip_resolved`` so that
    repeated calls within the same request lifecycle do not re-evaluate
    headers or emit duplicate warnings.
    """
    # Return cached result for this request (prevents duplicate warning logs)
    try:
        cached = request.state._client_ip_resolved
        if cached is not None:
            return cached
    except AttributeError:
        pass

    result = _resolve_client_ip_uncached(request)

    try:
        request.state._client_ip_resolved = result
    except Exception:
        pass

    return result


def _resolve_client_ip_uncached(request: Request) -> str:
    """Internal: compute the client IP without consulting or writing the cache."""
    remote_addr: str = (
        request.client.host if request.client else None
    ) or "0.0.0.0"

    trusted = get_trusted_networks()

    if not _is_trusted(remote_addr, trusted):
        # Connection from an untrusted address: ignore all forwarding headers.
        _PROXY_HEADERS = ("cf-connecting-ip", "x-forwarded-for", "x-real-ip")
        if any(h in request.headers for h in _PROXY_HEADERS):
            _logger.warning(
                "trusted_proxy: ignoring proxy headers from untrusted source %s",
                remote_addr,
            )
        return remote_addr

    # --- Connection is from a trusted proxy: extract real client IP ----------

    # 1. CF-Connecting-IP (authoritative when Cloudflare is in TRUSTED_PROXIES)
    cf_ip = (request.headers.get("cf-connecting-ip") or "").strip()
    if cf_ip:
        try:
            ipaddress.ip_address(cf_ip)
            return cf_ip
        except ValueError:
            _logger.warning("trusted_proxy: invalid CF-Connecting-IP %r", cf_ip)

    # 2. X-Forwarded-For: rightmost non-trusted IP
    xff = (request.headers.get("x-forwarded-for") or "").strip()
    if xff:
        ip = _first_untrusted_from_xff(xff, trusted)
        if ip:
            return ip

    # 3. X-Real-IP
    xri = (request.headers.get("x-real-ip") or "").strip()
    if xri:
        try:
            ipaddress.ip_address(xri)
            return xri
        except ValueError:
            _logger.warning("trusted_proxy: invalid X-Real-IP %r", xri)

    # 4. Fall back to the direct socket IP
    return remote_addr
