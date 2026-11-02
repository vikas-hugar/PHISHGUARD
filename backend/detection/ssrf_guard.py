"""
PhishGuard AI V6 — SSRF & Dangerous Protocol Guard
====================================================
Protects the backend from Server-Side Request Forgery (SSRF) attacks,
private/internal network access, cloud metadata endpoint abuse, and
dangerous URI schemes when processing user-submitted URLs.

Security coverage:
  - RFC1918 private IP ranges (10.x, 172.16-31.x, 192.168.x)
  - Loopback (127.x, ::1, localhost)
  - Link-local (169.254.x — AWS/GCP metadata endpoints)
  - IPv6 private ranges (fc00::/7, fe80::/10)
  - Dangerous schemes: file://, javascript:, data:, ftp://
  - Suspicious ports: default metadata, internal admin ports
  - Cloud metadata endpoints: 169.254.169.254, metadata.google, etc.

NOT designed as a Deep Scan network policy (that is handled by the sandbox).
This guard protects the Flask backend itself from SSRF via the /predict endpoint.
"""

import re
import socket
import ipaddress
from urllib.parse import urlparse

# ── Dangerous URI schemes ──────────────────────────────────────────────────
BLOCKED_SCHEMES = frozenset([
    "file", "javascript", "data", "ftp", "sftp",
    "gopher", "dict", "ldap", "ldaps", "telnet",
    "tftp", "jar", "netdoc", "man", "news"
])

# ── Private/Reserved IPv4 networks ────────────────────────────────────────
_PRIVATE_NETS_V4 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local / AWS metadata
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),      # Shared address space
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),    # Documentation
    ipaddress.ip_network("203.0.113.0/24"),     # Documentation
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
]

# ── Private/Reserved IPv6 networks ────────────────────────────────────────
_PRIVATE_NETS_V6 = [
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("fc00::/7"),           # ULA (private)
    ipaddress.ip_network("fe80::/10"),          # Link-local
    ipaddress.ip_network("ff00::/8"),           # Multicast
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped
    ipaddress.ip_network("100::/64"),           # Discard
    ipaddress.ip_network("2001:db8::/32"),      # Documentation
]

# ── Blocked hostnames (cloud metadata, common internal) ───────────────────
BLOCKED_HOSTNAMES = frozenset([
    "localhost", "broadcasthost",
    "metadata.google.internal",
    "computemetadata.v1.google.internal",
    "instance-data",
])

# ── Suspicious port list (internal admin, DB, metadata) ───────────────────
SUSPICIOUS_PORTS = frozenset([
    22, 23, 25, 80, 111, 135, 137, 138, 139, 445,
    1433, 1521, 2049, 2375, 2376, 3306, 3389,
    4444, 5432, 5900, 6379, 8080, 8443, 8500,
    9200, 11211, 27017, 50070,
])


def _is_private_ip(addr_str: str) -> bool:
    """Return True if addr_str is a private/reserved/loopback IP."""
    try:
        addr = ipaddress.ip_address(addr_str)
        if (addr.is_loopback or addr.is_private or addr.is_link_local or
            addr.is_multicast or addr.is_reserved or addr.is_unspecified):
            return True
        nets = _PRIVATE_NETS_V4 if addr.version == 4 else _PRIVATE_NETS_V6
        return any(addr in net for net in nets)
    except ValueError:
        return False


def _resolve_to_ip(hostname: str) -> list[str]:
    """
    Attempt a local DNS resolution.
    Returns a list of IP strings; empty list on failure.
    """
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC,
                                    socket.SOCK_STREAM, 0)
        return [info[4][0] for info in infos]
    except Exception:
        return []


# Public aliases
is_private_ip = _is_private_ip
resolve_to_ip = _resolve_to_ip


def validate_url_safe(raw_url: str, resolve_all_dns: bool = False) -> dict:
    """
    Validate a user-submitted URL for safety before any processing.

    Returns:
    {
        "safe": bool,
        "reason": str | None,   # human-readable reason if not safe
        "scheme": str,
        "hostname": str,
        "port": int | None
    }

    If safe=True, the URL may proceed to the detection pipeline.
    If safe=False, the /predict endpoint should return an error immediately.
    """
    raw = raw_url.strip() if raw_url else ""

    if not raw:
        return {"safe": False, "reason": "Empty URL", "scheme": "", "hostname": "", "port": None}

    # ── Ensure scheme is present for parsing ──────────────────────────────
    if "://" not in raw:
        raw = "https://" + raw

    # ── Block dangerous schemes ───────────────────────────────────────────
    try:
        parsed = urlparse(raw.lower())
    except Exception:
        return {"safe": False, "reason": "Malformed URL", "scheme": "", "hostname": "", "port": None}

    scheme = parsed.scheme.lower()
    if scheme in BLOCKED_SCHEMES:
        return {
            "safe": False,
            "reason": f"Blocked URI scheme: '{scheme}://'. Only http/https are permitted.",
            "scheme": scheme, "hostname": "", "port": None
        }

    if scheme not in ("http", "https"):
        return {
            "safe": False,
            "reason": f"Unsupported scheme '{scheme}'. Only http and https are allowed.",
            "scheme": scheme, "hostname": "", "port": None
        }

    # ── Extract hostname & port ───────────────────────────────────────────
    hostname = parsed.hostname or ""
    try:
        port = parsed.port
    except ValueError:
        # Malformed URL whose port field is not a valid integer (e.g. javascript:alert(1))
        return {
            "safe": False,
            "reason": "Malformed URL: could not parse port — possible dangerous scheme disguise.",
            "scheme": scheme, "hostname": "", "port": None
        }

    if not hostname:
        return {"safe": False, "reason": "No hostname in URL", "scheme": scheme, "hostname": "", "port": None}


    # ── Block known dangerous hostnames ──────────────────────────────────
    hostname_lower = hostname.lower().rstrip(".")
    if hostname_lower in BLOCKED_HOSTNAMES:
        return {
            "safe": False,
            "reason": f"Blocked hostname: '{hostname}'",
            "scheme": scheme, "hostname": hostname, "port": port
        }

    # ── Block direct IP submissions that are private ──────────────────────
    # First check if the hostname *looks* like an IP
    try:
        parsed_addr = ipaddress.ip_address(hostname_lower)
        if _is_private_ip(hostname_lower):
            return {
                "safe": False,
                "reason": f"Private/reserved IP address blocked: {hostname}",
                "scheme": scheme, "hostname": hostname, "port": port
            }
    except ValueError:
        pass  # Not a direct IP — proceed to hostname checks

    # ── Block suspicious non-standard ports ──────────────────────────────
    # (Only flag ports that are clearly internal service ports AND non-standard web ports)
    if port is not None and port in SUSPICIOUS_PORTS and port not in (80, 443, 8080, 8443):
        return {
            "safe": False,
            "reason": f"Suspicious port {port} blocked (potential internal service access)",
            "scheme": scheme, "hostname": hostname, "port": port
        }

    # ── Detect hexadecimal / octal / decimal IP obfuscation ──────────────
    # e.g. http://0x7f000001/  http://2130706433/
    hex_ip_pattern = re.compile(r'^0x[0-9a-f]{1,8}$', re.IGNORECASE)
    decimal_ip_pattern = re.compile(r'^\d{4,12}$')  # decimal IP: 2130706433 = 127.0.0.1
    octal_ip_pattern = re.compile(r'^0\d+$')

    if hex_ip_pattern.match(hostname_lower):
        return {
            "safe": False,
            "reason": f"Hex-encoded IP address blocked: {hostname}",
            "scheme": scheme, "hostname": hostname, "port": port
        }

    if decimal_ip_pattern.match(hostname_lower):
        try:
            num = int(hostname_lower)
            # Convert decimal to IP
            packed = num.to_bytes(4, 'big')
            ip_str = ".".join(str(b) for b in packed)
            if _is_private_ip(ip_str):
                return {
                    "safe": False,
                    "reason": f"Decimal-encoded private IP blocked: {hostname} → {ip_str}",
                    "scheme": scheme, "hostname": hostname, "port": port
                }
        except Exception:
            pass

    # ── DNS Resolution check (only for clearly SSRF-risk lookups unless resolve_all_dns=True) ────
    is_likely_internal = (
        resolve_all_dns or
        "." not in hostname_lower or
        hostname_lower.endswith(".local") or
        hostname_lower.endswith(".internal") or
        hostname_lower.endswith(".corp") or
        hostname_lower.endswith(".lan")
    )
    if is_likely_internal:
        resolved_ips = _resolve_to_ip(hostname_lower)
        for ip_str in resolved_ips:
            if _is_private_ip(ip_str):
                return {
                    "safe": False,
                    "reason": f"Hostname '{hostname}' resolves to private IP {ip_str}",
                    "scheme": scheme, "hostname": hostname, "port": port
                }

    return {
        "safe": True,
        "reason": None,
        "scheme": scheme,
        "hostname": hostname,
        "port": port
    }
