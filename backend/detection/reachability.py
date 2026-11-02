"""
PhishGuard AI — Reachability & SSRF Safety Pre-Scan Gate
=========================================================
Implements the mandatory URL syntax validation, SSRF security validation,
and lightweight reachability gate prior to executing the expensive
phishing analysis pipeline.

Architecture:
    validate_url()
        ↓
    validate_ssrf()
        ↓
    check_reachability()
        ↓
    [Reachable?]
     ├── YES ──> Full PhishGuard Analysis (Playwright VM, ML, Vision, DOM)
     └── NO  ──> Inconclusive / Not Reachable State (Scan Skipped)
"""

import socket
import time
from urllib.parse import urlparse, urljoin, urlsplit
import urllib3
import requests

from detection.ssrf_guard import (
    validate_url_safe,
    is_private_ip,
    resolve_to_ip,
    BLOCKED_SCHEMES,
    BLOCKED_HOSTNAMES,
)

# Suppress insecure TLS warnings during lightweight connectivity verification
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Standard browser User-Agent to avoid anti-bot blocks on lightweight pre-scan
BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36 PhishGuard-Reachability/7.0"
)

PRE_SCAN_HEADERS = {
    "User-Agent": BROWSER_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
}


def validate_url_syntax(raw_url: str) -> dict:
    """
    Validate and normalize the syntax of a user-submitted URL.
    Ensures safe scheme, non-empty hostname, valid port, and absence of parsing exploits.

    Returns:
    {
        "valid": bool,
        "reason": str | None,
        "original_url": str,
        "normalized_url": str,
        "scheme": str,
        "hostname": str,
        "port": int | None
    }
    """
    raw = (raw_url or "").strip()
    if not raw:
        return {
            "valid": False,
            "reason": "URL cannot be empty",
            "original_url": raw_url,
            "normalized_url": "",
            "scheme": "",
            "hostname": "",
            "port": None,
        }

    # Detect control characters, whitespace, or null byte exploits
    if any(c in raw for c in ("\x00", "\r", "\n", "\t", " ")):
        return {
            "valid": False,
            "reason": "URL contains invalid control characters or whitespace",
            "original_url": raw_url,
            "normalized_url": "",
            "scheme": "",
            "hostname": "",
            "port": None,
        }

    # Ensure scheme is present for parsing
    has_scheme = "://" in raw
    work_url = raw if has_scheme else "https://" + raw

    try:
        parsed = urlsplit(work_url)
    except Exception as e:
        return {
            "valid": False,
            "reason": f"Malformed URL: {e}",
            "original_url": raw_url,
            "normalized_url": "",
            "scheme": "",
            "hostname": "",
            "port": None,
        }

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        if scheme in BLOCKED_SCHEMES:
            reason = f"Blocked dangerous URI scheme: '{scheme}://'. Only http and https are allowed."
        else:
            reason = f"Unsupported URI scheme: '{scheme}://'. Only http and https are allowed."
        return {
            "valid": False,
            "reason": reason,
            "original_url": raw_url,
            "normalized_url": "",
            "scheme": scheme,
            "hostname": "",
            "port": None,
        }

    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        return {
            "valid": False,
            "reason": "Missing or invalid hostname in URL",
            "original_url": raw_url,
            "normalized_url": "",
            "scheme": scheme,
            "hostname": "",
            "port": None,
        }

    # Disallow backslash trickery in authority: e.g. https://google.com\evil.com
    if "\\" in parsed.netloc:
        return {
            "valid": False,
            "reason": "Backslash character in URL authority is not permitted",
            "original_url": raw_url,
            "normalized_url": "",
            "scheme": scheme,
            "hostname": hostname,
            "port": None,
        }

    try:
        port = parsed.port
    except ValueError:
        return {
            "valid": False,
            "reason": "Invalid or non-numeric port specified in URL",
            "original_url": raw_url,
            "normalized_url": "",
            "scheme": scheme,
            "hostname": hostname,
            "port": None,
        }

    if port is not None and not (1 <= port <= 65535):
        return {
            "valid": False,
            "reason": f"Port out of range (1-65535): {port}",
            "original_url": raw_url,
            "normalized_url": "",
            "scheme": scheme,
            "hostname": hostname,
            "port": port,
        }

    # Reconstruct normalized URL safely
    port_part = f":{port}" if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)) else ""
    path_part = parsed.path if parsed.path else "/"
    query_part = f"?{parsed.query}" if parsed.query else ""
    fragment_part = f"#{parsed.fragment}" if parsed.fragment else ""
    normalized = f"{scheme}://{hostname}{port_part}{path_part}{query_part}{fragment_part}"

    return {
        "valid": True,
        "reason": None,
        "original_url": raw_url,
        "normalized_url": normalized,
        "scheme": scheme,
        "hostname": hostname,
        "port": port,
    }


def validate_ssrf_destination(url_or_parsed: str, resolve_dns: bool = True) -> dict:
    """
    Validate that the URL target does not resolve to private/internal networks,
    cloud metadata endpoints, loopback, or reserved IP ranges.
    Protects against direct IP submission and DNS rebinding.

    Returns:
    {
        "safe": bool,
        "reason": str | None,
        "resolved_ips": list[str]
    }
    """
    url_str = url_or_parsed if isinstance(url_or_parsed, str) else url_or_parsed.get("normalized_url", "")
    
    # Run host-level SSRF guard (schemes, hostnames, IP formatting, decimal/hex IPs)
    base_check = validate_url_safe(url_str, resolve_all_dns=False)
    if not base_check["safe"]:
        return {
            "safe": False,
            "reason": base_check["reason"],
            "scheme": base_check.get("scheme", ""),
            "hostname": base_check.get("hostname", ""),
            "resolved_ips": [],
        }

    hostname = base_check.get("hostname")
    if not hostname:
        return {"safe": False, "reason": "No hostname found in URL", "resolved_ips": []}

    # Direct IP check
    if is_private_ip(hostname):
        return {
            "safe": False,
            "reason": f"Private/reserved IP address blocked: {hostname}",
            "resolved_ips": [hostname],
        }

    resolved_ips = []
    if resolve_dns:
        try:
            port = base_check.get("port") or (443 if base_check.get("scheme") == "https" else 80)
            infos = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            resolved_ips = list({info[4][0] for info in infos})
            for ip in resolved_ips:
                if is_private_ip(ip):
                    return {
                        "safe": False,
                        "reason": f"Destination hostname '{hostname}' resolves to private/prohibited IP: {ip}",
                        "resolved_ips": resolved_ips,
                    }
        except socket.gaierror:
            # DNS resolution failed — not an SSRF block, reachability check will flag as DNS_FAILED
            pass
        except Exception:
            pass

    return {
        "safe": True,
        "reason": None,
        "scheme": base_check.get("scheme", ""),
        "hostname": hostname,
        "resolved_ips": resolved_ips,
    }


def check_url_reachability(
    url: str,
    connect_timeout: float = 4.0,
    read_timeout: float = 6.0,
    max_redirects: int = 5,
) -> dict:
    """
    Lightweight, fast pre-scan reachability check.
    Ensures that only accessible websites enter the full Playwright/ML pipeline.

    Checks performed:
      1. URL syntax validation
      2. SSRF guard on origin
      3. DNS resolution (with private IP validation)
      4. Lightweight HTTP/HTTPS GET (stream=True, headers only)
      5. Safe redirect following with per-hop SSRF validation
      6. Final destination availability and HTTP response status

    Returns:
    {
        "reachable": bool,
        "ssrf_blocked": bool,
        "status": str,           # "REACHABLE", "DNS_FAILED", "CONNECTION_TIMEOUT", "CONNECTION_REFUSED",
                                 # "TLS_FAILED", "HOST_UNAVAILABLE", "REDIRECT_UNAVAILABLE", "SSRF_BLOCKED", "NETWORK_ERROR"
        "reachability_status": str,
        "reason": str | None,
        "http_status": int | None,
        "final_url": str,
        "redirect_chain": list[str],
        "redirect_count": int,
        "elapsed_ms": float,
    }
    """
    t_start = time.perf_counter()
    print(f"[REACHABILITY] Checking URL: {url}", flush=True)

    # ── Step 1: URL Syntax Validation ────────────────────────────────────────
    syntax = validate_url_syntax(url)
    if not syntax["valid"]:
        elapsed = round((time.perf_counter() - t_start) * 1000, 2)
        print(f"[REACHABILITY] Invalid URL syntax: {syntax['reason']}", flush=True)
        return {
            "reachable": False,
            "ssrf_blocked": False,
            "status": "INVALID_URL",
            "reachability_status": "INVALID_URL",
            "reason": syntax["reason"],
            "http_status": None,
            "final_url": url,
            "redirect_chain": [],
            "redirect_count": 0,
            "elapsed_ms": elapsed,
        }

    current_url = syntax["normalized_url"]
    hostname = syntax["hostname"]
    port = syntax["port"] or (443 if syntax["scheme"] == "https" else 80)

    # ── Step 2: SSRF Guard on Initial Target ─────────────────────────────────
    ssrf_check = validate_ssrf_destination(current_url, resolve_dns=False)
    if not ssrf_check["safe"]:
        elapsed = round((time.perf_counter() - t_start) * 1000, 2)
        print(f"[SSRF] Prohibited destination blocked: {ssrf_check['reason']}", flush=True)
        return {
            "reachable": False,
            "ssrf_blocked": True,
            "status": "SSRF_BLOCKED",
            "reachability_status": "SSRF_BLOCKED",
            "reachability_state": "SSRF_BLOCKED",
            "reason": ssrf_check["reason"],
            "http_status": None,
            "final_url": current_url,
            "redirect_chain": [],
            "redirect_count": 0,
            "elapsed_ms": elapsed,
        }

    # ── Step 3: DNS Resolution & Rebinding Check ─────────────────────────────
    resolved_ips = []
    try:
        infos = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        resolved_ips = list({info[4][0] for info in infos})
    except socket.gaierror as e:
        elapsed = round((time.perf_counter() - t_start) * 1000, 2)
        print(f"[REACHABILITY] DNS resolution failed: {e}", flush=True)
        return {
            "reachable": False,
            "ssrf_blocked": False,
            "status": "DNS_FAILED",
            "reachability_status": "DNS_FAILED",
            "reachability_state": "DNS_FAILED",
            "reason": "DNS resolution failed: Domain does not exist or nameserver unreachable",
            "http_status": None,
            "final_url": current_url,
            "redirect_chain": [],
            "redirect_count": 0,
            "elapsed_ms": elapsed,
        }
    except Exception as e:
        elapsed = round((time.perf_counter() - t_start) * 1000, 2)
        print(f"[REACHABILITY] Network resolution error: {e}", flush=True)
        return {
            "reachable": False,
            "ssrf_blocked": False,
            "status": "DNS_FAILED",
            "reachability_status": "DNS_FAILED",
            "reachability_state": "DNS_FAILED",
            "reason": f"DNS resolution failed: {e}",
            "http_status": None,
            "final_url": current_url,
            "redirect_chain": [],
            "redirect_count": 0,
            "elapsed_ms": elapsed,
        }

    # Check if any resolved IP belongs to a private or reserved range
    for ip in resolved_ips:
        if is_private_ip(ip):
            elapsed = round((time.perf_counter() - t_start) * 1000, 2)
            print(f"[SSRF] Hostname {hostname} resolved to prohibited IP: {ip}", flush=True)
            return {
                "reachable": False,
                "ssrf_blocked": True,
                "status": "SSRF_BLOCKED",
                "reachability_status": "SSRF_BLOCKED",
                "reachability_state": "SSRF_BLOCKED",
                "reason": f"Destination hostname '{hostname}' resolves to private/prohibited IP: {ip}",
                "http_status": None,
                "final_url": current_url,
                "redirect_chain": [],
                "redirect_count": 0,
                "elapsed_ms": elapsed,
            }

    print(f"[REACHABILITY] DNS resolved ({resolved_ips[0] if resolved_ips else 'ok'})", flush=True)

    # ── Step 4: Lightweight GET Request with Safe Redirect Loop ──────────────
    redirect_chain = []
    session = requests.Session()
    timeout = (connect_timeout, read_timeout)

    for hop in range(max_redirects + 1):
        if hop >= max_redirects:
            elapsed = round((time.perf_counter() - t_start) * 1000, 2)
            print(f"[REACHABILITY] Too many redirects (limit {max_redirects} exceeded)", flush=True)
            return {
                "reachable": False,
                "ssrf_blocked": False,
                "status": "REDIRECT_UNAVAILABLE",
                "reachability_status": "REDIRECT_UNAVAILABLE",
                "reachability_state": "CONNECTION_FAILED",
                "reason": f"Too many redirects (exceeded maximum limit of {max_redirects})",
                "http_status": 302,
                "final_url": current_url,
                "redirect_chain": redirect_chain,
                "redirect_count": len(redirect_chain),
                "elapsed_ms": elapsed,
            }

        resp = None
        try:
            # Attempt with standard TLS verification first
            try:
                resp = session.get(
                    current_url,
                    headers=PRE_SCAN_HEADERS,
                    timeout=timeout,
                    allow_redirects=False,
                    stream=True,
                    verify=True,
                )
            except requests.exceptions.SSLError:
                # If cert verification failed (common on phishing sites with self-signed certs),
                # retry with verify=False to determine if the server is responsive over HTTPS.
                try:
                    resp = session.get(
                        current_url,
                        headers=PRE_SCAN_HEADERS,
                        timeout=timeout,
                        allow_redirects=False,
                        stream=True,
                        verify=False,
                    )
                except requests.exceptions.SSLError as ssl_err:
                    elapsed = round((time.perf_counter() - t_start) * 1000, 2)
                    print(f"[REACHABILITY] TLS connection failed: {ssl_err}", flush=True)
                    return {
                        "reachable": False,
                        "ssrf_blocked": False,
                        "status": "TLS_FAILED",
                        "reachability_status": "TLS_FAILED",
                        "reachability_state": "TLS_FAILED",
                        "reason": f"TLS/HTTPS handshake failed: {ssl_err}",
                        "http_status": None,
                        "final_url": current_url,
                        "redirect_chain": redirect_chain,
                        "redirect_count": len(redirect_chain),
                        "elapsed_ms": elapsed,
                    }

        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout) as e:
            elapsed = round((time.perf_counter() - t_start) * 1000, 2)
            print(f"[REACHABILITY] Connection timeout: {e}", flush=True)
            return {
                "reachable": False,
                "ssrf_blocked": False,
                "status": "CONNECTION_TIMEOUT",
                "reachability_status": "CONNECTION_TIMEOUT",
                "reachability_state": "TIMEOUT",
                "reason": "Connection timeout: The target server did not respond within the time limit",
                "http_status": None,
                "final_url": current_url,
                "redirect_chain": redirect_chain,
                "redirect_count": len(redirect_chain),
                "elapsed_ms": elapsed,
            }

        except requests.exceptions.ConnectionError as e:
            elapsed = round((time.perf_counter() - t_start) * 1000, 2)
            err_str = str(e).lower()
            if "refused" in err_str or "10061" in err_str:
                status_code_str = "CONNECTION_REFUSED"
                reach_state = "CONNECTION_FAILED"
                reason_str = "Connection refused: Target server actively rejected the connection"
            elif "getaddrinfo" in err_str or "name or service not known" in err_str or "11001" in err_str:
                status_code_str = "DNS_FAILED"
                reach_state = "DNS_FAILED"
                reason_str = "DNS resolution failed: Domain does not exist"
            elif "timeout" in err_str:
                status_code_str = "CONNECTION_TIMEOUT"
                reach_state = "TIMEOUT"
                reason_str = "Connection timeout: Host did not respond"
            else:
                status_code_str = "HOST_UNAVAILABLE"
                reach_state = "CONNECTION_FAILED"
                reason_str = f"Host unavailable or connection reset: {e}"

            print(f"[REACHABILITY] Connection error: {reason_str}", flush=True)
            return {
                "reachable": False,
                "ssrf_blocked": False,
                "status": status_code_str,
                "reachability_status": status_code_str,
                "reachability_state": reach_state,
                "reason": reason_str,
                "http_status": None,
                "final_url": current_url,
                "redirect_chain": redirect_chain,
                "redirect_count": len(redirect_chain),
                "elapsed_ms": elapsed,
            }

        except Exception as e:
            elapsed = round((time.perf_counter() - t_start) * 1000, 2)
            print(f"[REACHABILITY] Network error: {e}", flush=True)
            return {
                "reachable": False,
                "ssrf_blocked": False,
                "status": "NETWORK_ERROR",
                "reachability_status": "NETWORK_ERROR",
                "reason": f"Network error during reachability check: {e}",
                "http_status": None,
                "final_url": current_url,
                "redirect_chain": redirect_chain,
                "redirect_count": len(redirect_chain),
                "elapsed_ms": elapsed,
            }

        status_code = resp.status_code

        # ── Redirect Handling (3xx) ──────────────────────────────────────────
        if status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location")
            resp.close()

            if not location:
                elapsed = round((time.perf_counter() - t_start) * 1000, 2)
                return {
                    "reachable": False,
                    "ssrf_blocked": False,
                    "status": "REDIRECT_UNAVAILABLE",
                    "reachability_status": "REDIRECT_UNAVAILABLE",
                    "reason": f"HTTP {status_code} redirect missing Location header",
                    "http_status": status_code,
                    "final_url": current_url,
                    "redirect_chain": redirect_chain,
                    "redirect_count": len(redirect_chain),
                    "elapsed_ms": elapsed,
                }

            next_url = urljoin(current_url, location)

            # Detect redirect loop
            if next_url in redirect_chain or next_url == current_url:
                elapsed = round((time.perf_counter() - t_start) * 1000, 2)
                print(f"[REACHABILITY] Redirect loop detected: {next_url}", flush=True)
                return {
                    "reachable": False,
                    "ssrf_blocked": False,
                    "status": "REDIRECT_UNAVAILABLE",
                    "reachability_status": "REDIRECT_UNAVAILABLE",
                    "reason": "Circular redirect loop detected",
                    "http_status": status_code,
                    "final_url": next_url,
                    "redirect_chain": redirect_chain,
                    "redirect_count": len(redirect_chain),
                    "elapsed_ms": elapsed,
                }

            # Validate redirect URL syntax
            redirect_syntax = validate_url_syntax(next_url)
            if not redirect_syntax["valid"]:
                elapsed = round((time.perf_counter() - t_start) * 1000, 2)
                return {
                    "reachable": False,
                    "ssrf_blocked": False,
                    "status": "REDIRECT_UNAVAILABLE",
                    "reachability_status": "REDIRECT_UNAVAILABLE",
                    "reason": f"Redirect destination invalid: {redirect_syntax['reason']}",
                    "http_status": status_code,
                    "final_url": next_url,
                    "redirect_chain": redirect_chain,
                    "redirect_count": len(redirect_chain),
                    "elapsed_ms": elapsed,
                }

            # ── CRITICAL: SSRF Validation on Every Redirect Hop ──────────────
            redirect_ssrf = validate_ssrf_destination(redirect_syntax["normalized_url"], resolve_dns=True)
            if not redirect_ssrf["safe"]:
                elapsed = round((time.perf_counter() - t_start) * 1000, 2)
                print(f"[SSRF] Unsafe redirect blocked: {redirect_ssrf['reason']}", flush=True)
                return {
                    "reachable": False,
                    "ssrf_blocked": True,
                    "status": "SSRF_BLOCKED",
                    "reachability_status": "SSRF_BLOCKED",
                    "reason": f"Redirect to prohibited target blocked: {redirect_ssrf['reason']}",
                    "http_status": status_code,
                    "final_url": next_url,
                    "redirect_chain": redirect_chain,
                    "redirect_count": len(redirect_chain),
                    "elapsed_ms": elapsed,
                }

            redirect_chain.append(current_url)
            current_url = redirect_syntax["normalized_url"]
            hostname = redirect_syntax["hostname"]
            continue

        # ── Valid HTTP Server Responses (2xx, 3xx, 4xx, 5xx) ───────────────────
        # Any valid HTTP response from the remote server indicates that network
        # connectivity to the server was successfully established.
        resp.close()
        elapsed = round((time.perf_counter() - t_start) * 1000, 2)

        if 200 <= status_code < 300:
            reach_state = "REACHABLE_HTTP_2XX"
            state_msg = f"Server reachable — returned HTTP {status_code}"
        elif 300 <= status_code < 400:
            reach_state = "REACHABLE_HTTP_3XX"
            state_msg = f"Server reachable — returned redirect HTTP {status_code}"
        elif 400 <= status_code < 500:
            reach_state = "REACHABLE_HTTP_4XX"
            state_msg = f"Server reachable — requested resource returned HTTP {status_code}"
        elif 500 <= status_code < 600:
            reach_state = "REACHABLE_HTTP_5XX"
            state_msg = f"Server reachable — remote server returned HTTP {status_code}"
        else:
            reach_state = f"REACHABLE_HTTP_{status_code}"
            state_msg = f"Server reachable — status {status_code}"

        print(f"[REACHABILITY] HTTP connection successful ({reach_state}: status {status_code})", flush=True)
        print(f"[REACHABILITY] URL reachable", flush=True)
        return {
            "reachable": True,
            "ssrf_blocked": False,
            "status": "REACHABLE",
            "reachability_status": "reachable",
            "reachability_state": reach_state,
            "message": state_msg,
            "reason": None,
            "http_status": status_code,
            "final_url": current_url,
            "redirect_chain": redirect_chain,
            "redirect_count": len(redirect_chain),
            "elapsed_ms": elapsed,
        }

    elapsed = round((time.perf_counter() - t_start) * 1000, 2)
    return {
        "reachable": False,
        "ssrf_blocked": False,
        "status": "REDIRECT_UNAVAILABLE",
        "reachability_status": "REDIRECT_UNAVAILABLE",
        "reachability_state": "CONNECTION_FAILED",
        "reason": "Exceeded redirect hops",
        "http_status": None,
        "final_url": current_url,
        "redirect_chain": redirect_chain,
        "redirect_count": len(redirect_chain),
        "elapsed_ms": elapsed,
    }


# Standard clean aliases
validate_url = validate_url_syntax
validate_ssrf = validate_ssrf_destination
check_reachability = check_url_reachability
