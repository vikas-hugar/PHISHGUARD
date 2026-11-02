"""
PhishGuard AI V6.3 — VirtualBox Analysis VM Controller
=======================================================
Replaces the Docker-based Deep Scan controller with a VirtualBox-based
isolated analysis VM, communicating over HTTP via a Host-Only network adapter.

Security Architecture:
  Windows Host (Flask Backend)
       ↓  HTTP POST  (Host-Only vboxnet adapter — never reaches LAN)
  VirtualBox Analysis VM  (Linux guest)
       ↓  Playwright Chromium  (isolated browser context — no host access)
  Target Website

Core Security Principles (unchanged from Docker version):
  1. The target website executes ONLY inside the isolated VirtualBox VM.
  2. The VM analysis agent uses a fresh, ephemeral browser context per scan.
  3. The VM NEVER uses host browser profiles, credentials, cookies, or clipboard.
  4. The VM NEVER mounts host filesystems.
  5. If the VM is stopped or unreachable, Deep Scan returns UNAVAILABLE immediately.
     It NEVER falls back to opening suspicious URLs in the Windows host browser.
  6. In-VM SSRF guard validates the initial URL and every redirect target.
  7. The VM is described as an "isolated disposable browser analysis environment",
     not as a guarantee of perfect security.
  8. No claim of 100% detection accuracy is made.

Configuration:
  All network parameters are read from environment variables or the defaults
  below.  NEVER hard-code the VM IP throughout the codebase; always use
  VM_CONFIG keys.

Environment overrides:
  PHISHGUARD_VM_IP          — default 192.168.56.101
  PHISHGUARD_VM_PORT        — default 8765
  PHISHGUARD_VM_TIMEOUT     — total HTTP request timeout in seconds (default 30)
  PHISHGUARD_VM_BROWSER_MS  — browser page-load timeout inside VM in ms (default 12000)
  PHISHGUARD_VM_MAX_REDIRECTS  — redirect limit (default 5)
  PHISHGUARD_VM_MAX_RESPONSE_KB — max response body size in KB (default 2048)
"""

import os
import sys
import time
import json
import uuid
import base64
import socket
import tempfile
from typing import Any

# ── VM Configuration (all from env so nothing is hard-coded at call sites) ──
VM_CONFIG: dict[str, Any] = {
    # Network — Host-Only Adapter is the preferred and default network mode.
    # DO NOT switch to bridged networking; that would expose the VM to the LAN.
    "VM_IP": os.environ.get("PHISHGUARD_VM_IP", "192.168.56.101"),
    "VM_PORT": int(os.environ.get("PHISHGUARD_VM_PORT", "8765")),

    # Multi-Stage Timeouts (configurable via env vars, all in seconds) - Requirement 11
    # MAIN_NAVIGATION_TIMEOUT = 30s, DOM_READY_TIMEOUT = 15s, RENDER_TIMEOUT = 10s,
    # SCREENSHOT_TIMEOUT = 10s, TOTAL_DEEP_SCAN_TIMEOUT = 90s, VM_TIMEOUT_SEC = 95s
    "CONNECT_TIMEOUT": float(os.environ.get("PHISHGUARD_CONNECT_TIMEOUT", "8")),
    "MAIN_NAVIGATION_TIMEOUT": float(os.environ.get("PHISHGUARD_MAIN_NAV_TIMEOUT", "30")),
    "DOM_READY_TIMEOUT": float(os.environ.get("PHISHGUARD_DOM_READY_TIMEOUT", "15")),
    "RENDER_TIMEOUT": float(os.environ.get("PHISHGUARD_RENDER_TIMEOUT", "10")),
    "SCREENSHOT_TIMEOUT": float(os.environ.get("PHISHGUARD_SCREENSHOT_TIMEOUT", "10")),
    "PAGE_ANALYSIS_TIMEOUT": float(os.environ.get("PHISHGUARD_PAGE_ANALYSIS_TIMEOUT", "30")),
    "TOTAL_DEEP_SCAN_TIMEOUT": float(os.environ.get("PHISHGUARD_TOTAL_TIMEOUT", "90")),

    # Backward compatibility with existing VM_TIMEOUT_SEC & BROWSER_TIMEOUT_MS
    "NAVIGATION_TIMEOUT": float(os.environ.get("PHISHGUARD_NAVIGATION_TIMEOUT", "30")),
    "CONTENT_SETTLE_TIMEOUT": float(os.environ.get("PHISHGUARD_SETTLE_TIMEOUT", "10")),
    "VM_TIMEOUT_SEC": float(os.environ.get("PHISHGUARD_VM_TIMEOUT", "95")),
    "BROWSER_TIMEOUT_MS": int(os.environ.get("PHISHGUARD_VM_BROWSER_MS", "30000")),

    # Safety limits forwarded to the agent
    "MAX_REDIRECTS": int(os.environ.get("PHISHGUARD_VM_MAX_REDIRECTS", "5")),
    "MAX_RESPONSE_KB": int(os.environ.get("PHISHGUARD_VM_MAX_RESPONSE_KB", "2048")),

    # Health-check TCP connect timeout (seconds)
    "HEALTH_CHECK_TIMEOUT": float(os.environ.get("PHISHGUARD_VM_HEALTH_TIMEOUT", "10")),
}

# ── Cached availability flags (populated by check_sandbox_availability) ─────
_VM_REACHABLE: bool = False
_VM_AGENT_HEALTHY: bool = False
_VM_AGENT_VERSION: str | None = None
_VM_OCR_AVAILABLE: bool = False
_VM_OCR_STATUS: str = "unavailable (install pytesseract + Tesseract)"
_SANDBOX_AVAILABLE: bool = False
_UNAVAILABILITY_REASON: str | None = "Availability check has not yet run"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _vm_base_url() -> str:
    """Construct the VM agent base URL from the current configuration."""
    return f"http://{VM_CONFIG['VM_IP']}:{VM_CONFIG['VM_PORT']}"


def _tcp_reachable(host: str, port: int, timeout: float) -> bool:
    """
    Check whether a TCP socket can be opened to host:port within *timeout*
    seconds.  This is a lightweight pre-flight check that does not require
    the requests library.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _get_requests():
    """
    Lazy-import the ``requests`` library so the module can be imported even
    if requests is not installed (availability check will report the error).
    """
    try:
        import requests as _requests
        return _requests
    except ImportError:
        return None


def _check_vm_tcp() -> tuple[bool, str | None]:
    """
    Try a raw TCP connect to the VM agent port.
    Supports dual interface fallback: tries configured VM_IP (default 192.168.56.101),
    and falls back to 127.0.0.1 (NAT forwarded) if VPN prevents Host-Only socket access.
    Returns (reachable, reason).
    """
    candidates = [VM_CONFIG["VM_IP"]]
    if "127.0.0.1" not in candidates:
        candidates.append("127.0.0.1")
    if "192.168.56.101" not in candidates:
        candidates.append("192.168.56.101")

    port = VM_CONFIG["VM_PORT"]
    timeout = VM_CONFIG["HEALTH_CHECK_TIMEOUT"]

    for host in candidates:
        if _tcp_reachable(host, port, timeout):
            VM_CONFIG["VM_IP"] = host
            return True, None

    return (
        False,
        f"VirtualBox analysis VM is not reachable at {VM_CONFIG['VM_IP']}:{port} or 127.0.0.1:{port}. "
        f"Ensure VirtualBox is running and the VM is started."
    )


def _check_vm_agent_health() -> tuple[bool, str | None, str | None]:
    """
    Query the VM agent's GET /health endpoint.
    Returns (healthy, agent_version, reason).
    """
    requests = _get_requests()
    if requests is None:
        return False, None, "The 'requests' Python library is not installed on the host."

    url = f"{_vm_base_url()}/health"
    timeout = VM_CONFIG["HEALTH_CHECK_TIMEOUT"]

    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            try:
                body = resp.json()
                global _VM_OCR_AVAILABLE, _VM_OCR_STATUS
                _VM_OCR_AVAILABLE = bool(body.get("ocr_available", False))
                _VM_OCR_STATUS = body.get("ocr_status", "available (pytesseract)" if _VM_OCR_AVAILABLE else "unavailable")
                if body.get("available", False) or body.get("status") == "ok":
                    version = body.get("version") or body.get("agent_version")
                    return True, str(version) if version else "unknown", None
                # Agent responded but says it is not ready
                reason = body.get("reason") or body.get("error") or "Agent reports not available"
                return False, None, f"VM agent unhealthy: {reason}"
            except Exception:
                # Non-JSON response — treat as healthy if HTTP 200
                return True, "unknown", None
        return (
            False,
            None,
            f"VM agent returned HTTP {resp.status_code} on /health — may be starting up."
        )
    except requests.exceptions.ConnectionError:
        return False, None, f"Connection refused by VM agent at {url}"
    except requests.exceptions.Timeout:
        return False, None, f"VM agent /health timed out after {timeout}s"
    except Exception as exc:
        return False, None, f"VM agent health check error: {exc}"


# ---------------------------------------------------------------------------
# Public API (mirrors sandbox_controller.py exactly so app.py import swap
# is a one-line change)
# ---------------------------------------------------------------------------

def check_sandbox_availability() -> dict:
    """
    Perform a two-stage availability audit:
      1. TCP reachability to VM_IP:VM_PORT
      2. HTTP GET /health on the VM analysis agent

    Updates the module-level cached flags and returns the status dictionary.
    This is called once at Flask startup and optionally re-called per request
    (see get_sandbox_status for the cached read).
    """
    global _VM_REACHABLE, _VM_AGENT_HEALTHY, _VM_AGENT_VERSION
    global _SANDBOX_AVAILABLE, _UNAVAILABILITY_REASON

    # Stage 1 — TCP reachability
    tcp_ok, tcp_reason = _check_vm_tcp()
    _VM_REACHABLE = tcp_ok

    if not tcp_ok:
        _VM_AGENT_HEALTHY = False
        _VM_AGENT_VERSION = None
        _SANDBOX_AVAILABLE = False
        _UNAVAILABILITY_REASON = tcp_reason
        return get_sandbox_status()

    # Stage 2 — HTTP health check
    agent_ok, agent_ver, agent_reason = _check_vm_agent_health()
    _VM_AGENT_HEALTHY = agent_ok
    _VM_AGENT_VERSION = agent_ver

    if not agent_ok:
        _SANDBOX_AVAILABLE = False
        _UNAVAILABILITY_REASON = agent_reason
    else:
        _SANDBOX_AVAILABLE = True
        _UNAVAILABILITY_REASON = None

    return get_sandbox_status()


def get_sandbox_status() -> dict:
    """
    Return the current cached sandbox status dictionary.

    Field names are chosen to be drop-in compatible with the /health endpoint
    in app.py.  Docker-specific fields are replaced with VM equivalents while
    keeping all fields that the frontend already reads (sandbox_available,
    sandbox_unavailability_reason, playwright_available, chromium_available).
    """
    return {
        # --- New VM fields ---
        "virtualbox_vm_reachable": _VM_REACHABLE,
        "vm_agent_healthy": _VM_AGENT_HEALTHY,
        "vm_agent_version": _VM_AGENT_VERSION,
        "vm_ip": VM_CONFIG["VM_IP"],
        "vm_port": VM_CONFIG["VM_PORT"],

        # --- Compatibility fields (same keys as sandbox_controller.py) ---
        "sandbox_available": _SANDBOX_AVAILABLE,
        # docker_* keys are set to False/None so old code that reads them
        # gracefully reports Docker as absent (which it is).
        "docker_installed": False,
        "docker_running": False,
        "docker_version": None,
        "sandbox_image_available": False,
        # Playwright & Chromium are available inside the VM when agent is healthy
        "playwright_available": _VM_AGENT_HEALTHY,
        "chromium_available": _VM_AGENT_HEALTHY,
        "ocr_available": _VM_OCR_AVAILABLE,
        "ocr_status": _VM_OCR_STATUS,
        "unavailability_reason": _UNAVAILABILITY_REASON,
    }


def run_deep_scan(url: str, fast_mode: bool = False, device_profile: str = "desktop") -> dict:
    """
    Send the target URL to the VirtualBox analysis VM for isolated browser
    analysis. Supports fast_mode for background crawl pages and device_profile
    (desktop, tablet, mobile) for responsive user agent and viewport emulation.

    CRITICAL SAFETY GUARANTEE:
    If the VM is unreachable or the agent reports an error, this function
    returns UNAVAILABLE immediately.  It NEVER opens the URL in the host
    Windows browser.  It NEVER falls back to any other local analysis.
    """
    t0 = time.perf_counter()

    # Always do a fresh availability check before executing a scan.
    # This ensures that if the VM was started after Flask launched, it works.
    status = check_sandbox_availability()

    if not status["sandbox_available"]:
        return _unavailable_result(
            url=url,
            t0=t0,
            reason=status.get("unavailability_reason",
                               "VirtualBox analysis VM is not available."),
        )

    return _execute_vm_scan(url, t0, fast_mode=fast_mode, device_profile=device_profile)


# ---------------------------------------------------------------------------
# Internal — VM scan execution
# ---------------------------------------------------------------------------

def _unavailable_result(url: str, t0: float, reason: str, error_type: str = "VM_AGENT_UNAVAILABLE") -> dict:
    """Return the standardised UNAVAILABLE result dict."""
    return {
        "available": False,
        "success": False,
        "scan_status": "UNAVAILABLE",
        "navigation_status": "ERROR",
        "error_type": error_type,
        "error": (
            f"Deep Scan unavailable: {reason}. "
            f"Quick Scan AI & heuristics are fully active."
        ),
        "redirect_chain": [],
        "final_url": url,
        "page_title": None,
        "html_raw": None,
        "dom_snapshot": None,
        "screenshot_path": None,
        "screenshot_b64": None,
        "screenshot_type": None,
        "screenshot_status": "unavailable",
        "forms": [],
        "password_fields": [],
        "email_fields": [],
        "otp_fields": [],
        "payment_fields": [],
        "external_resources": [],
        "redirect_count": 0,
        "load_time_ms": 0.0,
        "scan_time_ms": round((time.perf_counter() - t0) * 1000, 1),
        "security_warnings": [
            "Deep Scan disabled — host browser fallback is prohibited by security policy."
        ],
    }


def _execute_vm_scan(url: str, t0: float, fast_mode: bool = False, device_profile: str = "desktop") -> dict:
    """
    POST the URL to the VM agent's /analyze endpoint and process the response.
    Supports multi-stage timeouts, partial capture recovery, and comprehensive telemetry.
    """
    requests = _get_requests()
    if requests is None:
        return _unavailable_result(
            url=url,
            t0=t0,
            reason="The 'requests' library is not installed on the Flask host.",
        )

    analyze_url = f"{_vm_base_url()}/analyze"
    timeout_sec = 42.0 if fast_mode else VM_CONFIG["VM_TIMEOUT_SEC"]

    payload = {
        "url": url,
        "fast_mode": fast_mode,
        "device_profile": device_profile,
        "device": device_profile,
        "connect_timeout_ms": int(VM_CONFIG["CONNECT_TIMEOUT"] * 1000),
        "main_navigation_timeout_ms": int((28 if fast_mode else VM_CONFIG["MAIN_NAVIGATION_TIMEOUT"]) * 1000),
        "dom_ready_timeout_ms": int((12 if fast_mode else VM_CONFIG["DOM_READY_TIMEOUT"]) * 1000),
        "render_timeout_ms": int((3 if fast_mode else VM_CONFIG["RENDER_TIMEOUT"]) * 1000),
        "screenshot_timeout_ms": int((5 if fast_mode else VM_CONFIG["SCREENSHOT_TIMEOUT"]) * 1000),
        "total_scan_timeout_ms": int((38 if fast_mode else VM_CONFIG["TOTAL_DEEP_SCAN_TIMEOUT"]) * 1000),
        # Backward compatibility with older VM agent versions
        "navigation_timeout_ms": int((28 if fast_mode else VM_CONFIG["MAIN_NAVIGATION_TIMEOUT"]) * 1000),
        "content_settle_timeout_ms": int((3 if fast_mode else VM_CONFIG["RENDER_TIMEOUT"]) * 1000),
        "browser_timeout_ms": int((28 if fast_mode else VM_CONFIG["MAIN_NAVIGATION_TIMEOUT"]) * 1000),
        "max_redirects": VM_CONFIG["MAX_REDIRECTS"],
        "max_response_kb": VM_CONFIG["MAX_RESPONSE_KB"],
        # Unique scan ID for log correlation between host and VM
        "scan_id": uuid.uuid4().hex[:16],
    }

    try:
        resp = requests.post(
            analyze_url,
            json=payload,
            timeout=timeout_sec,
            # Limit response body to prevent memory issues with very large pages
            stream=False,
        )
    except requests.exceptions.ConnectionError as exc:
        return {
            "available": True,   # VM was reachable at check time; transient error
            "success": False,
            "scan_status": "UNAVAILABLE",
            "navigation_status": "PAGE_NAVIGATION_FAILED",
            "error_type": "VM_AGENT_UNAVAILABLE",
            "failure_stage": "VM Agent Network Connection",
            "stage_timings": {"total_scan_ms": round((time.perf_counter() - t0) * 1000, 1)},
            "retry_attempt": 1,
            "failed_resources": [],
            "error": f"Connection to VM analysis agent lost during scan: {exc}",
            "redirect_chain": [],
            "final_url": url,
            "page_title": None,
            "html_raw": None,
            "dom_snapshot": None,
            "screenshot_path": None,
            "screenshot_b64": None,
            "screenshot_type": None,
            "screenshot_status": "unavailable",
            "forms": [],
            "password_fields": [],
            "email_fields": [],
            "otp_fields": [],
            "payment_fields": [],
            "external_resources": [],
            "redirect_count": 0,
            "load_time_ms": 0.0,
            "scan_time_ms": round((time.perf_counter() - t0) * 1000, 1),
            "security_warnings": ["VM agent connection lost during scan."],
        }
    except requests.exceptions.Timeout:
        elapsed = round((time.perf_counter() - t0) * 1000, 1)
        return {
            "available": True,
            "success": False,
            "scan_status": "UNAVAILABLE",
            "navigation_status": "TIMEOUT",
            "error_type": "PAGE_NAVIGATION_TIMEOUT",
            "failure_stage": "MAIN_DOCUMENT",
            "stage_timings": {"total_scan_ms": elapsed},
            "retry_attempt": 1,
            "failed_resources": [],
            "error": f"PAGE_NAVIGATION_TIMEOUT: Main document timed out after {timeout_sec:.0f}s.",
            "redirect_chain": [],
            "final_url": url,
            "page_title": None,
            "html_raw": None,
            "dom_snapshot": None,
            "screenshot_path": None,
            "screenshot_b64": None,
            "screenshot_type": None,
            "screenshot_status": "unavailable",
            "forms": [],
            "password_fields": [],
            "email_fields": [],
            "otp_fields": [],
            "payment_fields": [],
            "external_resources": [],
            "redirect_count": 0,
            "load_time_ms": 0.0,
            "scan_time_ms": elapsed,
            "security_warnings": [f"Main navigation timeout after {timeout_sec:.0f}s."],
        }
    except Exception as exc:
        return {
            "available": True,
            "success": False,
            "scan_status": "ERROR",
            "navigation_status": "ERROR",
            "error_type": "NAVIGATION_ERROR",
            "error": f"VM scan request error: {exc}",
            "redirect_chain": [],
            "final_url": url,
            "page_title": None,
            "html_raw": None,
            "dom_snapshot": None,
            "screenshot_path": None,
            "screenshot_b64": None,
            "screenshot_type": None,
            "screenshot_status": "unavailable",
            "forms": [],
            "password_fields": [],
            "email_fields": [],
            "otp_fields": [],
            "payment_fields": [],
            "external_resources": [],
            "redirect_count": 0,
            "load_time_ms": 0.0,
            "scan_time_ms": round((time.perf_counter() - t0) * 1000, 1),
            "security_warnings": [f"Request exception: {exc}"],
        }

    # ── Parse the VM agent response ─────────────────────────────────────────
    if resp.status_code != 200:
        try:
            err_body = resp.json()
            if isinstance(err_body, dict) and "scan_status" in err_body:
                # Agent returned structured partial/error result
                err_body["available"] = True
                err_body["scan_time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
                return err_body
            err_msg = err_body.get("error") if isinstance(err_body, dict) else f"VM agent HTTP {resp.status_code}"
            err_type = err_body.get("error_type") if isinstance(err_body, dict) else "TARGET_ERROR"
        except Exception:
            err_msg = f"VM agent returned HTTP {resp.status_code}"
            err_type = "TARGET_ERROR"

        return {
            "available": True,
            "success": False,
            "scan_status": "UNAVAILABLE",
            "navigation_status": "ERROR",
            "error_type": err_type,
            "error": err_msg,
            "redirect_chain": [],
            "final_url": url,
            "page_title": None,
            "html_raw": None,
            "dom_snapshot": None,
            "screenshot_path": None,
            "screenshot_b64": None,
            "screenshot_type": None,
            "screenshot_status": "unavailable",
            "forms": [],
            "password_fields": [],
            "email_fields": [],
            "otp_fields": [],
            "payment_fields": [],
            "external_resources": [],
            "redirect_count": 0,
            "load_time_ms": 0.0,
            "scan_time_ms": round((time.perf_counter() - t0) * 1000, 1),
            "security_warnings": [err_msg],
        }

    try:
        result_dict: dict = resp.json()
    except Exception as parse_exc:
        return {
            "available": True,
            "success": False,
            "scan_status": "ERROR",
            "navigation_status": "ERROR",
            "error_type": "JSON_PARSE_ERROR",
            "error": f"Failed to parse VM agent JSON response: {parse_exc}",
            "redirect_chain": [],
            "final_url": url,
            "page_title": None,
            "html_raw": None,
            "dom_snapshot": None,
            "screenshot_path": None,
            "screenshot_b64": None,
            "screenshot_type": None,
            "screenshot_status": "unavailable",
            "forms": [],
            "password_fields": [],
            "email_fields": [],
            "otp_fields": [],
            "payment_fields": [],
            "external_resources": [],
            "redirect_count": 0,
            "load_time_ms": 0.0,
            "scan_time_ms": round((time.perf_counter() - t0) * 1000, 1),
            "security_warnings": ["JSON parse error on VM agent response."],
        }

    # Stamp host-side timing
    result_dict["available"] = True
    result_dict["scan_time_ms"] = round((time.perf_counter() - t0) * 1000, 1)

    # ── Handle base64-encoded screenshot from VM ─────────────────────────────
    # The VM agent sends screenshot_b64 because there is no shared filesystem.
    # We decode it to a temp file so the existing screenshot_analyzer can read it.
    screenshot_b64: str | None = result_dict.get("screenshot_b64")
    if screenshot_b64:
        try:
            temp_dir = tempfile.gettempdir()
            scr_filename = f"phishguard_vm_scr_{uuid.uuid4().hex[:10]}.png"
            scr_path = os.path.join(temp_dir, scr_filename)
            with open(scr_path, "wb") as f:
                f.write(base64.b64decode(screenshot_b64))
            result_dict["screenshot_path"] = scr_path
        except Exception as scr_exc:
            # Screenshot decode failure is non-fatal — scan continues
            result_dict["screenshot_path"] = None
            result_dict["screenshot_b64"] = None
            warnings = result_dict.get("security_warnings") or []
            warnings.append(f"Screenshot decode warning: {scr_exc}")
            result_dict["security_warnings"] = warnings
    else:
        result_dict.setdefault("screenshot_path", None)
        result_dict.setdefault("screenshot_b64", None)

    print(f"[PERF] Deep scan dispatch completed for {url} (fast_mode={fast_mode}) in {result_dict['scan_time_ms']}ms", flush=True)
    return result_dict
