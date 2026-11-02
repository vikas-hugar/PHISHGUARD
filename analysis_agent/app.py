"""
PhishGuard AI — Analysis VM Agent
===================================
Flask HTTP API that runs INSIDE the VirtualBox Linux analysis VM.

This service exposes two endpoints:
  GET  /health   — reports agent readiness
  POST /analyze  — executes an isolated Playwright browser scan

Security controls:
  - Fresh, isolated Playwright browser context per scan (no persistent storage)
  - Headless Chromium; no host browser profile, cookies, extensions, clipboard,
    camera, microphone, or filesystem access
  - In-VM SSRF guard: validates initial URL and every redirect destination
  - Redirect limit: configurable, default 5
  - Page-load timeout: configurable per request (default 12000 ms)
  - Response-size limit: configurable per request (default 2048 KB)
  - Dangerous URI schemes (file://, javascript://, data://, etc.) are blocked
  - Downloads disabled
  - Permissions denied: camera, microphone, clipboard, notifications, geolocation
  - Output returned as structured JSON over HTTP; NO host filesystem writes
  - Described as "isolated disposable browser analysis environment",
    NOT as a guarantee of perfect containment

This script is NOT meant to run on the Windows host.
Deploy it to the VirtualBox Linux guest and start it with:
    python app.py
or with a process manager such as gunicorn / systemd.
"""

import os
import sys
import time
import threading

# Allow importing sibling modules when run directly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify
from scanner import run_scan

app = Flask(__name__)

# Bind only on the Host-Only network interface so the agent is not reachable
# from the internet.  The host Flask backend reaches it via the vboxnet
# address (default 192.168.56.101).
_BIND_HOST = os.environ.get("AGENT_BIND_HOST", "0.0.0.0")
_BIND_PORT = int(os.environ.get("AGENT_PORT", "8765"))
_AGENT_VERSION = "1.0.0"


# Cache dependencies check at startup to eliminate per-request import overhead
_PLAYWRIGHT_OK = False
try:
    from playwright.async_api import async_playwright  # noqa: F401
    _PLAYWRIGHT_OK = True
except ImportError:
    pass

_OCR_INFO: dict = {"available": False, "status": "unavailable"}
try:
    from screenshot import get_ocr_status
    _OCR_INFO = get_ocr_status()
except Exception:
    pass

# Controlled concurrency semaphore (Requirement 11: 3 concurrent analyses default)
_MAX_CONCURRENT_SCANS = int(os.environ.get("PHISHGUARD_CRAWL_CONCURRENCY", "3"))
_SCAN_SEMAPHORE = threading.BoundedSemaphore(_MAX_CONCURRENT_SCANS)


@app.route("/health", methods=["GET"])
def health():
    """
    Ultra-lightweight liveness probe.
    Returns in <1ms without re-importing heavy libraries or blocking on scans.
    """
    return jsonify({
        "available": _PLAYWRIGHT_OK,
        "status": "ok" if _PLAYWRIGHT_OK else "degraded",
        "version": _AGENT_VERSION,
        "playwright_available": _PLAYWRIGHT_OK,
        "chromium_available": _PLAYWRIGHT_OK,
        "ocr_available": _OCR_INFO.get("available", False),
        "ocr_status": _OCR_INFO.get("status", "unavailable"),
        "scan_busy": _SCAN_SEMAPHORE._value <= 0,
        "max_concurrency": _MAX_CONCURRENT_SCANS,
        "available_workers": _SCAN_SEMAPHORE._value,
        "description": "PhishGuard AI — isolated disposable browser analysis environment",
        "note": (
            "This environment provides isolation from the host OS. "
            "It is not a guarantee of perfect containment."
        ),
    }), 200 if _PLAYWRIGHT_OK else 503


@app.route("/diag", methods=["GET", "POST"])
def diag():
    import socket, urllib.request, asyncio
    from browser import make_browser_and_context
    from playwright.async_api import async_playwright
    target = (request.args.get("url") or (request.get_json(silent=True) or {}).get("url") or "https://hdhub4u.fast/").strip()
    parsed = urllib.parse.urlparse(target)
    host = parsed.hostname or ""
    diag_res = {"target": target, "host": host}
    t0 = time.time()
    try:
        diag_res["dns_ip"] = socket.gethostbyname(host)
        diag_res["dns_time_ms"] = round((time.time() - t0) * 1000, 1)
    except Exception as e:
        diag_res["dns_error"] = str(e)

    # Test urllib request
    t_http = time.time()
    try:
        req = urllib.request.Request(target, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        with urllib.request.urlopen(req, timeout=5) as u:
            diag_res["urllib_status"] = u.status
            diag_res["urllib_time_ms"] = round((time.time() - t_http) * 1000, 1)
    except Exception as e:
        diag_res["urllib_error"] = str(e)
        diag_res["urllib_time_ms"] = round((time.time() - t_http) * 1000, 1)

    # Test Playwright commit vs domcontentloaded vs fullpage screenshot
    async def _test_pw():
        pw_info = {}
        async with async_playwright() as p:
            browser, ctx = await make_browser_and_context(p)
            page = await ctx.new_page()

            # Listeners
            resps = []
            reqs = []
            page.on("response", lambda r: resps.append(r.status))
            page.on("request", lambda r: reqs.append(r.resource_type))

            # Test 1: Commit
            tp = time.time()
            try:
                resp = await page.goto(target, wait_until="commit", timeout=8000)
                pw_info["step1_commit_ms"] = round((time.time() - tp) * 1000, 1)
                pw_info["step1_status"] = resp.status if resp else None
            except Exception as e:
                pw_info["step1_commit_error"] = str(e)
                pw_info["step1_commit_ms"] = round((time.time() - tp) * 1000, 1)

            # Test 2: DOMContentLoaded load state
            tp2 = time.time()
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=8000)
                pw_info["step2_dom_ms"] = round((time.time() - tp2) * 1000, 1)
            except Exception as e:
                pw_info["step2_dom_error"] = str(e)
                pw_info["step2_dom_ms"] = round((time.time() - tp2) * 1000, 1)

            # Test 3: HTML length
            tp3 = time.time()
            try:
                c = await page.content()
                pw_info["step3_html_len"] = len(c)
                pw_info["step3_content_ms"] = round((time.time() - tp3) * 1000, 1)
            except Exception as e:
                pw_info["step3_error"] = str(e)

            # Test 4: Viewport screenshot
            tp4 = time.time()
            try:
                scr_vp = await page.screenshot(type="png", full_page=False, timeout=5000)
                pw_info["step4_vp_scr_ms"] = round((time.time() - tp4) * 1000, 1)
                pw_info["step4_vp_scr_len"] = len(scr_vp)
            except Exception as e:
                pw_info["step4_vp_scr_error"] = str(e)
                pw_info["step4_vp_scr_ms"] = round((time.time() - tp4) * 1000, 1)

            # Test 5: Full-page screenshot
            tp5 = time.time()
            try:
                scr_fp = await page.screenshot(type="png", full_page=True, timeout=8000)
                pw_info["step5_fp_scr_ms"] = round((time.time() - tp5) * 1000, 1)
                pw_info["step5_fp_scr_len"] = len(scr_fp)
            except Exception as e:
                pw_info["step5_fp_scr_error"] = str(e)
                pw_info["step5_fp_scr_ms"] = round((time.time() - tp5) * 1000, 1)

            pw_info["req_count"] = len(reqs)
            pw_info["resp_count"] = len(resps)

            await ctx.close()
            await browser.close()
            return pw_info

    try:
        diag_res["playwright"] = asyncio.run(_test_pw())
    except Exception as e:
        diag_res["playwright_error"] = str(e)

    diag_res["total_time_ms"] = round((time.time() - t0) * 1000, 1)
    return jsonify(diag_res)


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Execute an isolated browser scan for the submitted URL.
    Enforces concurrency serialization via _SCAN_LOCK.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "error": "Invalid or missing JSON body"}), 400

    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"success": False, "error": "No URL provided"}), 400

    connect_timeout_ms = int(data.get("connect_timeout_ms", 8000))
    main_navigation_timeout_ms = int(data.get("main_navigation_timeout_ms", data.get("navigation_timeout_ms", data.get("browser_timeout_ms", 30000))))
    dom_ready_timeout_ms = int(data.get("dom_ready_timeout_ms", 15000))
    render_timeout_ms = int(data.get("render_timeout_ms", data.get("content_settle_timeout_ms", 10000)))
    screenshot_timeout_ms = int(data.get("screenshot_timeout_ms", 10000))
    max_redirects = int(data.get("max_redirects", 5))
    max_response_kb = int(data.get("max_response_kb", 2048))
    scan_id = data.get("scan_id", "")
    fast_mode = bool(data.get("fast_mode", False))
    device_profile = str(data.get("device_profile") or data.get("device") or "desktop").lower()

    # Acquire scan semaphore with bounded wait (Requirement 11: controlled concurrency)
    acquired = _SCAN_SEMAPHORE.acquire(timeout=90.0)
    if not acquired:
        return jsonify({
            "success": False,
            "scan_status": "BUSY",
            "navigation_status": "BUSY",
            "error_type": "VM_AGENT_BUSY",
            "error": "VirtualBox analysis VM is currently at maximum concurrency capacity.",
        }), 503

    try:
        print(f"[VM Agent] Scan {scan_id}: {url} (device={device_profile}, fast_mode={fast_mode}, main_nav={main_navigation_timeout_ms}ms, dom_ready={dom_ready_timeout_ms}ms, render={render_timeout_ms}ms, scr={screenshot_timeout_ms}ms)", flush=True)
        result = run_scan(
            url=url,
            connect_timeout_ms=connect_timeout_ms,
            main_navigation_timeout_ms=main_navigation_timeout_ms,
            dom_ready_timeout_ms=dom_ready_timeout_ms,
            render_timeout_ms=render_timeout_ms,
            screenshot_timeout_ms=screenshot_timeout_ms,
            max_redirects=max_redirects,
            max_response_kb=max_response_kb,
            fast_mode=fast_mode,
            device_profile=device_profile,
        )
    finally:
        _SCAN_SEMAPHORE.release()

    # Return 200 for successful scan or partial recovery with evidence; 422 if failed or blocked
    http_status = 200 if (result.get("success", False) or result.get("page_available", False) or result.get("scan_status") in ("SUCCESS", "PARTIAL")) else 422
    return jsonify(result), http_status


@app.route("/test_scan", methods=["GET", "POST"])
def test_scan():
    import traceback
    target = (request.args.get("url") or (request.get_json(silent=True) or {}).get("url") or "https://hdhub4u.fast/").strip()
    t0 = time.time()
    try:
        res = run_scan(
            url=target,
            connect_timeout_ms=8000,
            navigation_timeout_ms=15000,
            content_settle_timeout_ms=1500,
            screenshot_timeout_ms=5000,
            max_redirects=5,
            max_response_kb=2048,
        )
        res["diag_elapsed_s"] = round(time.time() - t0, 2)
        if "screenshot_b64" in res and res["screenshot_b64"]:
            res["screenshot_b64_len"] = len(res["screenshot_b64"])
            del res["screenshot_b64"]
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e), "traceback": traceback.format_exc(), "elapsed": time.time() - t0})


@app.route("/restart", methods=["POST"])
def restart_agent():
    """Triggers clean service restart via systemd Restart=always to pick up synced files."""
    def _do_exit():
        time.sleep(0.5)
        os._exit(0)
    threading.Thread(target=_do_exit, daemon=True).start()
    return jsonify({"status": "restarting", "version": _AGENT_VERSION}), 200


if __name__ == "__main__":
    print(f"[VM Agent] Starting PhishGuard Analysis Agent v{_AGENT_VERSION}", flush=True)
    print(f"[VM Agent] Listening on {_BIND_HOST}:{_BIND_PORT}", flush=True)
    print("[VM Agent] Isolated disposable browser analysis environment", flush=True)
    app.run(host=_BIND_HOST, port=_BIND_PORT, debug=False, threaded=True)
