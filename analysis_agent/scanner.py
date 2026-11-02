"""
PhishGuard AI — Analysis VM Agent: Scanner Module
===================================================
Orchestrates the Playwright browser scan.  Called by app.py for each
POST /analyze request.

Runs INSIDE the VirtualBox Linux guest.  Never on the Windows host.

Security controls (ported and strengthened from sandbox_agent.py):
  - validate_target_url() blocks private IPs, loopback, link-local, cloud
    metadata, dangerous schemes before any browser navigation begins
  - on_response() handler validates EVERY redirect destination — not just
    the initial URL — and sets ssrf_aborted=True on a violation so the
    browser navigation is halted on the next tick
  - on_request() handler intercepts all outbound requests and blocks
    dangerous URI schemes (file, data, javascript, vbscript, blob, about)
  - MAX_REDIRECTS enforced via the response handler
  - HTML/DOM content is truncated to MAX_HTML_CHARS to prevent OOM
  - External resource list is capped at MAX_EXTERNAL_RESOURCES
  - Screenshot captured as base64 string — no disk writes outside /tmp
  - Browser and context are always closed in a finally block
"""

import sys
import time
import base64
import socket
import asyncio
import ipaddress
from urllib.parse import urlparse, urljoin
from typing import Any

# ---------------------------------------------------------------------------
# Security constants
# ---------------------------------------------------------------------------

# All blocked IPv4/IPv6 network ranges — union of SSRF + RFC1918 + metadata
_BLOCKED_NETS_V4 = [
    ipaddress.ip_network(n) for n in [
        "0.0.0.0/8",          # Current network
        "10.0.0.0/8",         # RFC 1918 private
        "100.64.0.0/10",      # Shared address space (RFC 6598)
        "127.0.0.0/8",        # Loopback
        "169.254.0.0/16",     # Link-local / AWS/GCP metadata endpoint
        "172.16.0.0/12",      # RFC 1918 private
        "192.0.0.0/24",       # IETF protocol assignments
        "192.0.2.0/24",       # RFC 5737 Test Net 1
        "192.168.0.0/16",     # RFC 1918 private
        "198.18.0.0/15",      # Benchmark testing (RFC 2544)
        "198.51.100.0/24",    # RFC 5737 Test Net 2
        "203.0.113.0/24",     # RFC 5737 Test Net 3
        "224.0.0.0/4",        # Multicast
        "240.0.0.0/4",        # Reserved
        "255.255.255.255/32", # Broadcast
    ]
]

_BLOCKED_NETS_V6 = [
    ipaddress.ip_network(n) for n in [
        "::1/128",            # IPv6 loopback
        "fc00::/7",           # Unique Local Address (ULA) — RFC 4193
        "fe80::/10",          # Link-local
        "::ffff:0:0/96",      # IPv4-mapped
        "100::/64",           # Discard prefix
        "2001:db8::/32",      # Documentation
    ]
]

# Loopback hostname aliases
_LOOPBACK_HOSTS = frozenset([
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "broadcasthost",
])

# URI schemes that must never be navigated to
_BLOCKED_SCHEMES = frozenset([
    "file", "data", "javascript", "vbscript",
    "blob", "about", "chrome", "mhtml",
])

# Content size limits (raised to 2.5MB so real-world pages & SPAs are not truncated)
MAX_HTML_CHARS = 2_500_000
MAX_PAGE_TEXT_CHARS = 100_000
MAX_FORMS = 30
MAX_EXTERNAL_RESOURCES = 100

# Try to import Playwright
try:
    from playwright.async_api import async_playwright, TimeoutError as PwTimeout
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


# ---------------------------------------------------------------------------
# SSRF validation helpers
# ---------------------------------------------------------------------------

def _is_blocked_ip(addr_str: str) -> tuple[bool, str]:
    """
    Return (True, reason) if addr_str is a private, loopback, link-local,
    cloud-metadata, or otherwise restricted IP address.
    """
    try:
        ip = ipaddress.ip_address(addr_str)
        nets = _BLOCKED_NETS_V4 if ip.version == 4 else _BLOCKED_NETS_V6
        for net in nets:
            if ip in net:
                return True, f"IP {ip} is in blocked range {net}"
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return True, f"IP {ip} is a restricted address (private/loopback/link-local)"
        return False, ""
    except ValueError:
        return False, ""


def _resolve_host(hostname: str) -> list[str]:
    """DNS-resolve hostname to IP strings.  Returns empty list on failure."""
    try:
        infos = socket.getaddrinfo(
            hostname, None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
            0,
            socket.AI_ADDRCONFIG,
        )
        return [info[4][0] for info in infos]
    except Exception:
        return []


def is_safe_url(raw_url: str) -> tuple[bool, str]:
    """
    Validate scheme and host of a URL against SSRF and scheme-block policies.

    Returns (safe: bool, reason: str).
    reason is an empty string when safe=True.
    """
    if not raw_url:
        return False, "Empty URL"

    try:
        parsed = urlparse(raw_url)
    except Exception as exc:
        return False, f"URL parse error: {exc}"

    scheme = (parsed.scheme or "").lower()

    if scheme in _BLOCKED_SCHEMES:
        return False, f"Blocked URI scheme: '{scheme}' is not permitted"

    if scheme not in ("http", "https"):
        return False, f"Unsupported scheme '{scheme}': only http and https are allowed"

    host = parsed.hostname or ""
    if not host:
        return False, "URL contains no hostname"

    host_lower = host.lower().rstrip(".")

    # Reject known loopback hostnames
    if host_lower in _LOOPBACK_HOSTS:
        return False, f"Loopback hostname rejected: {host}"

    # If host is a direct IP literal, check it immediately
    try:
        blocked, reason = _is_blocked_ip(host_lower)
        if blocked:
            return False, reason
        return True, ""
    except Exception:
        pass

    # Hostname — resolve and check all returned IPs
    resolved_ips = _resolve_host(host_lower)
    for ip_str in resolved_ips:
        blocked, reason = _is_blocked_ip(ip_str)
        if blocked:
            return False, f"Host '{host}' resolves to blocked IP: {reason}"

    return True, ""


# ---------------------------------------------------------------------------
# Core scan
# ---------------------------------------------------------------------------

def _normalize_resource_type(rt: str | None) -> str:
    """Normalize resource type according to Requirement 10."""
    if not rt:
        return "other"
    rtl = rt.lower().strip()
    if rtl in ("document", "script", "stylesheet", "image", "font", "media", "xhr", "fetch", "websocket"):
        return rtl
    if rtl in ("subdocument", "iframe"):
        return "document"
    if rtl in ("css", "style"):
        return "stylesheet"
    if rtl in ("img", "png", "jpg", "jpeg", "svg", "webp", "gif", "ico"):
        return "image"
    if rtl in ("js", "javascript"):
        return "script"
    if rtl in ("video", "audio"):
        return "media"
    return "other"


def run_scan(
    url: str,
    connect_timeout_ms: int = 8000,
    main_navigation_timeout_ms: int = 30000,
    dom_ready_timeout_ms: int = 15000,
    render_timeout_ms: int = 10000,
    screenshot_timeout_ms: int = 10000,
    max_redirects: int = 5,
    max_response_kb: int = 2048,
    navigation_timeout_ms: int | None = None,
    content_settle_timeout_ms: int | None = None,
    browser_timeout_ms: int | None = None,
    fast_mode: bool = False,
    device_profile: str = "desktop",
) -> dict:
    """
    Synchronous entry point called from app.py.
    Wraps the async implementation with independent timeout architecture (Requirement 11)
    and a limited retry strategy (max 2 attempts) only for transient connection glitches (Requirement 12).
    """
    # Backward compatibility with older parameter names
    if browser_timeout_ms is not None and browser_timeout_ms > 0:
        main_navigation_timeout_ms = browser_timeout_ms
    elif navigation_timeout_ms is not None and navigation_timeout_ms > 0:
        main_navigation_timeout_ms = navigation_timeout_ms

    if content_settle_timeout_ms is not None and content_settle_timeout_ms > 0:
        render_timeout_ms = content_settle_timeout_ms

    # Attempt 1
    result = asyncio.run(_async_scan(
        url=url,
        connect_timeout_ms=connect_timeout_ms,
        main_navigation_timeout_ms=main_navigation_timeout_ms,
        dom_ready_timeout_ms=dom_ready_timeout_ms,
        render_timeout_ms=render_timeout_ms,
        screenshot_timeout_ms=screenshot_timeout_ms,
        max_redirects=max_redirects,
        max_response_kb=max_response_kb,
        attempt=1,
        fast_mode=fast_mode,
        device_profile=device_profile,
    ))

    # Requirement 12: Retry ONLY transient network failures (connection timeout, target unreachable, transient socket reset)
    # Do NOT retry SSRF blocked, private IP, invalid URL, HTTP 4xx/5xx, or pages where DOM was already captured.
    if (
        not result.get("success")
        and result.get("error_type") in ("CONNECTION_TIMEOUT", "TARGET_UNREACHABLE", "PAGE_NAVIGATION_TIMEOUT")
        and not result.get("security_block")
        and not result.get("page_available")
    ):
        print(f"[VM Agent] [RETRY] Attempt 1 failed with {result.get('error_type')}. Retrying navigation (Attempt 2/2)...", flush=True)
        retry_result = asyncio.run(_async_scan(
            url=url,
            connect_timeout_ms=connect_timeout_ms,
            main_navigation_timeout_ms=min(main_navigation_timeout_ms, 15000),
            dom_ready_timeout_ms=dom_ready_timeout_ms,
            render_timeout_ms=render_timeout_ms,
            screenshot_timeout_ms=screenshot_timeout_ms,
            max_redirects=max_redirects,
            max_response_kb=max_response_kb,
            attempt=2,
            fast_mode=fast_mode,
            device_profile=device_profile,
        ))
        retry_result["retry_attempt"] = 2
        return retry_result

    result["retry_attempt"] = 1
    return result


async def _async_scan(
    url: str,
    connect_timeout_ms: int,
    main_navigation_timeout_ms: int,
    dom_ready_timeout_ms: int,
    render_timeout_ms: int,
    screenshot_timeout_ms: int,
    max_redirects: int,
    max_response_kb: int,
    attempt: int = 1,
    fast_mode: bool = False,
    device_profile: str = "desktop",
) -> dict:
    """
    Async browser scan implementation with Universal Public Website Fetching:
      - 2-Step Navigation: page.goto(url, wait_until='commit') followed by wait_for_load_state('domcontentloaded')
      - Separation of main document navigation from subresource loading (Requirements 2, 3, 4)
      - Independent timeouts (Requirement 11)
      - Subresources never increment redirect_count or cause navigation failure (Requirement 10 & 13)
      - Partial success handling: main document 200 + DOM = PARTIAL/SUCCESS (Requirement 5)
      - True navigation failure only on main document connection/TLS/DNS/commit failure (Requirement 6)
      - Independent forensics: navigation, DOM, screenshot, OCR, network fail independently (Requirement 21)
    """
    start = time.perf_counter()
    stage_timings: dict[str, float] = {}
    failure_stage: str | None = None

    if not PLAYWRIGHT_AVAILABLE:
        return {
            "success": False,
            "scan_status": "UNAVAILABLE",
            "navigation_status": "ERROR",
            "error": "Playwright is not installed in the VM agent environment.",
            "error_type": "VM_PLAYWRIGHT_MISSING",
            "failure_stage": "Environment Verification",
            "stage_timings": {},
            "final_url": url,
            "redirect_chain": [],
            "scan_time_ms": 0.0,
        }

    # ── Stage 1: Pre-navigation SSRF check (Requirement 14 & 24) ────────
    print(f"[SCAN] URL received: {url} (Attempt {attempt})", flush=True)
    print(f"[SSRF] Validation started for {url}", flush=True)
    t_ssrf = time.perf_counter()
    safe, block_reason = is_safe_url(url)
    stage_timings["ssrf_ms"] = round((time.perf_counter() - t_ssrf) * 1000, 2)

    if not safe:
        print(f"[ERROR][SECURITY] SSRF blocked: {block_reason} ({stage_timings['ssrf_ms']}ms)", flush=True)
        return {
            "success": False,
            "scan_status": "BLOCKED",
            "navigation_status": "SSRF_BLOCKED",
            "security_block": True,
            "error": f"In-VM SSRF Guard blocked URL: {block_reason}",
            "error_type": "BLOCKED_BY_SSRF_GUARD",
            "failure_stage": "MAIN_DOCUMENT",
            "stage_timings": stage_timings,
            "final_url": url,
            "redirect_chain": [],
            "scan_time_ms": round((time.perf_counter() - start) * 1000, 1),
            "security_warnings": [f"SSRF block: {block_reason}"],
        }

    print(f"[SSRF] URL allowed", flush=True)

    # ── Stage 2: DNS Resolution timing ───────────────────────────────────
    t_dns = time.perf_counter()
    target_host = urlparse(url).hostname or ""
    print(f"[DNS] Resolving host: {target_host}", flush=True)
    resolved_ips = _resolve_host(target_host)
    stage_timings["dns_ms"] = round((time.perf_counter() - t_dns) * 1000, 2)

    if not resolved_ips:
        elapsed = stage_timings["dns_ms"]
        print(f"[ERROR][NAVIGATION] stage=MAIN_DOCUMENT reason=DNS_FAILED elapsed={elapsed}ms", flush=True)
        return {
            "success": False,
            "scan_status": "UNAVAILABLE",
            "navigation_status": "PAGE_NAVIGATION_FAILED",
            "security_block": False,
            "error": f"PAGE_NAVIGATION_FAILED: DNS resolution failed for host '{target_host}'.",
            "error_type": "DNS_FAILED",
            "failure_stage": "MAIN_DOCUMENT",
            "stage_timings": stage_timings,
            "final_url": url,
            "redirect_chain": [],
            "scan_time_ms": round((time.perf_counter() - start) * 1000, 1),
            "security_warnings": [f"DNS resolution failed for {target_host}"],
        }

    print(f"[DNS] Resolved in {stage_timings['dns_ms']}ms: {resolved_ips[:3]}", flush=True)

    # ── Mutable scan state ────────────────────────────────────────────────
    redirect_chain: list[str] = []
    forms: list[dict] = []
    password_fields: list[str] = []
    email_fields: list[str] = []
    otp_fields: list[str] = []
    payment_fields: list[str] = []
    form_actions: list[str] = []
    iframes: list[str] = []
    external_scripts: list[str] = []
    external_resources: list[dict] = []
    failed_resources: list[dict] = []
    discovered_links: list[str] = []
    security_warnings: list[str] = []
    dom_behavior: dict[str, Any] = {
        "temporal_snapshots": {},
        "mutation_metrics": {},
        "behavioral_events": [],
        "dynamic_password_injection": False,
        "dynamic_form_action_changed": False,
    }

    redirect_count = 0
    redirect_limit_exceeded = False
    ssrf_aborted = False
    final_url = url
    page_title = ""
    html_raw = ""
    dom_snapshot = ""
    visible_text = ""
    screenshot_b64: str | None = None
    screenshot_evidence: dict[str, Any] | None = None
    screenshot_type: str | None = None
    screenshot_status: str = "unavailable"
    load_time_ms = 0.0
    extraction_ms = 0.0
    scr_time_ms = 0.0
    ocr_time_ms = 0.0
    settle_ms = 0.0
    success = False
    error_msg: str | None = None
    error_type: str | None = None
    http_status: int | None = None
    scan_status = "PENDING"
    navigation_status = "PENDING"
    page_available = False
    screenshot_available = False
    ocr_available = False
    dom_available = False

    from browser import make_browser_and_context
    from screenshot import analyze_screenshot_bytes

    t_launch = time.perf_counter()
    async with async_playwright() as p:
        browser, context = await make_browser_and_context(p, device_profile=device_profile)
        print(f"[BROWSER] Chromium started (device_profile={device_profile})", flush=True)
        page = await context.new_page()
        print(f"[PAGE] Created", flush=True)
        stage_timings["browser_launch_ms"] = round((time.perf_counter() - t_launch) * 1000, 2)

        # Set default timeouts on page
        page.set_default_timeout(main_navigation_timeout_ms)
        page.set_default_navigation_timeout(main_navigation_timeout_ms)

        # Resource optimization & subresource SSRF route filter (Requirement 16)
        _BLOCKED_HOST_PATS = [
            "google-analytics.com", "googletagmanager.com", "doubleclick.net", "adservice.google",
            "facebook.net", "connect.facebook.net", "clarity.ms", "hotjar.com",
            "segment.io", "segment.com", "mixpanel.com", "outbrain.com", "taboola.com",
            "scorecardresearch.com", "criteo.com", "adnxs.com", "rubiconproject.com",
            "pubmatic.com", "openx.net", "casalemedia.com", "moatads.com",
            "quantserve.com", "newrelic.com", "nr-data.net", "sentry.io",
        ]
        _BLOCKED_EXTS = (".mp4", ".webm", ".avi", ".mov", ".mp3", ".wav", ".ogg")

        async def _route_filter(route: Any, req: Any) -> None:
            try:
                r_type = getattr(req, "resource_type", "")
                r_url = getattr(req, "url", None) or ""
                r_url_lower = r_url.lower()

                # 1. Scheme checks: allow data: for fonts/images, abort dangerous schemes
                if r_url_lower.startswith("data:"):
                    if r_type in ("image", "font", "media"):
                        await route.continue_()
                        return
                    else:
                        await route.abort()
                        return

                parsed_req = urlparse(r_url)
                req_scheme = (parsed_req.scheme or "").lower()
                if req_scheme in _BLOCKED_SCHEMES or (req_scheme and req_scheme not in ("http", "https")):
                    await route.abort()
                    return

                # 2. SSRF check for all subresources: block private/loopback/cloud metadata
                req_host = (parsed_req.hostname or "").lower()
                if req_host:
                    if req_host in _LOOPBACK_HOSTS or any(req_host.endswith("." + lb) for lb in ("localhost", "local", "internal")):
                        security_warnings.append(f"Subresource blocked by SSRF Guard: {r_url[:120]}")
                        await route.abort()
                        return
                    blocked_ip, _ = _is_blocked_ip(req_host)
                    if blocked_ip:
                        security_warnings.append(f"Subresource blocked by SSRF Guard (private IP): {r_url[:120]}")
                        await route.abort()
                        return

                # 3. Optimize heavy non-essential media (videos, audio)
                if r_type == "media" or any(r_url_lower.endswith(ext) for ext in _BLOCKED_EXTS):
                    await route.abort()
                    return

                # 4. Abort ad networks & tracking without failing the main document
                if any(pat in r_url_lower for pat in _BLOCKED_HOST_PATS):
                    await route.abort()
                    return

                # 5. Allow all other safe public resources (HTML, CSS, JS, images, fonts, same-origin API)
                await route.continue_()
            except Exception:
                try:
                    await route.continue_()
                except Exception:
                    pass

        try:
            await page.route("**/*", _route_filter)
        except Exception:
            pass

        # ── Response handler: decouple main document from subresources (Requirement 3, 4, 10, 13) ──
        def on_response(resp: Any) -> None:
            nonlocal redirect_count, ssrf_aborted, redirect_limit_exceeded, http_status, final_url
            if ssrf_aborted:
                return

            res_url = resp.url or ""
            req_obj = resp.request
            res_type = _normalize_resource_type(req_obj.resource_type if req_obj else "other")
            res_status = resp.status

            # Check if this response belongs strictly to the MAIN DOCUMENT navigation (Requirement 4, 10, 13)
            is_main_nav = False
            try:
                is_nav_fn = getattr(req_obj, "is_navigation_request", None)
                if callable(is_nav_fn):
                    is_main_nav = bool(is_nav_fn()) and (resp.frame == page.main_frame)
                else:
                    is_main_nav = (resp.frame == page.main_frame) and (getattr(req_obj, "resource_type", "") == "document")
            except Exception:
                is_main_nav = False

            if is_main_nav:
                # Track main document redirects
                if res_status in (301, 302, 303, 307, 308):
                    redirect_count += 1
                    redirect_chain.append(res_url)

                    if redirect_count > max_redirects:
                        redirect_limit_exceeded = True
                        ssrf_aborted = True
                        security_warnings.append(
                            f"Redirect limit exceeded ({max_redirects} hops) — navigation aborted"
                        )
                        return

                    loc = (resp.headers.get("location") or "").strip()
                    if loc:
                        full_loc = urljoin(res_url, loc)
                        rd_safe, rd_reason = is_safe_url(full_loc)
                        if not rd_safe:
                            ssrf_aborted = True
                            security_warnings.append(
                                f"Redirect to blocked destination aborted: {full_loc} — {rd_reason}"
                            )
                            return
                else:
                    # Final main document response arrived!
                    if http_status is None:
                        http_status = res_status
                    if res_url and not res_url.startswith("about:"):
                        final_url = res_url
            else:
                # Subresource fallback: if main document status is still unset, take first document
                if http_status is None and res_type == "document":
                    http_status = res_status

            # Track external resource
            r_host = urlparse(res_url).hostname or ""
            if len(external_resources) < MAX_EXTERNAL_RESOURCES:
                external_resources.append({
                    "url": res_url[:250],
                    "type": res_type,
                    "host": r_host,
                    "status": res_status,
                })

            # Subresource HTTP errors (Requirement 4 & 10: Failed resources reported separately)
            if not is_main_nav and res_status >= 400 and len(failed_resources) < 50:
                failed_resources.append({
                    "url": res_url[:250],
                    "resource_type": res_type,
                    "host": r_host,
                    "status": res_status,
                    "failure": f"HTTP {res_status}",
                })

        # ── Request failure handler: inspect network failures without aborting scan (Requirement 4 & 10) ─────
        def on_request_failed(req: Any) -> None:
            try:
                if req.is_navigation_request() and req.frame == page.main_frame:
                    return
            except Exception:
                pass
            r_url = req.url or ""
            f_reason = str(getattr(req, "failure", None) or "Failed")
            r_host = urlparse(r_url).hostname or ""
            r_type = _normalize_resource_type(req.resource_type)
            if len(failed_resources) < 50:
                failed_resources.append({
                    "url": r_url[:250],
                    "resource_type": r_type,
                    "host": r_host,
                    "status": "blocked" if "block" in f_reason.lower() else "failed",
                    "failure": f_reason,
                })

        # ── Request handler: block dangerous schemes, track externals ─────
        def on_request(req: Any) -> None:
            nonlocal ssrf_aborted
            req_url = req.url or ""
            if not req_url:
                return

            try:
                parsed_req = urlparse(req_url)
            except Exception:
                return

            req_scheme = (parsed_req.scheme or "").lower()
            if req_scheme in _BLOCKED_SCHEMES:
                security_warnings.append(
                    f"Blocked scheme request intercepted: {req_url[:120]}"
                )
                if len(failed_resources) < 50:
                    failed_resources.append({
                        "url": req_url[:250],
                        "resource_type": _normalize_resource_type(req.resource_type),
                        "host": parsed_req.hostname or "",
                        "status": "blocked",
                        "failure": f"Blocked URI scheme '{req_scheme}'",
                    })
                return

            req_host = parsed_req.hostname or ""
            if req_host and req_host != target_host:
                if req.resource_type == "script" and len(external_scripts) < 20:
                    external_scripts.append(req_url[:250])

        page.on("response", on_response)
        page.on("request", on_request)
        page.on("requestfailed", on_request_failed)

        # ── Pre-Navigation MutationObserver Injection ───────────────────────
        try:
            await page.add_init_script("""(() => {
                try {
                    window.__phishguard_observer = {
                        injected: true,
                        mutations: { total: 0, addedNodes: 0, modifiedAttrs: 0, passwordAdded: 0, formActionChanged: 0, iframeAdded: 0 },
                        events: [],
                        report: function() {
                            return { injected: this.injected, mutations: this.mutations, events: this.events };
                        }
                    };
                    const obs = new MutationObserver((mutationsList) => {
                        for (const mut of mutationsList) {
                            window.__phishguard_observer.mutations.total++;
                            if (mut.type === 'childList') {
                                for (const node of mut.addedNodes) {
                                    if (node.nodeType === 1) {
                                        window.__phishguard_observer.mutations.addedNodes++;
                                        const tag = (node.tagName || '').toUpperCase();
                                        if (tag === 'INPUT' && (node.type === 'password' || (node.name && node.name.toLowerCase().includes('password')))) {
                                            window.__phishguard_observer.mutations.passwordAdded++;
                                            window.__phishguard_observer.events.push('dynamic_password_injection');
                                        } else if (node.querySelectorAll) {
                                            const pws = node.querySelectorAll('input[type="password"]');
                                            if (pws && pws.length > 0) {
                                                window.__phishguard_observer.mutations.passwordAdded += pws.length;
                                                window.__phishguard_observer.events.push('dynamic_password_injection');
                                            }
                                        }
                                        if (tag === 'IFRAME') {
                                            window.__phishguard_observer.mutations.iframeAdded++;
                                            window.__phishguard_observer.events.push('dynamic_iframe_injection');
                                        }
                                    }
                                }
                            } else if (mut.type === 'attributes') {
                                window.__phishguard_observer.mutations.modifiedAttrs++;
                                const tag = (mut.target.tagName || '').toUpperCase();
                                if (tag === 'FORM' && mut.attributeName === 'action') {
                                    window.__phishguard_observer.mutations.formActionChanged++;
                                    window.__phishguard_observer.events.push('dynamic_form_action_mutated');
                                }
                                if (tag === 'INPUT' && mut.attributeName === 'type' && mut.target.type === 'password') {
                                    window.__phishguard_observer.mutations.passwordAdded++;
                                    window.__phishguard_observer.events.push('dynamic_password_unmasked');
                                }
                            }
                        }
                    });
                    obs.observe(document, {
                        childList: true,
                        subtree: true,
                        attributes: true
                    });
                } catch(e) {}
            })();""")
        except Exception:
            pass

        # ── STEP 1: Main Document Navigation (Requirement 2, 3, 4) ─────────
        # Uses wait_until="commit" so navigation succeeds as soon as main response arrives.
        # NEVER requires networkidle or full resource loading for navigation success!
        t_nav = time.perf_counter()
        main_doc_ok = False
        main_doc_error: str | None = None
        main_doc_error_type: str | None = None
        print(f"[NAVIGATION] Started for {url} (commit timeout={main_navigation_timeout_ms}ms)", flush=True)

        try:
            main_resp = await page.goto(
                url,
                timeout=main_navigation_timeout_ms,
                wait_until="commit",
            )
            load_time_ms = round((time.perf_counter() - t_nav) * 1000, 1)
            stage_timings["navigation_ms"] = load_time_ms

            if main_resp:
                try:
                    http_status = main_resp.status
                except Exception:
                    pass

            print(f"[NAVIGATION] Response received in {load_time_ms}ms (HTTP {http_status or 200})", flush=True)

            if ssrf_aborted:
                if redirect_limit_exceeded:
                    raise ValueError(f"Redirect limit exceeded ({max_redirects} hops)")
                raise ValueError("Navigation halted: redirect attempted to reach a blocked address.")

            main_doc_ok = True
            navigation_status = "SUCCESS"

        except PwTimeout:
            elapsed = round((time.perf_counter() - t_nav) * 1000, 1)
            print(f"[TIMEOUT] page.goto commit timed out after {elapsed}ms for {url}. Attempting partial DOM recovery...", flush=True)
            try:
                rec_content = await page.content()
                if rec_content and len(rec_content.strip()) > 100 and rec_content.strip() != "<html><head></head><body></body></html>":
                    print(f"[RECOVERY] Successfully recovered {len(rec_content)} bytes of HTML after navigation timeout!", flush=True)
                    main_doc_ok = True
                    navigation_status = "PARTIAL_RECOVERED"
            except Exception as rec_err:
                print(f"[RECOVERY] DOM recovery failed: {rec_err}", flush=True)

            if not main_doc_ok:
                failure_stage = "MAIN_DOCUMENT"
                navigation_status = "PAGE_NAVIGATION_FAILED"
                main_doc_error_type = "PAGE_NAVIGATION_TIMEOUT"
                main_doc_error = f"PAGE_NAVIGATION_TIMEOUT: Target server main document took longer than {main_navigation_timeout_ms}ms to respond."
                security_warnings.append(main_doc_error)
                print(f"[ERROR][NAVIGATION] stage=MAIN_DOCUMENT reason=TIMEOUT elapsed={elapsed}ms", flush=True)

        except ValueError as val_err:
            elapsed = round((time.perf_counter() - t_nav) * 1000, 1)
            main_doc_error = str(val_err)
            if redirect_limit_exceeded:
                failure_stage = "REDIRECTS"
                navigation_status = "REDIRECT_LIMIT_EXCEEDED"
                main_doc_error_type = "REDIRECT_LIMIT_EXCEEDED"
            else:
                failure_stage = "SSRF_GUARD"
                navigation_status = "BLOCKED_BY_SSRF_GUARD"
                main_doc_error_type = "BLOCKED_BY_SSRF_GUARD"
            security_warnings.append(main_doc_error)
            print(f"[ERROR][SECURITY] stage={failure_stage} reason={main_doc_error_type} elapsed={elapsed}ms", flush=True)

        except Exception as nav_exc:
            elapsed = round((time.perf_counter() - t_nav) * 1000, 1)
            nav_str = str(nav_exc)
            failure_stage = "MAIN_DOCUMENT"
            navigation_status = "PAGE_NAVIGATION_FAILED"
            if any(k in nav_str.upper() for k in ("CERT", "SSL", "TLS", "AUTHORITY_INVALID")):
                main_doc_error_type = "TLS_ERROR"
                reason_code = "TLS_HANDSHAKE_FAILED"
            elif any(k in nav_str.upper() for k in ("ERR_NAME_NOT_RESOLVED", "ENOTFOUND", "NAME_NOT_RESOLVED", "GAI_ERROR", "GETADDRINFO")):
                main_doc_error_type = "DNS_FAILED"
                reason_code = "DNS_RESOLUTION_FAILED"
            elif any(k in nav_str.upper() for k in ("ERR_CONNECTION_TIMED_OUT", "ETIMEDOUT", "CONNECTION_TIMEOUT", "CONNECT TIMEOUT")):
                main_doc_error_type = "CONNECTION_TIMEOUT"
                reason_code = "CONNECTION_TIMEOUT"
            elif any(k in nav_str.upper() for k in ("ECONNREFUSED", "ERR_CONNECTION_REFUSED", "ERR_CONNECTION")):
                main_doc_error_type = "TARGET_UNREACHABLE"
                reason_code = "CONNECTION_REFUSED"
            elif any(k in nav_str.upper() for k in ("CRASH", "DISCONNECTED", "TARGET CLOSED")):
                main_doc_error_type = "BROWSER_ERROR"
                reason_code = "BROWSER_PROCESS_CRASH"
            elif "Timeout" in nav_str:
                main_doc_error_type = "PAGE_NAVIGATION_TIMEOUT"
                reason_code = "TIMEOUT"
            else:
                main_doc_error_type = "NAVIGATION_ERROR"
                reason_code = "NAVIGATION_ERROR"
            main_doc_error = f"{main_doc_error_type}: {nav_str[:250]}"
            security_warnings.append(main_doc_error)
            print(f"[ERROR][NAVIGATION] stage=MAIN_DOCUMENT reason={reason_code} elapsed={elapsed}ms", flush=True)

        # ── STEP 2: DOM Availability (Requirement 2 & 3) ───────────────────
        if main_doc_ok and not (ssrf_aborted and not redirect_limit_exceeded):
            t_dom = time.perf_counter()
            print(f"[NAVIGATION] DOMContentLoaded waiting (timeout={dom_ready_timeout_ms}ms)...", flush=True)
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=dom_ready_timeout_ms)
                stage_timings["dom_ready_ms"] = round((time.perf_counter() - t_dom) * 1000, 1)
                print(f"[NAVIGATION] DOMContentLoaded completed in {stage_timings['dom_ready_ms']}ms", flush=True)
            except Exception as dom_wait_err:
                stage_timings["dom_ready_ms"] = round((time.perf_counter() - t_dom) * 1000, 1)
                print(f"[NAVIGATION] DOMContentLoaded wait reached limit ({dom_ready_timeout_ms}ms); proceeding to render stabilization: {dom_wait_err}", flush=True)

            # Allow required JavaScript execution & wait for network activity to settle (faster in fast_mode)
            try:
                net_timeout = 400 if fast_mode else min(dom_ready_timeout_ms, 1800)
                await page.wait_for_load_state("networkidle", timeout=net_timeout)
            except Exception:
                pass

            # Capture T0 snapshot immediately after DOM readiness
            t0_input_count = 0
            t0_password_count = 0
            t0_html_len = 0
            try:
                t0_html_len = await page.evaluate("() => document.documentElement ? document.documentElement.outerHTML.length : 0")
                t0_counts = await page.evaluate("""() => {
                    const inputs = document.querySelectorAll('input');
                    let pw = 0;
                    for (const inp of inputs) {
                        if (inp.type === 'password' || (inp.name && inp.name.toLowerCase().includes('password'))) {
                            pw++;
                        }
                    }
                    return { inputs: inputs.length, passwords: pw };
                }""")
                if isinstance(t0_counts, dict):
                    t0_input_count = t0_counts.get("inputs", 0)
                    t0_password_count = t0_counts.get("passwords", 0)
            except Exception:
                pass

            # ── STEP 3 & 4: JavaScript Execution & Stabilization (Requirement 8 & 9) ──
            t_settle = time.perf_counter()
            print(f"[RENDER] Stabilization started", flush=True)
            try:
                fn_timeout = 800 if fast_mode else min(render_timeout_ms, 2500)
                await page.wait_for_function(
                    """() => {
                        const b = document.body;
                        if (!b) return false;
                        if ((b.innerText || '').trim().length > 20) return true;
                        const roots = document.querySelectorAll('#root, #app, #__next, main, [id*="app"], [id*="content"], article, section');
                        for (const r of roots) {
                            if (r.children && r.children.length > 0) return true;
                        }
                        return Boolean(b.children && b.children.length > 0);
                    }""",
                    timeout=fn_timeout,
                )
            except Exception:
                pass

            # Bounded micro settle for layout and font stabilization (faster in fast_mode)
            settle_s = 0.05 if fast_mode else min(render_timeout_ms / 1000.0, 0.4)
            try:
                await asyncio.sleep(settle_s)
            except Exception:
                pass
            settle_ms = round((time.perf_counter() - t_settle) * 1000, 1)
            stage_timings["stabilization_ms"] = settle_ms
            print(f"[RENDER] Stabilization complete in {settle_ms}ms", flush=True)

            # Capture T1 observer report after stabilization
            t1_html_len = 0
            t1_input_count = 0
            try:
                obs_report = await page.evaluate("() => window.__phishguard_observer ? window.__phishguard_observer.report() : null")
                t1_html_len = await page.evaluate("() => document.documentElement ? document.documentElement.outerHTML.length : 0")
                t1_counts = await page.evaluate("() => document.querySelectorAll('input').length")
                t1_input_count = t1_counts if isinstance(t1_counts, int) else 0

                dom_behavior["mutation_observer_injected"] = bool(obs_report and obs_report.get("injected"))
                dom_behavior["stabilization_wait_ms"] = int(settle_ms)

                if isinstance(obs_report, dict):
                    obs_muts = obs_report.get("mutations", {})
                    obs_evts = obs_report.get("events", [])
                    dom_behavior["mutation_metrics"] = {
                        "total_mutations": obs_muts.get("total", 0),
                        "added_nodes": obs_muts.get("addedNodes", 0),
                        "modified_attributes": obs_muts.get("modifiedAttrs", 0),
                        "iframe_added": obs_muts.get("iframeAdded", 0),
                    }
                    dom_behavior["behavioral_events"] = obs_evts
                    if obs_muts.get("passwordAdded", 0) > 0:
                        dom_behavior["dynamic_password_injection"] = True
                    if obs_muts.get("formActionChanged", 0) > 0:
                        dom_behavior["dynamic_form_action_changed"] = True
                    if obs_muts.get("iframeAdded", 0) > 0:
                        dom_behavior["iframe_injection"] = True

                dom_behavior["temporal_snapshots"] = {
                    "t0_html_len": t0_html_len,
                    "t0_input_count": t0_input_count,
                    "t0_password_count": t0_password_count,
                    "t1_html_len": t1_html_len,
                    "t1_input_count": t1_input_count,
                    "t1_password_count": 0,
                }
            except Exception:
                pass

        # ── STEP 5 & 6: DOM Extraction (Full or Partial) (Requirement 3, 5, 6) ─
        if not (ssrf_aborted and not redirect_limit_exceeded):
            try:
                is_closed = page.is_closed()
            except Exception:
                is_closed = True

            if not is_closed:
                try:
                    p_url = page.url
                    if p_url and p_url != "about:blank":
                        final_url = p_url
                except Exception:
                    pass

                # Extract HTML & DOM snapshot
                t_extract = time.perf_counter()
                print(f"[DOM] Extraction started", flush=True)
                try:
                    content = await page.content()
                    if content and content.strip() and content != "<html><head></head><body></body></html>":
                        html_raw = content[:MAX_HTML_CHARS]
                        dom_snapshot = html_raw
                        page_available = True
                        dom_available = True
                except Exception as dom_exc:
                    security_warnings.append(f"DOM extraction warning: {str(dom_exc)[:120]}")

                # Page Title
                try:
                    t = await page.title()
                    if t:
                        page_title = t[:200]
                except Exception:
                    pass

                # Visible Body Text
                try:
                    visible_text = await page.evaluate(
                        "() => document.body ? document.body.innerText : ''"
                    )
                    visible_text = (visible_text or "")[:MAX_PAGE_TEXT_CHARS]
                except Exception:
                    visible_text = ""

                # Forms, Inputs, Iframes & Links — Single high-performance in-browser extraction (Requirement 16, 19, 21)
                try:
                    dom_data = await page.evaluate("""() => {
                        const forms = [];
                        const passwordFields = [];
                        const emailFields = [];
                        const otpFields = [];
                        const paymentFields = [];
                        const formActions = [];

                        const formEls = document.querySelectorAll('form');
                        for (const f of Array.from(formEls).slice(0, 20)) {
                            const action = (f.getAttribute('action') || '').slice(0, 250);
                            const method = (f.getAttribute('method') || 'get').toLowerCase();
                            formActions.push(action);

                            const inputTypes = [];
                            const inps = f.querySelectorAll('input');
                            for (const inp of Array.from(inps)) {
                                const itype = (inp.getAttribute('type') || 'text').toLowerCase();
                                const iname = (inp.getAttribute('name') || '');
                                const iph = (inp.getAttribute('placeholder') || '');
                                inputTypes.push(itype);
                                const combined = (iname + ' ' + iph).toLowerCase();

                                if (itype === 'password' || combined.includes('password')) {
                                    passwordFields.push(iname || 'password');
                                } else if (itype === 'email' || combined.includes('email') || combined.includes('user')) {
                                    emailFields.push(iname || 'email');
                                } else if (['otp', 'code', 'token', '2fa', 'mfa'].some(k => combined.includes(k))) {
                                    otpFields.push(iname || 'otp');
                                } else if (['card', 'cvv', 'cvc', 'exp', 'payment'].some(k => combined.includes(k))) {
                                    paymentFields.push(iname || 'payment');
                                }
                            }
                            forms.push({
                                action: action,
                                method: method,
                                input_types: inputTypes,
                                has_password: passwordFields.length > 0,
                            });
                        }

                        const iframes = Array.from(document.querySelectorAll('iframe'))
                            .slice(0, 15)
                            .map(ifr => ifr.getAttribute('src') || '')
                            .filter(Boolean)
                            .map(s => s.slice(0, 250));

                        // Comprehensive Link Extraction from Rendered DOM (Requirements 8, 13, 33)
                        const links = [];
                        const seenHrefs = new Set();
                        
                        // 1. All anchor and area elements with href
                        const anchorEls = document.querySelectorAll('a[href], area[href]');
                        for (const a of Array.from(anchorEls).slice(0, 250)) {
                            const rawHref = (a.getAttribute('href') || '').trim();
                            const resolvedHref = (a.href || rawHref).trim();
                            const targetHref = resolvedHref || rawHref;
                            if (!targetHref || targetHref.startsWith('#') || targetHref.startsWith('javascript:') || targetHref.startsWith('mailto:') || targetHref.startsWith('tel:') || targetHref.startsWith('data:')) {
                                continue;
                            }
                            if (!seenHrefs.has(targetHref)) {
                                seenHrefs.add(targetHref);
                                const text = (a.innerText || a.getAttribute('title') || a.getAttribute('aria-label') || '').trim().replace(/\s+/g, ' ');
                                links.push({
                                    href: targetHref.slice(0, 500),
                                    raw_href: rawHref.slice(0, 500),
                                    text: text.slice(0, 80),
                                    tag: a.tagName.toLowerCase(),
                                });
                            }
                        }

                        // 2. Client-side SPA navigation attributes
                        const spaEls = document.querySelectorAll('[data-href], [data-to], [routerlink], [data-route], [data-url]');
                        for (const el of Array.from(spaEls).slice(0, 100)) {
                            const route = (el.getAttribute('data-href') || el.getAttribute('data-to') || el.getAttribute('routerlink') || el.getAttribute('data-route') || el.getAttribute('data-url') || '').trim();
                            if (!route || route.startsWith('#') || route.startsWith('javascript:') || seenHrefs.has(route)) {
                                continue;
                            }
                            seenHrefs.add(route);
                            const text = (el.innerText || el.getAttribute('title') || '').trim().replace(/\s+/g, ' ');
                            links.push({
                                href: route.slice(0, 500),
                                raw_href: route.slice(0, 500),
                                text: text.slice(0, 80),
                                tag: 'spa_route',
                            });
                        }

                        return {
                            forms,
                            formActions,
                            passwordFields,
                            emailFields,
                            otpFields,
                            paymentFields,
                            iframes,
                            links,
                        };
                    }""")
                    if isinstance(dom_data, dict):
                        forms = dom_data.get("forms", [])
                        form_actions = dom_data.get("formActions", [])
                        password_fields = dom_data.get("passwordFields", [])
                        email_fields = dom_data.get("emailFields", [])
                        otp_fields = dom_data.get("otpFields", [])
                        payment_fields = dom_data.get("paymentFields", [])
                        iframes = dom_data.get("iframes", [])
                        discovered_links = dom_data.get("links", [])
                        print(f"[LINKS] DOM links discovered: {len(discovered_links)}", flush=True)
                except Exception as eval_exc:
                    security_warnings.append(f"DOM structure extraction warning: {str(eval_exc)[:120]}")

                # Safe internal scroll to trigger lazy loading / IntersectionObservers
                try:
                    await page.evaluate("""() => {
                        try {
                            const totalHeight = document.body ? document.body.scrollHeight : 0;
                            const viewportHeight = window.innerHeight || 800;
                            if (totalHeight > viewportHeight) {
                                window.scrollTo(0, totalHeight);
                                window.scrollTo(0, 0);
                            }
                        } catch(e) {}
                    }""")
                except Exception:
                    pass

                extraction_ms = round((time.perf_counter() - t_extract) * 1000, 1)
                stage_timings["dom_extraction_ms"] = extraction_ms
                print(f"[DOM] Extraction complete in {extraction_ms}ms (HTML {len(html_raw)} chars, Text {len(visible_text)} chars)", flush=True)

                # ── STEP 7: Screenshot Capture (Requirement 18 & 21) ──────────
                scr_bytes: bytes | None = None
                scr_timeout_s = min(screenshot_timeout_ms / 1000.0, 10.0)
                t_scr = time.perf_counter()
                print(f"[SCREENSHOT] Capturing (timeout={scr_timeout_s:.1f}s)...", flush=True)

                try:
                    # Viewport first (fast and reliable)
                    try:
                        scr_bytes = await asyncio.wait_for(
                            page.screenshot(type="png", full_page=False),
                            timeout=scr_timeout_s,
                        )
                        screenshot_type = "viewport"
                    except Exception:
                        pass

                    if scr_bytes:
                        if len(scr_bytes) > 5 * 1024 * 1024:
                            scr_bytes = await page.screenshot(type="png", full_page=False)
                            screenshot_type = "viewport"

                        screenshot_b64 = base64.b64encode(scr_bytes).decode("ascii")
                        screenshot_available = True
                        screenshot_status = "captured"
                        scr_time_ms = round((time.perf_counter() - t_scr) * 1000, 1)
                        stage_timings["screenshot_ms"] = scr_time_ms
                        print(f"[SCREENSHOT] Captured mode {screenshot_type} in {scr_time_ms}ms", flush=True)

                        # Isolated in-VM OCR — Independent forensic component with bounded timeout
                        if fast_mode:
                            # In fast mode, skip heavy OCR; mark deferred (Requirement 13 & 14)
                            screenshot_evidence = {
                                "available": True,
                                "ocr_available": False,
                                "ocr_status": "deferred_in_fast_mode",
                                "ocr_word_count": 0,
                            }
                        else:
                            t_ocr = time.perf_counter()
                            try:
                                screenshot_evidence = await asyncio.wait_for(
                                    asyncio.to_thread(analyze_screenshot_bytes, scr_bytes),
                                    timeout=12.0,
                                )
                            except Exception as ocr_to_err:
                                screenshot_evidence = {
                                    "available": True,
                                    "ocr_available": False,
                                    "ocr_status": "timeout_or_failed",
                                    "error": f"OCR skipped/timeout: {str(ocr_to_err)[:100]}",
                                }
                            ocr_time_ms = round((time.perf_counter() - t_ocr) * 1000, 1)
                            stage_timings["ocr_ms"] = ocr_time_ms
                            if screenshot_evidence and screenshot_evidence.get("ocr_available"):
                                ocr_available = True
                                print(f"[OCR] Completed in {ocr_time_ms}ms (words={screenshot_evidence.get('ocr_word_count', 0)})", flush=True)

                except Exception as scr_exc:
                    security_warnings.append(
                        f"Screenshot capture warning: {str(scr_exc)[:120]}"
                    )
                    screenshot_status = "unavailable"
                    screenshot_evidence = {
                        "available": False,
                        "ocr_available": False,
                        "error": f"Screenshot capture warning: {str(scr_exc)[:120]}",
                    }

        # Fallback viewport screenshot recovery if main capture missed but page handle exists
        if not screenshot_available and page:
            try:
                scr_fb_bytes = await page.screenshot(type="png", full_page=False, timeout=3000)
                if scr_fb_bytes and len(scr_fb_bytes) > 200:
                    screenshot_b64 = base64.b64encode(scr_fb_bytes).decode("ascii")
                    screenshot_available = True
                    screenshot_status = "viewport_recovered"
                    print(f"[RECOVERY] Captured fallback viewport screenshot ({len(scr_fb_bytes)} bytes)", flush=True)
            except Exception:
                pass

        # Telemetry logging (Requirement 24)
        print(f"[NETWORK] Resources recorded (total={len(external_resources)}, failed={len(failed_resources)})", flush=True)
        print(f"[SAFEVIEW] Representation stored", flush=True)

        # ── Status Resolution (Requirement 4, 5, 6, 22) ───────────────────
        if ssrf_aborted and not redirect_limit_exceeded:
            scan_status = "BLOCKED"
            success = False
            error_msg = main_doc_error or "BLOCKED BY SSRF GUARD"
            error_type = "BLOCKED_BY_SSRF_GUARD"
        elif redirect_limit_exceeded:
            scan_status = "PARTIAL"
            success = True if (page_available or screenshot_available) else False
            error_type = "REDIRECT_LIMIT_EXCEEDED"
            error_msg = f"Redirect limit exceeded ({max_redirects} hops)"
        elif page_available:
            # Main document succeeded and DOM was extracted!
            success = True
            if len(failed_resources) > 0:
                scan_status = "PARTIAL"
            else:
                scan_status = "SUCCESS"
            error_msg = None
            error_type = None

            # Server HTTP errors on main document (e.g. 403, 404, 500)
            if http_status and http_status >= 400:
                error_type = f"HTTP_{http_status}"
                error_msg = f"Target server responded with HTTP {http_status}"
        elif screenshot_available:
            # Partial: screenshot captured even if DOM was sparse
            scan_status = "PARTIAL"
            success = True
            error_msg = None
            error_type = None
        else:
            # True navigation failure: main document itself could not be reached
            scan_status = "UNAVAILABLE"
            success = False
            error_type = main_doc_error_type or "PAGE_NAVIGATION_FAILED"
            error_msg = main_doc_error or f"Navigation failed ({error_type})."

        # ── Cleanup: close isolated context and browser ───
        if context is not None:
            try:
                await context.close()
            except Exception:
                pass
        if browser is not None:
            try:
                await browser.close()
            except Exception:
                pass

    total_ms = round((time.perf_counter() - start) * 1000, 1)
    stage_timings["total_scan_ms"] = total_ms

    # ── Reachability & Browser Render State Machine ──
    if ssrf_aborted and not redirect_limit_exceeded:
        reachability_state = "SSRF_BLOCKED"
        browser_render_state = "BROWSER_RENDER_FAILED"
        server_response_msg = "Blocked by SSRF Guard"
    elif http_status is not None:
        if 200 <= http_status < 300:
            reachability_state = "REACHABLE_HTTP_2XX"
            server_response_msg = f"Server reachable — returned HTTP {http_status}"
        elif 300 <= http_status < 400:
            reachability_state = "REACHABLE_HTTP_3XX"
            server_response_msg = f"Server reachable — returned redirect HTTP {http_status}"
        elif 400 <= http_status < 500:
            reachability_state = "REACHABLE_HTTP_4XX"
            server_response_msg = f"Server reachable — requested resource returned HTTP {http_status}"
        elif 500 <= http_status < 600:
            reachability_state = "REACHABLE_HTTP_5XX"
            server_response_msg = f"Server reachable — remote server returned HTTP {http_status}"
        else:
            reachability_state = f"REACHABLE_HTTP_{http_status}"
            server_response_msg = f"Server reachable — HTTP {http_status}"
        browser_render_state = "BROWSER_RENDERED" if (page_available or screenshot_available) else "BROWSER_RENDER_FAILED"
    else:
        # Genuine network failure
        if main_doc_error_type in ("DNS_FAILED", "DNS_RESOLUTION_FAILED"):
            reachability_state = "DNS_FAILED"
            server_response_msg = "Could not establish a connection to destination server: DNS resolution failed."
        elif main_doc_error_type in ("CONNECTION_TIMEOUT", "TIMEOUT", "PAGE_NAVIGATION_TIMEOUT"):
            reachability_state = "TIMEOUT"
            server_response_msg = "Could not establish a connection to destination server: Connection timeout."
        elif main_doc_error_type in ("TLS_ERROR", "TLS_HANDSHAKE_FAILED"):
            reachability_state = "TLS_FAILED"
            server_response_msg = "Could not establish a secure connection: TLS handshake failed."
        elif main_doc_error_type in ("TARGET_UNREACHABLE", "CONNECTION_REFUSED"):
            reachability_state = "CONNECTION_FAILED"
            server_response_msg = "Could not establish a connection to destination server: Connection refused."
        else:
            reachability_state = "CONNECTION_FAILED"
            server_response_msg = f"Could not establish a connection to destination server ({main_doc_error_type})."
        browser_render_state = "BROWSER_RENDER_FAILED"

    print(f"[PERF] URL={url} | Navigation: {stage_timings.get('navigation_ms', 0)}ms | DOM ready: {stage_timings.get('dom_ready_ms', 0)}ms | Extraction: {stage_timings.get('dom_extraction_ms', 0)}ms | Screenshot: {stage_timings.get('screenshot_ms', 0)}ms | Total: {total_ms}ms", flush=True)
    print(f"[SCAN] Completed for {url}: status={scan_status}, success={success}, reach={reachability_state}, render={browser_render_state} in {total_ms}ms", flush=True)

    return {
        "success": success,
        "scan_status": scan_status,
        "navigation_status": navigation_status,
        "reachability_state": reachability_state,
        "browser_render_state": browser_render_state,
        "server_response_message": server_response_msg,
        "device_profile": device_profile,
        "error": error_msg,
        "error_type": error_type,
        "failure_stage": failure_stage,
        "stage_timings": stage_timings,
        "http_status": http_status,
        "page_available": page_available,
        "screenshot_available": screenshot_available,
        "ocr_available": ocr_available,
        "dom_available": dom_available,
        "screenshot_type": screenshot_type,
        "screenshot_status": screenshot_status,
        "original_url": url,
        "final_url": final_url,
        "redirect_chain": redirect_chain[:max_redirects],
        "redirect_count": redirect_count,
        "page_title": page_title,
        "html_raw": html_raw[:MAX_HTML_CHARS],
        "dom_snapshot": dom_snapshot,
        "visible_text": visible_text,
        "forms": forms,
        "password_fields": list(set(password_fields)),
        "email_fields": list(set(email_fields)),
        "otp_fields": list(set(otp_fields)),
        "payment_fields": list(set(payment_fields)),
        "form_actions": form_actions,
        "iframes": iframes,
        "external_scripts": external_scripts,
        "external_resources": external_resources,
        "failed_resources": failed_resources,
        "discovered_links": discovered_links,
        "screenshot_b64": screenshot_b64,
        "screenshot_evidence": screenshot_evidence,
        "dom_behavior": dom_behavior,
        "load_time_ms": load_time_ms,
        "scan_time_ms": total_ms,
        "security_warnings": security_warnings,
    }

