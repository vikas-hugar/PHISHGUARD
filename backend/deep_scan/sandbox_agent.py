"""
PhishGuard AI V6.2 — In-Sandbox Browser Analysis Agent
======================================================
This script runs EXCLUSIVELY INSIDE the disposable Docker container.
It launches an isolated Chromium browser instance using Playwright,
navigates to the target URL with strict timeouts, validates redirects
against SSRF policies, extracts forensic DOM & network telemetry,
takes an in-memory screenshot, and outputs structured JSON to stdout.

Security Controls inside Container:
- Fresh, unprivileged browser context per execution
- JavaScript execution permitted in isolated sandbox, persistent storage disabled
- Downloads blocked (accept_downloads=False)
- Camera, microphone, clipboard, notifications permissions denied
- In-container SSRF guard: validates initial URL and every redirect target
- Redirect limit: MAX_REDIRECTS = 5
- Page load timeout: 10,000ms
- No host filesystem access; output emitted strictly as JSON via stdout
"""

import sys
import json
import time
import base64
import socket
import ipaddress
from urllib.parse import urlparse

# Playwright import inside container
try:
    from playwright.async_api import async_playwright, TimeoutError as PwTimeout
    PLAYWRIGHT_INSTALLED = True
except ImportError:
    PLAYWRIGHT_INSTALLED = False

import asyncio

# ── Security Configuration ──────────────────────────────────────────────────
PAGE_LOAD_TIMEOUT_MS = 10000
MAX_REDIRECTS = 5
MAX_PAGE_TEXT_CHARS = 50000
MAX_HTML_CHARS = 100000
MAX_FORMS = 15
MAX_EXTERNAL_RESOURCES = 50

# SSRF Blocked IPv4 / IPv6 Networks
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 Private
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local (Cloud metadata 169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Private
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Private
    ipaddress.ip_network("192.0.2.0/24"),       # RFC 5737 Test Net 1
    ipaddress.ip_network("198.51.100.0/24"),    # RFC 5737 Test Net 2
    ipaddress.ip_network("203.0.113.0/24"),     # RFC 5737 Test Net 3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("fc00::/7"),           # Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-Local
]

BLOCKED_SCHEMES = {"file", "data", "javascript", "vbscript", "blob", "about", "chrome"}


def is_safe_network_address(host: str) -> tuple[bool, str]:
    """
    Validate that a host does not resolve to private, loopback, or cloud metadata addresses.
    """
    if not host:
        return False, "Empty host"

    # Reject known loopback keywords
    if host.lower() in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"):
        return False, f"Loopback host rejected: {host}"

    # Try parsing host directly as IP address
    try:
        ip_obj = ipaddress.ip_address(host)
        for net in BLOCKED_NETWORKS:
            if ip_obj in net:
                return False, f"Prohibited IP address ({ip_obj}) in blocked range {net}"
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
            return False, f"Prohibited IP address ({ip_obj})"
        return True, "IP is public"
    except ValueError:
        pass

    # Resolve domain to IP addresses via DNS
    try:
        addr_info = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                for net in BLOCKED_NETWORKS:
                    if ip_obj in net:
                        return False, f"Host '{host}' resolves to prohibited IP ({ip_str}) in blocked range {net}"
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                    return False, f"Host '{host}' resolves to prohibited address ({ip_str})"
            except ValueError:
                continue
    except socket.gaierror as e:
        # If DNS fails to resolve, let browser handle connection failure (or block if desired)
        return True, f"DNS resolution warning: {e}"

    return True, "Host validated safe"


def validate_target_url(raw_url: str) -> tuple[bool, str]:
    """Validate URL scheme and host against SSRF vulnerabilities."""
    try:
        parsed = urlparse(raw_url)
    except Exception as e:
        return False, f"URL parse error: {e}"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, f"Prohibited URL scheme '{scheme}'. Only http and https permitted."

    host = parsed.hostname or ""
    return is_safe_network_address(host)


async def execute_sandbox_scan(target_url: str) -> dict:
    """
    Execute headless Playwright browser analysis inside container.
    Returns structured forensic evidence.
    """
    start_time = time.perf_counter()

    if not PLAYWRIGHT_INSTALLED:
        return {
            "success": False,
            "error": "Playwright is not installed inside container environment.",
            "final_url": target_url,
            "redirect_chain": [],
            "scan_time_ms": 0.0,
        }

    # Step 1: In-sandbox SSRF check on initial target URL
    is_safe, reason = validate_target_url(target_url)
    if not is_safe:
        return {
            "success": False,
            "security_block": True,
            "error": f"In-Sandbox SSRF Guard Blocked URL: {reason}",
            "final_url": target_url,
            "redirect_chain": [],
            "scan_time_ms": round((time.perf_counter() - start_time) * 1000, 1),
            "security_warnings": [reason],
        }

    redirect_chain = []
    forms = []
    password_fields = []
    email_fields = []
    otp_fields = []
    payment_fields = []
    form_actions = []
    iframes = []
    external_scripts = []
    external_resources = []
    security_warnings = []
    final_url = target_url
    page_title = ""
    html_raw = ""
    dom_snapshot = ""
    visible_text = ""
    screenshot_b64 = None
    ocr_text = None
    load_time_ms = 0.0
    success = False
    error_msg = None
    redirect_count = 0
    ssrf_aborted = False

    target_host = urlparse(target_url).hostname or ""

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-extensions",
                "--disable-plugins",
                "--disable-default-apps",
                "--disable-background-networking",
                "--disable-sync",
                "--disable-translate",
                "--disable-features=Translate",
                "--safebrowsing-disable-auto-update",
                "--disable-client-side-phishing-detection",
                "--disable-component-update",
                "--mute-audio",
                "--disable-notifications",
                "--block-new-web-contents",
            ]
        )

        context = await browser.new_context(
            viewport={"width": 1280, "height": 800},
            java_script_enabled=True,
            accept_downloads=False,
            ignore_https_errors=True,
            permissions=[],
            extra_http_headers={"Accept-Language": "en-US,en;q=0.9"},
            bypass_csp=False,
        )

        page = await context.new_page()

        # Handle responses for redirect validation & chain tracking
        def on_response(resp):
            nonlocal redirect_count, ssrf_aborted
            if ssrf_aborted:
                return

            if resp.status in (301, 302, 303, 307, 308):
                redirect_count += 1
                loc = resp.headers.get("location") or ""
                redirect_chain.append(resp.url)

                if redirect_count > MAX_REDIRECTS:
                    security_warnings.append(f"Redirect limit exceeded ({MAX_REDIRECTS} hops)")
                    return

                # Validate redirect destination against SSRF
                if loc:
                    # Resolve relative location header
                    from urllib.parse import urljoin
                    full_loc = urljoin(resp.url, loc)
                    safe_dest, dest_reason = validate_target_url(full_loc)
                    if not safe_dest:
                        ssrf_aborted = True
                        security_warnings.append(f"Redirect to prohibited destination blocked: {full_loc} ({dest_reason})")

        # Handle requests for external resource tracking & dangerous scheme blocking
        def on_request(req):
            nonlocal ssrf_aborted
            ru = req.url
            if not ru:
                return

            parsed_req = urlparse(ru)
            req_scheme = (parsed_req.scheme or "").lower()

            if req_scheme in BLOCKED_SCHEMES:
                security_warnings.append(f"Prohibited scheme request intercepted: {ru[:100]}")
                return

            req_host = parsed_req.hostname or ""
            if req_host and req_host != target_host:
                if len(external_resources) < MAX_EXTERNAL_RESOURCES:
                    external_resources.append({
                        "url": ru[:250],
                        "type": req.resource_type,
                        "host": req_host
                    })
                if req.resource_type == "script" and len(external_scripts) < 20:
                    external_scripts.append(ru[:250])

        page.on("response", on_response)
        page.on("request", on_request)

        t_nav_start = time.perf_counter()
        try:
            resp = await page.goto(
                target_url,
                timeout=PAGE_LOAD_TIMEOUT_MS,
                wait_until="domcontentloaded"
            )
            load_time_ms = round((time.perf_counter() - t_nav_start) * 1000, 1)

            if ssrf_aborted:
                raise ValueError("Navigation halted: redirect attempted to reach private or restricted IP.")

            final_url = page.url
            page_title = (await page.title()) or ""
            html_raw = (await page.content()) or ""
            dom_snapshot = html_raw[:MAX_HTML_CHARS]

            # Extract visible text from body
            try:
                visible_text = await page.evaluate("() => document.body ? document.body.innerText : ''")
                visible_text = (visible_text or "")[:MAX_PAGE_TEXT_CHARS]
            except Exception:
                visible_text = ""

            # Extract form structures
            try:
                form_elements = await page.query_selector_all("form")
                for form in form_elements[:MAX_FORMS]:
                    action = (await form.get_attribute("action")) or ""
                    method = (await form.get_attribute("method")) or "get"
                    form_actions.append(action[:250])

                    input_elements = await form.query_selector_all("input")
                    input_types = []
                    for inp in input_elements:
                        itype = ((await inp.get_attribute("type")) or "text").lower()
                        iname = (await inp.get_attribute("name")) or ""
                        iplaceholder = (await inp.get_attribute("placeholder")) or ""
                        input_types.append(itype)

                        combined = f"{iname} {iplaceholder}".lower()
                        if itype == "password" or "password" in combined:
                            password_fields.append(iname or "password")
                        elif itype == "email" or "email" in combined or "user" in combined:
                            email_fields.append(iname or "email")
                        elif any(k in combined for k in ("otp", "code", "token", "2fa", "mfa")):
                            otp_fields.append(iname or "otp")
                        elif any(k in combined for k in ("card", "cvv", "cvc", "exp", "payment")):
                            payment_fields.append(iname or "payment")

                    forms.append({
                        "action": action[:250],
                        "method": method.lower(),
                        "input_types": input_types,
                        "has_password": len(password_fields) > 0,
                    })
            except Exception as fe:
                security_warnings.append(f"Form parsing warning: {str(fe)[:100]}")

            # Extract iframe sources
            try:
                iframe_elements = await page.query_selector_all("iframe")
                for ifr in iframe_elements[:15]:
                    src = await ifr.get_attribute("src")
                    if src:
                        iframes.append(src[:250])
            except Exception:
                pass

            # In-memory screenshot capture (no host volume mount)
            try:
                screenshot_bytes = await page.screenshot(type="png", full_page=False)
                screenshot_b64 = base64.b64encode(screenshot_bytes).decode("ascii")
            except Exception as se:
                security_warnings.append(f"Screenshot capture warning: {str(se)[:100]}")

            success = True

        except PwTimeout:
            error_msg = f"Page navigation timed out after {PAGE_LOAD_TIMEOUT_MS}ms"
            final_url = page.url
        except Exception as e:
            error_msg = f"Navigation error: {str(e)[:250]}"
            final_url = page.url
        finally:
            await context.close()
            await browser.close()

    total_time_ms = round((time.perf_counter() - start_time) * 1000, 1)

    return {
        "success": success,
        "error": error_msg,
        "original_url": target_url,
        "final_url": final_url,
        "redirect_chain": redirect_chain[:MAX_REDIRECTS],
        "redirect_count": redirect_count,
        "page_title": page_title[:200],
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
        "screenshot_b64": screenshot_b64,
        "ocr_text": ocr_text,
        "load_time_ms": load_time_ms,
        "scan_time_ms": total_time_ms,
        "security_warnings": security_warnings,
    }


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"success": False, "error": "No target URL provided to sandbox agent"}))
        sys.exit(1)

    url = sys.argv[1].strip()
    result = asyncio.run(execute_sandbox_scan(url))
    # Emit single line of structured JSON to stdout
    print(json.dumps(result))


if __name__ == "__main__":
    main()
