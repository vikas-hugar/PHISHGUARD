"""
PhishGuard AI — Safe Web View & Reachability State Machine Test Suite
=====================================================================
Validates all required scenarios A through P:
  Scenario A: HTTP 200 static website -> FULL PAGE RENDER
  Scenario B: HTTP 200 JavaScript website -> JAVASCRIPT RENDERED
  Scenario C: HTTP 301/302 website -> REDIRECT FOLLOWED SAFELY
  Scenario D: HTTP 404 (e.g. https://b.paytm.me/ipaytm/ba_hp) -> SERVER REACHABLE + AUTHENTIC 404 RESPONSE
  Scenario E: HTTP 403 -> SERVER REACHABLE + 403 RESPONSE
  Scenario F: HTTP 500 -> SERVER REACHABLE + 500 RESPONSE
  Scenario G: DNS failure -> NETWORK FAILURE
  Scenario H: Connection timeout -> NETWORK FAILURE
  Scenario I: TLS failure -> TLS FAILURE
  Scenario J: Modern SPA -> APPLICATION RENDERED
  Scenario K: Website with failed analytics -> PAGE STILL LOADS
  Scenario L: Website with failed font -> PAGE STILL LOADS
  Scenario M: Website with CDN resources -> SAFE RESOURCES LOAD
  Scenario N: Redirect to private IP -> SSRF BLOCKED
  Scenario O: localhost -> SSRF BLOCKED
  Scenario P: Private IP -> SSRF BLOCKED
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Add backend directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.reachability import (
    validate_url,
    validate_ssrf,
    check_url_reachability,
    check_reachability,
)
from safe_view.sanitizer import html_sanitizer
from safe_view.safe_view_engine import safe_view_engine
from safe_view.routes import _build_page_payload


class TestSafeViewRenderingScenarios(unittest.TestCase):
    """Scenario verification suite for reachability state machine and Safe Web View rendering."""

    # =========================================================================
    # SCENARIO A: HTTP 200 Static Website
    # =========================================================================
    def test_scenario_a_http_200_static_website(self):
        """HTTP 200 static website renders DOM with assets resolved and scripts neutralized."""
        html_input = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Static Test</title>
            <link rel="stylesheet" href="/css/style.css">
        </head>
        <body>
            <h1>Welcome to Static Site</h1>
            <img src="/images/logo.png" alt="Logo">
        </body>
        </html>
        """
        clean_html, elements, inventory = html_sanitizer.sanitize(
            html_content=html_input,
            base_url="https://example.com/sub/index.html",
            http_status=200,
        )
        self.assertIn("https://example.com/css/style.css", clean_html)
        self.assertIn("https://example.com/images/logo.png", clean_html)
        self.assertIn("Welcome to Static Site", clean_html)
        self.assertIn("pg-safe-viewer-styles", clean_html)

    # =========================================================================
    # SCENARIO B: HTTP 200 JavaScript Website
    # =========================================================================
    def test_scenario_b_http_200_javascript_website(self):
        """HTTP 200 JavaScript website strips active scripts but preserves rendered DOM."""
        html_input = """
        <html>
        <head><title>JS App</title></head>
        <body>
            <div id="app"><h2>Rendered by React</h2></div>
            <script>alert('malicious')</script>
            <button onclick="steal()">Click</button>
        </body>
        </html>
        """
        clean_html, elements, inventory = html_sanitizer.sanitize(
            html_content=html_input,
            base_url="https://example.com/",
            http_status=200,
        )
        self.assertIn("Rendered by React", clean_html)
        self.assertNotIn("<script>", clean_html)
        self.assertNotIn("alert('malicious')", clean_html)
        self.assertNotIn("onclick", clean_html)

    # =========================================================================
    # SCENARIO C: HTTP 301/302 Redirect Followed Safely
    # =========================================================================
    def test_scenario_c_http_301_302_redirect_followed_safely(self):
        """Public-to-public redirect is safe and followed to destination with REACHABLE status."""
        reach = check_url_reachability("https://httpbin.org/status/302")
        self.assertTrue(reach["reachable"])
        self.assertIn(reach["reachability_state"], ("REACHABLE_HTTP_2XX", "REACHABLE_HTTP_3XX"))
        self.assertGreater(reach["redirect_count"], 0)

    # =========================================================================
    # SCENARIO D: HTTP 404 Server Reachable + Authentic 404 Response
    # =========================================================================
    def test_scenario_d_http_404_authentic_response(self):
        """
        Paytm deep link (https://b.paytm.me/ipaytm/ba_hp) returns HTTP 404 with [ERR_008].
        Must be classified as REACHABLE: True, REACHABLE_HTTP_4XX, and NOT a network failure.
        """
        # Test reachability check directly
        reach = check_url_reachability("https://b.paytm.me/ipaytm/ba_hp")
        self.assertTrue(reach["reachable"], "HTTP 404 MUST be classified as reachable!")
        self.assertEqual(reach["reachability_state"], "REACHABLE_HTTP_4XX")
        self.assertEqual(reach["http_status"], 404)

        # Test sanitizer renders authentic server response directly
        paytm_html = "<html><head></head><body>[ERR_008] Url not found</body></html>"
        clean_html, elements, inventory = html_sanitizer.sanitize(
            html_content=paytm_html,
            base_url="https://b.paytm.me/ipaytm/ba_hp",
            http_status=404,
        )
        self.assertNotIn("pg-server-error-container", clean_html)
        self.assertIn("[ERR_008] Url not found", clean_html)
        self.assertNotIn("Website failed to load", clean_html)

    # =========================================================================
    # SCENARIO E: HTTP 403 Server Reachable + 403 Response
    # =========================================================================
    def test_scenario_e_http_403_server_response(self):
        """HTTP 403 is classified as REACHABLE_HTTP_4XX with authentic response payload."""
        reach = check_url_reachability("https://httpbin.org/status/403")
        self.assertTrue(reach["reachable"])
        self.assertEqual(reach["reachability_state"], "REACHABLE_HTTP_4XX")
        self.assertEqual(reach["http_status"], 403)

        clean_html, _, _ = html_sanitizer.sanitize(
            html_content="<html><body>403 Forbidden - Access Denied</body></html>",
            base_url="https://httpbin.org/status/403",
            http_status=403,
        )
        self.assertNotIn("pg-server-error-container", clean_html)
        self.assertIn("403 Forbidden - Access Denied", clean_html)

    # =========================================================================
    # SCENARIO F: HTTP 500 Server Reachable + 500 Response
    # =========================================================================
    def test_scenario_f_http_500_server_response(self):
        """HTTP 500 is classified as REACHABLE_HTTP_5XX (Server Error, not network failure)."""
        reach = check_url_reachability("https://httpbin.org/status/500")
        self.assertTrue(reach["reachable"], "HTTP 500 is a valid server response!")
        self.assertEqual(reach["reachability_state"], "REACHABLE_HTTP_5XX")
        self.assertEqual(reach["http_status"], 500)

        clean_html, _, _ = html_sanitizer.sanitize(
            html_content="<html><body>500 Internal Server Error</body></html>",
            base_url="https://httpbin.org/status/500",
            http_status=500,
        )
        self.assertNotIn("pg-server-error-container", clean_html)
        self.assertIn("500 Internal Server Error", clean_html)

    # =========================================================================
    # SCENARIO G: DNS Failure
    # =========================================================================
    def test_scenario_g_dns_failure(self):
        """Non-existent domain triggers genuine network failure with DNS_FAILED state."""
        reach = check_url_reachability("http://this-domain-definitely-does-not-exist-phishguard-test.com")
        self.assertFalse(reach["reachable"])
        self.assertEqual(reach["reachability_state"], "DNS_FAILED")
        self.assertEqual(reach["status"], "DNS_FAILED")

    # =========================================================================
    # SCENARIO H: Connection Timeout
    # =========================================================================
    @patch("requests.Session.get")
    def test_scenario_h_connection_timeout(self, mock_get):
        """Connection timeout triggers TIMEOUT reachability state."""
        import requests
        mock_get.side_effect = requests.exceptions.ConnectTimeout("Connection timed out (connect timeout=1.5)")
        reach = check_url_reachability("https://example.com/slow-timeout-test")
        self.assertFalse(reach["reachable"])
        self.assertEqual(reach["reachability_state"], "TIMEOUT")

    # =========================================================================
    # SCENARIO I: TLS Failure
    # =========================================================================
    def test_scenario_i_tls_failure(self):
        """TLS handshake failure (e.g. invalid cipher/null) correctly triggers TLS_FAILED."""
        reach = check_url_reachability("https://null.badssl.com/")
        self.assertFalse(reach["reachable"])
        self.assertEqual(reach["reachability_state"], "TLS_FAILED")

    # =========================================================================
    # SCENARIO J: Modern SPA
    # =========================================================================
    def test_scenario_j_modern_spa(self):
        """Modern SPA client markup is preserved and formatted cleanly."""
        spa_html = """
        <html>
        <head><title>SPA</title></head>
        <body>
            <div id="root">
                <nav><a href="/dashboard">Dashboard</a></nav>
                <main><h1>User Dashboard</h1><p>Active content loaded</p></main>
            </div>
        </body>
        </html>
        """
        clean_html, elements, inventory = html_sanitizer.sanitize(
            html_content=spa_html,
            base_url="https://app.example.com/",
            http_status=200,
        )
        self.assertIn("User Dashboard", clean_html)
        self.assertIn("Active content loaded", clean_html)
        # Should NOT inject the minimal empty SPA banner element
        self.assertNotIn('<div class="pg-spa-notice">', clean_html)

    # =========================================================================
    # SCENARIO K: Website with Failed Analytics (Page Still Loads)
    # =========================================================================
    def test_scenario_k_website_with_failed_analytics(self):
        """Failed analytics script does NOT mark page as failed; page remains AVAILABLE with partial flag."""
        page_dict = {
            "page_id": "p_root",
            "url": "https://example.com",
            "http_status": 200,
            "dom_snapshot": "<html><body><h1>Hello World</h1></body></html>",
            "page_available": True,
            "failed_resources": [
                {"url": "https://www.google-analytics.com/analytics.js", "error": "ERR_NAME_NOT_RESOLVED"}
            ],
        }
        payload = _build_page_payload(page_dict, "p_root", "sess_1")
        self.assertEqual(payload["scan_status"], "AVAILABLE")
        self.assertTrue(payload["page_available"])
        self.assertEqual(len(payload["failed_resources"]), 1)
        self.assertIn("Hello World", payload["safe_html"])

    # =========================================================================
    # SCENARIO L: Website with Failed Font (Page Still Loads)
    # =========================================================================
    def test_scenario_l_website_with_failed_font(self):
        """Failed optional font does NOT fail page."""
        page_dict = {
            "page_id": "p_root",
            "url": "https://example.com",
            "http_status": 200,
            "dom_snapshot": "<html><body><p>Content with standard fallback font</p></body></html>",
            "page_available": True,
            "failed_resources": [
                {"url": "https://fonts.gstatic.com/s/inter/v12/font.woff2", "error": "ERR_CONNECTION_RESET"}
            ],
        }
        payload = _build_page_payload(page_dict, "p_root", "sess_1")
        self.assertEqual(payload["scan_status"], "AVAILABLE")
        self.assertTrue(payload["page_available"])

    # =========================================================================
    # SCENARIO M: Website with CDN Resources (Safe Resources Load)
    # =========================================================================
    def test_scenario_m_website_with_cdn_resources(self):
        """Safe public CDN resources and srcset are properly rewritten to absolute URLs."""
        html_input = """
        <html>
        <head>
            <link rel="stylesheet" href="//cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css">
        </head>
        <body>
            <img src="/img/hero.jpg" srcset="/img/hero-1x.jpg 1x, /img/hero-2x.jpg 2x" alt="Hero">
            <style>
                .banner { background-image: url('/img/bg.png'); }
            </style>
        </body>
        </html>
        """
        clean_html, _, _ = html_sanitizer.sanitize(
            html_content=html_input,
            base_url="https://example.com/",
            http_status=200,
        )
        self.assertIn("https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css", clean_html)
        self.assertIn("https://example.com/img/hero-1x.jpg 1x", clean_html)
        self.assertIn("https://example.com/img/hero-2x.jpg 2x", clean_html)
        self.assertIn('url("https://example.com/img/bg.png")', clean_html)

    # =========================================================================
    # SCENARIO N: Redirect to Private IP (SSRF Blocked)
    # =========================================================================
    def test_scenario_n_redirect_to_private_ip(self):
        """Redirect destination targeting private IP is caught and blocked by SSRF guard."""
        # Direct check
        ssrf = validate_ssrf("http://192.168.1.50/admin")
        self.assertFalse(ssrf["safe"])
        self.assertIn("Private/reserved IP", ssrf["reason"])

        # Check in reachability engine
        reach = check_url_reachability("http://192.168.1.50/admin")
        self.assertFalse(reach["reachable"])
        self.assertTrue(reach["ssrf_blocked"])
        self.assertEqual(reach["reachability_state"], "SSRF_BLOCKED")

    # =========================================================================
    # SCENARIO O: localhost (SSRF Blocked)
    # =========================================================================
    def test_scenario_o_localhost_blocked(self):
        """Localhost is blocked by SSRF guard."""
        ssrf = validate_ssrf("http://localhost:8080/secret")
        self.assertFalse(ssrf["safe"])

        reach = check_url_reachability("http://localhost:8080/secret")
        self.assertFalse(reach["reachable"])
        self.assertTrue(reach["ssrf_blocked"])
        self.assertEqual(reach["reachability_state"], "SSRF_BLOCKED")

    # =========================================================================
    # SCENARIO P: Private IP (SSRF Blocked)
    # =========================================================================
    def test_scenario_p_private_ip_blocked(self):
        """Private IPv4 and loopback addresses are blocked by SSRF guard."""
        for test_ip in ("http://127.0.0.1/", "http://10.0.0.1/", "http://172.16.0.1/", "http://169.254.169.254/"):
            ssrf = validate_ssrf(test_ip)
            self.assertFalse(ssrf["safe"], f"SSRF must block {test_ip}")
            reach = check_url_reachability(test_ip)
            self.assertFalse(reach["reachable"])
            self.assertTrue(reach["ssrf_blocked"])
            self.assertEqual(reach["reachability_state"], "SSRF_BLOCKED")

    # =========================================================================
    # SCENARIO Q: Scroll-Reveal, Preloaders, Noscript Styles, Lazy Images & Async CSS
    # =========================================================================
    def test_scenario_q_scroll_reveal_and_preloader_visibility(self):
        """Scroll-reveal classes (e.g. .reveal, custom .hero-fade) and preloaders do not blank out the page."""
        html_input = """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                .hero-fade { opacity: 0; transform: translateY(40px); }
                .hero-fade.is-visible { opacity: 1; transform: translateY(0); }
                .modal-overlay { opacity: 0; }
                .modal-overlay.show { opacity: 1; }
            </style>
        </head>
        <body>
            <div id="preloader">Loading...</div>
            <header class="reveal"><h1>KSRTC Portal</h1></header>
            <section class="hero-fade"><p>Main content</p></section>
        </body>
        </html>
        """
        clean_html, _, _ = html_sanitizer.sanitize(html_input, "https://www.ksrtc.in/", http_status=200)
        self.assertIn("data-pg-sanitizer-v=\"2\"", clean_html)
        self.assertIn("pg-reveal-overrides", clean_html)
        self.assertIn(".hero-fade", clean_html)
        self.assertNotIn(".modal-overlay", clean_html.split("pg-reveal-overrides")[1])
        self.assertIn("#preloader", clean_html)
        self.assertIn(".reveal", clean_html)

    def test_scenario_r_noscript_styles_and_empty_body_fallback(self):
        """Unwraps <noscript><style> rules and empty-body <noscript> messages without leaving <noscript> tags."""
        bbc_style_html = """
        <html><body>
            <img src="/placeholder.png" class="hide-when-no-script">
            <img src="/real-news.jpg">
            <noscript><style>.hide-when-no-script { visibility: hidden; }</style></noscript>
            <p>Breaking news article headline with sufficient text content.</p>
        </body></html>
        """
        clean_bbc, _, _ = html_sanitizer.sanitize(bbc_style_html, "https://www.bbc.com/", http_status=200)
        self.assertNotIn("<noscript", clean_bbc.lower())
        self.assertIn(".hide-when-no-script { visibility: hidden; }", clean_bbc)

        cf_html = """
        <html><body>
            <div class="main-wrapper"><div class="main-content"></div></div>
            <noscript>Enable JavaScript and cookies to continue</noscript>
        </body></html>
        """
        clean_cf, _, _ = html_sanitizer.sanitize(cf_html, "https://stackoverflow.com/", http_status=403)
        self.assertNotIn("<noscript", clean_cf.lower())
        self.assertIn("Enable JavaScript and cookies to continue", clean_cf)

    def test_scenario_s_lazy_images_comments_and_svg_fragments(self):
        """Promotes lazy data-src images, skips commented <link>, and preserves SVG #fragment urls."""
        html_input = """
        <html>
        <head>
            <!-- <link rel="stylesheet" href="https://dead.example.invalid/old.css"> -->
        </head>
        <body>
            <img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" data-src="/img/bus.jpg" data-srcset="/img/bus-2x.jpg 2x">
            <svg><path style="fill: url(#myGrad)"></path></svg>
        </body>
        </html>
        """
        clean_html, _, _ = html_sanitizer.sanitize(html_input, "https://example.com/", http_status=200)
        self.assertNotIn("dead.example.invalid", clean_html)
        self.assertIn('src="https://example.com/img/bus.jpg"', clean_html)
        self.assertIn('srcset="https://example.com/img/bus-2x.jpg 2x"', clean_html)
        self.assertIn("url(#myGrad)", clean_html)

    def test_scenario_t_stale_cached_page_resanitizes_to_v2(self):
        """Cached page representations missing v2 sanitizer marker automatically re-sanitize from dom_snapshot."""
        stale_page = {
            "page_id": "p_root",
            "url": "https://example.com/",
            "http_status": 200,
            "dom_snapshot": "<html><body><section class='reveal'>Visible Now</section></body></html>",
            "safe_html": "<html><head><style id='pg-safe-viewer-styles'></style></head><body><section class='reveal'>Old</section></body></html>",
        }
        payload = _build_page_payload(stale_page, "p_root", "sess_v2")
        self.assertIn('data-pg-sanitizer-v="2"', payload["safe_html"])
        self.assertIn("Visible Now", payload["safe_html"])

    def test_scenario_u_spa_noscript_boilerplate_replaced_with_spa_notice(self):
        """Unhydrated CRA/Vue/Vite SPAs replace raw 'enable JavaScript' boilerplate with clean SPA notice."""
        cra_html = """<!doctype html>
        <html lang="en">
        <head><title>KSRTC Awatar 4.0</title><style>body{margin:0;color:#111;}</style></head>
        <body>
            <noscript>You need to enable JavaScript to run this app.</noscript>
            <div id="root" class="rootLayout"></div>
        </body>
        </html>"""
        clean_cra, _, inv_cra = html_sanitizer.sanitize(cra_html, "https://awatar4.ksrtc.in/", http_status=200)
        self.assertNotIn("<noscript", clean_cra.lower())
        self.assertNotIn("You need to enable JavaScript to run this app.", clean_cra)
        self.assertIn('<div class="pg-spa-notice">', clean_cra)
        self.assertIn("KSRTC Awatar 4.0", clean_cra)
        self.assertEqual(inv_cra["text_characters"], 0)

        vue_html = """<html><head><title>Vue Portal</title></head><body>
            <noscript>We're sorry but app doesn't work properly without JavaScript enabled. Please enable it to continue.</noscript>
            <div id="app"></div>
        </body></html>"""
        clean_vue, _, inv_vue = html_sanitizer.sanitize(vue_html, "https://vue.example.com/", http_status=200)
        self.assertNotIn("doesn't work properly without JavaScript", clean_vue)
        self.assertIn('<div class="pg-spa-notice">', clean_vue)
        self.assertEqual(inv_vue["text_characters"], 0)

        stale_spa_page = {
            "page_id": "p_1",
            "url": "https://awatar4.ksrtc.in/",
            "http_status": 200,
            "dom_snapshot": cra_html,
            "safe_html": '<html><head><style id="pg-safe-viewer-styles" data-pg-sanitizer-v="2"></style></head><body><div id="pg-safe-banner"><div>PHISHGUARD</div><div>TARGET</div></div>You need to enable JavaScript to run this app.<div id="root"></div></body></html>',
            "content_inventory": {"text_characters": 63, "forms": 0, "links": 0},
        }
        upgraded = _build_page_payload(stale_spa_page, "p_1", "sess_spa")
        self.assertIn('<div class="pg-spa-notice">', upgraded["safe_html"])
        self.assertNotIn("You need to enable JavaScript to run this app.", upgraded["safe_html"])
        self.assertEqual(upgraded["content_inventory"]["text_characters"], 0)

    def test_scenario_v_vm_browser_no_forbidden_fetch_headers(self):
        """VM Playwright context must not inject Sec-Fetch-*/Sec-Ch-Ua-*/Upgrade-Insecure-Requests headers that break subresources."""
        import asyncio
        from unittest.mock import AsyncMock, MagicMock
        agent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "analysis_agent"))
        if agent_dir not in sys.path:
            sys.path.insert(0, agent_dir)
        from browser import make_browser_and_context

        captured_kwargs = {}
        mock_context = AsyncMock()
        async def _fake_new_context(**kwargs):
            captured_kwargs.update(kwargs)
            return mock_context
        mock_browser = MagicMock()
        mock_browser.new_context = _fake_new_context
        mock_pw = MagicMock()
        mock_pw.chromium.launch = AsyncMock(return_value=mock_browser)

        asyncio.run(make_browser_and_context(mock_pw, device_profile="desktop"))
        extra_headers = {k.lower(): v for k, v in (captured_kwargs.get("extra_http_headers") or {}).items()}
        for forbidden in ("sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user", "upgrade-insecure-requests", "sec-ch-ua"):
            self.assertNotIn(forbidden, extra_headers)

    def test_scenario_w_read_only_form_and_link_sanitization(self):
        """Sanitizer locks write controls, preserves clickable links/hashes, marks downloads and unsupported schemes."""
        html_input = """
        <!DOCTYPE html>
        <html>
        <body>
            <form action="/login" method="POST">
                <input type="text" name="email">
                <textarea name="notes">hello</textarea>
                <select name="role"><option value="user">User</option></select>
                <button type="submit">Submit</button>
            </form>
            <a href="/about"><button>About Us</button></a>
            <a href="#pricing">Pricing Section</a>
            <a href="/files/guide.pdf" download>Download PDF</a>
            <a href="mailto:help@example.com">Email Support</a>
        </body>
        </html>
        """
        safe_html, _, _ = html_sanitizer.sanitize(html_input, "https://example.com/")

        self.assertIn('action="javascript:void(0)"', safe_html)
        self.assertIn('onsubmit="return false;"', safe_html)
        self.assertNotIn('action="/login"', safe_html)
        self.assertIn("<textarea", safe_html)
        self.assertIn("<select", safe_html)
        self.assertRegex(safe_html, r'<textarea[^>]*readonly="true"[^>]*disabled="true"')
        self.assertRegex(safe_html, r'<select[^>]*readonly="true"[^>]*disabled="true"')
        self.assertIn('data-pg-href="https://example.com/about"', safe_html)
        self.assertIn('data-pg-hash="#pricing"', safe_html)
        self.assertIn('data-pg-download="true"', safe_html)
        self.assertNotRegex(safe_html, r'\sdownload(?:=|[\s>])')
        self.assertIn('data-pg-blocked-scheme="mailto"', safe_html)
        self.assertIn("a[data-pg-href]", safe_html)
        self.assertIn("pointer-events: none !important;", safe_html)

    def test_scenario_x_resanitize_upgrades_legacy_cursor_default(self):
        """Cached HTML with legacy non-navigating */ cursor:default CSS upgrades cleanly from html_raw."""
        stale_page = {
            "page_id": "p_root",
            "url": "https://example.com/",
            "scan_status": "AVAILABLE",
            "page_available": True,
            "safe_html": (
                "<!DOCTYPE html><html data-pg-sanitizer-v=\"2\"><head>"
                "<style>a { cursor: default !important; /* non-navigating */ }</style>"
                "</head><body><a data-pg-href=\"https://example.com/pricing\">Pricing</a></body></html>"
            ),
            "html_raw": (
                "<!DOCTYPE html><html><body>"
                "<a href=\"/pricing\">Pricing</a>"
                "<textarea name=\"msg\">test</textarea>"
                "</body></html>"
            ),
            "dom_diff": {"added": 1},
            "network_forensics": {"total_requests": 2},
            "timeline": [{"event": "DOMContentLoaded"}],
        }
        upgraded = _build_page_payload(stale_page, "p_root", "sess_legacy_cursor")
        self.assertNotIn("non-navigating */", upgraded["safe_html"])
        self.assertIn("cursor: pointer !important;", upgraded["safe_html"])
        self.assertRegex(upgraded["safe_html"], r'<textarea[^>]*disabled="true"')
        self.assertEqual(upgraded["dom_diff"], {"added": 1})
        self.assertEqual(upgraded["network_forensics"], {"total_requests": 2})
        self.assertEqual(upgraded["timeline"], [{"event": "DOMContentLoaded"}])

    def test_scenario_y_navigate_endpoint_and_write_blocking(self):
        """POST /safe-view/session/<sid>/navigate serves cached/on-demand read pages and blocks writes with 403."""
        from flask import Flask
        from safe_view.routes import safe_view_bp
        from safe_view.session_manager import session_manager

        engine_mod = sys.modules["safe_view.safe_view_engine"]

        app = Flask(__name__)
        app.register_blueprint(safe_view_bp)
        client = app.test_client()

        session = session_manager.create_session("https://example.com/")
        session.add_page("p_root", {
            "page_id": "p_root",
            "url": "https://example.com/",
            "title": "Home",
            "http_status": 200,
            "scan_status": "AVAILABLE",
            "page_available": True,
            "safe_html": "<!DOCTYPE html><html><body><a data-pg-href='https://example.com/about'>About</a></body></html>",
        })
        session.add_page("p_about", {
            "page_id": "p_about",
            "url": "https://example.com/about",
            "title": "About Us",
            "http_status": 200,
            "scan_status": "AVAILABLE",
            "page_available": True,
            "safe_html": "<!DOCTYPE html><html><body><h1>About Us</h1></body></html>",
            "network_forensics": {"total_requests": 1},
            "timeline": [{"event": "Load"}],
        })

        with patch.object(engine_mod, "validate_url_safe", return_value={"safe": True}):
            # 1. Cached page navigation returns 200 immediately with cached=True and forensic data
            resp_cached = client.post(
                f"/safe-view/session/{session.session_id}/navigate",
                json={"url": "https://example.com/about"},
            )
            self.assertEqual(resp_cached.status_code, 200)
            body_cached = resp_cached.get_json()
            self.assertTrue(body_cached["success"])
            self.assertTrue(body_cached["cached"])
            self.assertEqual(body_cached["page_id"], "p_about")
            self.assertEqual(body_cached["page"]["network_forensics"], {"total_requests": 1})

            # 2. Write / destructive / download URLs are strictly blocked with 403 READ_ONLY_WRITE_BLOCKED
            for blocked_target in (
                "https://example.com/account/logout",
                "https://example.com/checkout",
                "https://example.com/search?method=post",
                "https://example.com/downloads/installer.exe",
            ):
                resp_blocked = client.post(
                    f"/safe-view/session/{session.session_id}/navigate",
                    json={"url": blocked_target},
                )
                self.assertEqual(resp_blocked.status_code, 403, f"Expected 403 for {blocked_target}")
                body_blocked = resp_blocked.get_json()
                self.assertFalse(body_blocked["success"])
                self.assertTrue(body_blocked["write_blocked"])
                self.assertEqual(body_blocked["error_code"], "READ_ONLY_WRITE_BLOCKED")

            # 3. Uncached read-only page triggers fast_mode scan and returns 200
            def _fake_scan(**kwargs):
                return {
                    "page_id": kwargs["page_id"],
                    "url": kwargs["url"],
                    "title": "Pricing",
                    "http_status": 200,
                    "scan_status": "AVAILABLE",
                    "page_available": True,
                    "safe_html": "<!DOCTYPE html><html><body><h1>Pricing Page</h1></body></html>",
                    "content_inventory": {"text_characters": 12, "forms": 0, "links": 0},
                }

            with patch.object(safe_view_engine, "recover_html_via_http", return_value=None), patch.object(
                safe_view_engine, "_scan_and_process_page", side_effect=_fake_scan
            ) as mock_scan:
                resp_live = client.post(
                    f"/safe-view/session/{session.session_id}/navigate",
                    json={"url": "https://example.com/pricing", "device_profile": "desktop"},
                )
                self.assertEqual(resp_live.status_code, 200)
                body_live = resp_live.get_json()
                self.assertTrue(body_live["success"])
                self.assertFalse(body_live["cached"])
                self.assertIn("Pricing Page", body_live["page"]["safe_html"])
                self.assertTrue(mock_scan.call_args.kwargs.get("fast_mode"))

            # 4. Subsequent navigation to that same URL hits session cache (no extra scan)
            with patch.object(safe_view_engine, "_scan_and_process_page") as mock_scan_again:
                resp_repeat = client.post(
                    f"/safe-view/session/{session.session_id}/navigate",
                    json={"url": "https://example.com/pricing/"},
                )
                self.assertEqual(resp_repeat.status_code, 200)
                self.assertTrue(resp_repeat.get_json()["cached"])
                mock_scan_again.assert_not_called()

        # 5. SSRF private/loopback URL is blocked with 403 BLOCKED_BY_SSRF_GUARD
        resp_ssrf = client.post(
            f"/safe-view/session/{session.session_id}/navigate",
            json={"url": "http://127.0.0.1/admin"},
        )
        self.assertEqual(resp_ssrf.status_code, 403)
        self.assertEqual(resp_ssrf.get_json()["error_code"], "BLOCKED_BY_SSRF_GUARD")

        # 6. Unknown session returns 404 SESSION_EXPIRED
        resp_missing = client.post(
            "/safe-view/session/nonexistent_sess_id/navigate",
            json={"url": "https://example.com/about"},
        )
        self.assertEqual(resp_missing.status_code, 404)
        self.assertEqual(resp_missing.get_json()["error_code"], "SESSION_EXPIRED")

    def test_scenario_z_universal_buttons_dropdowns_and_fast_http_reachability(self):
        """
        Verifies universal button/dropdown/area/unquoted-link support, token-boundary
        destructive URL checks (allowing /killers, /skills, ?orderby=date, /backdrop),
        fast HTTP SSR immediate navigation, SPA VM escalation, SSRF redirect blocking,
        and non-caching of FAILED fallback stubs.
        """
        from flask import Flask
        from safe_view.routes import safe_view_bp, _resanitize_if_needed
        from safe_view.session_manager import session_manager
        from safe_view.safe_view_engine import safe_view_engine
        from safe_view.discovery_engine import page_discovery_engine

        # 1. Sanitizer button, onclick-nav, data-to, unquoted href, area, form button, and dropdown CSS
        raw_html = """
        <html>
        <body>
            <nav>
                <button onclick="window.location='/movies'">Browse Movies</button>
                <button data-to="/about">About Button</button>
                <button type="button" aria-expanded="false">GENRES</button>
                <a href=/raw-unquoted>Unquoted</a>
                <map name="m"><area shape="rect" coords="0,0,10,10" href="/map-spot"></map>
                <form action="/login">
                    <input type="text" name="u">
                    <button>Submit Form</button>
                </form>
            </nav>
        </body>
        </html>
        """
        safe_html, elements, _ = html_sanitizer.sanitize(raw_html, "https://example.com/")
        self.assertNotIn("onclick", safe_html.lower())
        self.assertIn('data-pg-href="https://example.com/movies"', safe_html)
        self.assertIn('data-pg-href="https://example.com/about"', safe_html)
        self.assertIn('data-pg-href="https://example.com/raw-unquoted"', safe_html)
        self.assertIn('data-pg-href="https://example.com/map-spot"', safe_html)
        self.assertIn('data-pg-control="nav"', safe_html)
        self.assertIn('data-pg-control="ui"', safe_html)
        self.assertIn('data-pg-nav-v="3"', safe_html)
        self.assertIn(".pg-dropdown-open", safe_html)
        # Interactive nav/ui buttons must not be natively disabled; form submit buttons stay disabled
        self.assertNotRegex(safe_html, r'<button[^>]*data-pg-control="(?:nav|ui)"[^>]*disabled="true"')
        self.assertRegex(safe_html, r'<button[^>]*disabled="true"[^>]*>Submit Form</button>')
        self.assertEqual(sum(1 for e in elements if e.get("tag") == "AREA"), 1)

        # Auto-upgrade v2 cached HTML without data-pg-nav-v="3"
        upgraded = _resanitize_if_needed({
            "safe_html": '<html><head><style id="pg-safe-viewer-styles" data-pg-sanitizer-v="2"></style></head><body><button type="button">Menu</button></body></html>',
            "html_raw": '<html><body><button type="button">Menu</button></body></html>',
            "url": "https://example.com/",
        })
        self.assertIn('data-pg-nav-v="3"', upgraded)

        # 2. Discovery & read-only gate must allow benign words and block real destructive endpoints
        discovery = page_discovery_engine.extract_all_links(
            html_content="""
                <a href="/killers-2026/">Killers</a>
                <a href="/skills">Skills</a>
                <a href="/?orderby=date">Latest</a>
                <a href="/backdrop">Backdrop</a>
                <a href="/exhibition">Exhibition</a>
                <a href="/account/logout">Logout</a>
                <a href="/checkout">Checkout</a>
                <a href="/item?action=delete">Delete</a>
                <button onclick="location.href='/guides'">Guides</button>
            """,
            current_url="https://example.com/",
            target_origin_url="https://example.com/",
            current_depth=0,
        )
        allowed_urls = {c["url"] for c in discovery["candidates"]}
        for expected in (
            "https://example.com/killers-2026",
            "https://example.com/skills",
            "https://example.com/?orderby=date",
            "https://example.com/backdrop",
            "https://example.com/exhibition",
            "https://example.com/guides",
        ):
            self.assertIn(expected, allowed_urls, f"Benign URL was falsely blocked: {expected}")

        blocked_urls = {b["url"] for b in discovery["blocked_actions"]}
        self.assertTrue(any("/account/logout" in u for u in blocked_urls))
        self.assertTrue(any("/checkout" in u for u in blocked_urls))
        self.assertTrue(any("action=delete" in u for u in blocked_urls))

        # 3. Fast HTTP SSR immediate navigation + retry on stale FAILED fallback + SPA escalation
        engine_mod = sys.modules["safe_view.safe_view_engine"]
        app = Flask(__name__)
        app.register_blueprint(safe_view_bp)
        client = app.test_client()

        session = session_manager.create_session("https://example.com/")
        session.add_page("p_root", {
            "page_id": "p_root",
            "url": "https://example.com/",
            "title": "Home",
            "http_status": 200,
            "scan_status": "AVAILABLE",
            "page_available": True,
            "safe_html": safe_html,
            "html_raw": raw_html,
            "content_inventory": {"text_characters": 100, "forms": 1, "links": 2},
        })
        # Stale failed fallback cached previously for /killers-2026/
        session.add_discovered_candidate(
            page_id="p_killers",
            url="https://example.com/killers-2026/",
            path="/killers-2026/",
            depth=1,
            title="Killers 2026",
            is_root=False,
            parent_page_id="p_root",
        )
        session.add_page("p_killers", {
            "page_id": "p_killers",
            "url": "https://example.com/killers-2026/",
            "scan_status": "FAILED",
            "page_available": False,
            "error_type": "NAV_TIMEOUT",
            "safe_html": "<div>PAGE NAVIGATION FAILED</div>",
        })

        with patch.object(engine_mod, "validate_url_safe", return_value={"safe": True}):
            # 3a. Stale FAILED cache is NOT served as hit; fast SSR HTML serves immediately without VM scan
            with patch.object(
                safe_view_engine,
                "recover_html_via_http",
                return_value={
                    "html": "<html><head><title>Killers 2026</title></head><body><main><h1>Killers 2026 Movie Page</h1><p>Full server-rendered details with plenty of readable content to bypass SPA heuristics cleanly.</p></main></body></html>",
                    "final_url": "https://example.com/killers-2026/",
                    "http_status": 200,
                    "page_title": "Killers 2026",
                    "redirect_chain": ["https://example.com/killers-2026/"],
                },
            ), patch.object(safe_view_engine, "_scan_and_process_page") as mock_vm_scan:
                resp_ssr = client.post(
                    f"/safe-view/session/{session.session_id}/navigate",
                    json={"url": "https://example.com/killers-2026/"},
                )
                self.assertEqual(resp_ssr.status_code, 200)
                body_ssr = resp_ssr.get_json()
                self.assertTrue(body_ssr["success"])
                self.assertIn("Killers 2026 Movie Page", body_ssr["page"]["safe_html"])
                mock_vm_scan.assert_not_called()

            # 3b. SPA shell triggers automatic escalation to VM Playwright (fast_mode=True)
            def _fake_spa_vm(**kwargs):
                return {
                    "page_id": kwargs["page_id"],
                    "url": kwargs["url"],
                    "title": "SPA App Page",
                    "http_status": 200,
                    "scan_status": "AVAILABLE",
                    "page_available": True,
                    "safe_html": "<!DOCTYPE html><html><body><div id='root'>Hydrated SPA UI</div></body></html>",
                    "content_inventory": {"text_characters": 15, "forms": 0, "links": 0},
                }

            with patch.object(
                safe_view_engine,
                "recover_html_via_http",
                return_value={
                    "html": '<html><body><div id="root"></div><script src="/a.js"></script><script src="/b.js"></script></body></html>',
                    "final_url": "https://example.com/spa-app",
                    "http_status": 200,
                    "page_title": "SPA",
                    "redirect_chain": ["https://example.com/spa-app"],
                },
            ), patch.object(safe_view_engine, "_scan_and_process_page", side_effect=_fake_spa_vm) as mock_spa_vm:
                resp_spa = client.post(
                    f"/safe-view/session/{session.session_id}/navigate",
                    json={"url": "https://example.com/spa-app"},
                )
                self.assertEqual(resp_spa.status_code, 200)
                self.assertIn("Hydrated SPA UI", resp_spa.get_json()["page"]["safe_html"])
                self.assertTrue(mock_spa_vm.call_args.kwargs.get("fast_mode"))

            # 3c. SSRF redirect hop in fast HTTP is blocked with 403 BLOCKED_BY_SSRF_GUARD
            with patch.object(
                safe_view_engine,
                "recover_html_via_http",
                return_value={
                    "ssrf_redirect_blocked": True,
                    "blocked_url": "http://127.0.0.1/secret",
                    "reason": "Blocked internal loopback redirect",
                },
            ):
                resp_ssrf_redir = client.post(
                    f"/safe-view/session/{session.session_id}/navigate",
                    json={"url": "https://example.com/open-redirect"},
                )
                self.assertEqual(resp_ssrf_redir.status_code, 403)
                self.assertEqual(resp_ssrf_redir.get_json()["error_code"], "BLOCKED_BY_SSRF_GUARD")


if __name__ == "__main__":
    unittest.main()
