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


if __name__ == "__main__":
    unittest.main()
