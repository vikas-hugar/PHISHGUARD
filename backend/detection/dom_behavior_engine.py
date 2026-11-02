"""
PhishGuard AI V7.0 — Temporal HTML/DOM Behavioral Intelligence Engine
=====================================================================
Analyzes temporal mutation dynamics, DOM structural evolutions, deceptive UI
architectures, script behavioral execution patterns, and cross-domain entity
relationships to detect zero-day phishing, delayed form injections, and cloaked
credential exfiltration.

Architecture & Principles:
  1. Operates offline without external APIs.
  2. Pure Python Standard Library (html.parser, re, urllib.parse, math, time).
  3. Consumes both VM Playwright temporal observer telemetry AND fallback static DOM/HTML.
  4. Generates a standardized 24-dimensional normalized feature vector for ML hooks.
  5. Computes a calibrated Behavioral Risk Score (0.0 to 100.0) with granular XAI reasons.
  6. Accounts for enterprise whitelisting to prevent false positives on legitimate CDNs/OAuth.
"""

from __future__ import annotations

import re
import math
import time
from html.parser import HTMLParser
from urllib.parse import urlparse, urljoin
from typing import Any


# ── Suspicious Exfiltration Endpoints & Patterns ──────────────────────────────
_KNOWN_EXFILTRATION_PATTERNS = [
    re.compile(r"api\.telegram\.org/bot", re.IGNORECASE),
    re.compile(r"discord\.com/api/webhooks", re.IGNORECASE),
    re.compile(r"discordapp\.com/api/webhooks", re.IGNORECASE),
    re.compile(r"formspree\.io", re.IGNORECASE),
    re.compile(r"formsubmit\.co", re.IGNORECASE),
    re.compile(r"getform\.io", re.IGNORECASE),
    re.compile(r"webtooid\.com", re.IGNORECASE),
    re.compile(r"pastebin\.com/api", re.IGNORECASE),
    re.compile(r"ngrok-free\.app", re.IGNORECASE),
    re.compile(r"ngrok\.io", re.IGNORECASE),
    re.compile(r"loca\.lt", re.IGNORECASE),
    re.compile(r"trycloudflare\.com", re.IGNORECASE),
    re.compile(r"pipedream\.net", re.IGNORECASE),
    re.compile(r"webhook\.site", re.IGNORECASE),
    re.compile(r"requestbin\.com", re.IGNORECASE),
    re.compile(r"b-cdn\.net", re.IGNORECASE),
    re.compile(r"workers\.dev", re.IGNORECASE),
    re.compile(r"pages\.dev", re.IGNORECASE),
]

# Legitimate OAuth / SSO Identity Providers
_RECOGNIZED_AUTH_PROVIDERS = frozenset([
    "accounts.google.com",
    "login.microsoftonline.com",
    "appleid.apple.com",
    "github.com",
    "auth0.com",
    "okta.com",
    "cognito.amazonaws.com",
    "facebook.com",
    "twitter.com",
    "x.com",
])

# Legitimate Third-Party Analytics / CDNs (whitelisted from exfiltration flags)
_LEGITIMATE_THIRD_PARTIES = frozenset([
    "google-analytics.com",
    "googletagmanager.com",
    "gstatic.com",
    "googleapis.com",
    "cloudflare.com",
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "fontawesome.com",
    "recaptcha.net",
    "google.com/recaptcha",
    "hcaptcha.com",
    "stripe.com",
    "paypal.com",
])


class DOMStructuralParser(HTMLParser):
    """
    Fast streaming parser using Python's standard library html.parser.
    Extracts structural tree metadata, inputs, forms, scripts, overlays,
    iframes, and inline event listeners without third-party dependencies.
    """

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, Any]] = []
        self.current_form: dict[str, Any] | None = None
        self.inputs: list[dict[str, str]] = []
        self.scripts: list[dict[str, str]] = []
        self.iframes: list[dict[str, str]] = []
        self.inline_event_handlers: list[tuple[str, str]] = []
        self.meta_refresh: str | None = None
        self.has_fullscreen_overlay = False
        self.high_zindex_elements = 0
        self.hidden_elements = 0
        self.total_tag_count = 0
        self.tag_depth = 0
        self.max_depth = 0
        self._current_script_body: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.total_tag_count += 1
        self.tag_depth += 1
        if self.tag_depth > self.max_depth:
            self.max_depth = self.tag_depth

        attr_dict: dict[str, str] = {
            k.lower(): (v or "") for k, v in attrs
        }

        # Check inline event handlers (oncontextmenu, onkeydown, onsubmit, onerror, etc.)
        for k, v in attr_dict.items():
            if k.startswith("on"):
                self.inline_event_handlers.append((k, v))

        # Check style attributes for deceptive overlay / clickjacking patterns
        style = attr_dict.get("style", "").lower()
        if style:
            if "z-index" in style:
                z_match = re.search(r"z-index\s*:\s*(\d+)", style)
                if z_match and int(z_match.group(1)) >= 999:
                    self.high_zindex_elements += 1
                    if any(p in style for p in ("position: fixed", "position:fixed", "position: absolute", "position:absolute")):
                        if any(w in style for w in ("width: 100%", "width:100%", "inset: 0", "inset:0", "top: 0")):
                            self.has_fullscreen_overlay = True

            if any(h in style for h in ("display: none", "display:none", "visibility: hidden", "visibility:hidden", "opacity: 0", "opacity:0")):
                self.hidden_elements += 1

        if attr_dict.get("hidden") is not None or attr_dict.get("aria-hidden") == "true":
            self.hidden_elements += 1

        # Form tracking
        if tag == "form":
            self.current_form = {
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "get").lower(),
                "inputs": [],
            }
            self.forms.append(self.current_form)

        # Input tracking
        elif tag == "input":
            inp_info = {
                "type": attr_dict.get("type", "text").lower(),
                "name": attr_dict.get("name", ""),
                "id": attr_dict.get("id", ""),
                "placeholder": attr_dict.get("placeholder", ""),
                "autocomplete": attr_dict.get("autocomplete", ""),
                "hidden": "true" if (
                    attr_dict.get("type", "").lower() == "hidden" or
                    "display:none" in style or "opacity:0" in style
                ) else "false"
            }
            self.inputs.append(inp_info)
            if self.current_form is not None:
                self.current_form["inputs"].append(inp_info)

        # Script tracking
        elif tag == "script":
            self._in_script = True
            self._current_script_body = []
            src = attr_dict.get("src", "")
            script_type = attr_dict.get("type", "")
            self.scripts.append({"src": src, "type": script_type, "content": ""})

        # Iframe tracking
        elif tag == "iframe":
            self.iframes.append({
                "src": attr_dict.get("src", ""),
                "style": style,
                "hidden": "true" if any(h in style for h in ("display: none", "visibility: hidden", "opacity: 0")) else "false"
            })

        # Meta refresh
        elif tag == "meta":
            http_equiv = attr_dict.get("http-equiv", "").lower()
            if http_equiv == "refresh":
                self.meta_refresh = attr_dict.get("content", "")

    def handle_endtag(self, tag: str) -> None:
        if self.tag_depth > 0:
            self.tag_depth -= 1

        if tag == "form":
            self.current_form = None
        elif tag == "script":
            self._in_script = False
            if self.scripts and not self.scripts[-1]["src"]:
                self.scripts[-1]["content"] = "".join(self._current_script_body)
            self._current_script_body = []

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._current_script_body.append(data)


def _extract_domain(url: str) -> str:
    """Safely extract lowercase registered/hostname domain from a URL string."""
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def _is_suspicious_exfiltration_url(action_url: str, page_domain: str) -> tuple[bool, str]:
    """
    Determines if an action or resource URL represents an unauthorized exfiltration vector.
    """
    if not action_url or action_url.startswith("#") or action_url.startswith("javascript:"):
        return False, ""

    action_domain = _extract_domain(action_url)
    if not action_domain:
        return False, ""

    # Check for direct hits against known webhooks/exfiltration infrastructure
    for pat in _KNOWN_EXFILTRATION_PATTERNS:
        if pat.search(action_url):
            return True, f"Known exfiltration service pattern: {pat.pattern}"

    # Check if form targets a raw IP address
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?$", action_domain):
        return True, f"Form action targets raw IP: {action_domain}"

    # Check if target is a different domain than page domain
    if page_domain and action_domain != page_domain:
        # Check subdomains
        if action_domain.endswith("." + page_domain):
            return False, ""
        # Check recognized OAuth providers
        if any(auth in action_domain for auth in _RECOGNIZED_AUTH_PROVIDERS):
            return False, ""
        # Check legitimate CDNs/gateways
        if any(cdn in action_domain for cdn in _LEGITIMATE_THIRD_PARTIES):
            return False, ""

        return True, f"Cross-domain form submission to untrusted host: {action_domain}"

    return False, ""


def analyze_dom_behavior(
    dom_raw: str | None = None,
    raw_ds: dict[str, Any] | None = None,
    page_url: str = "",
    target_domain: str = "",
    is_whitelisted: bool = False,
) -> dict[str, Any]:
    """
    Unified entry point for the Temporal HTML/DOM Behavioral Intelligence Engine.

    Parameters:
      - dom_raw: Rendered DOM or static HTML string.
      - raw_ds: Deep scan output dictionary from vm_controller/scanner (if available).
      - page_url: Original or final URL of the inspected page.
      - target_domain: Primary registered domain being analyzed.
      - is_whitelisted: True if domain is on the trusted enterprise whitelist.

    Returns:
      Structured dictionary with behavioral metrics, temporal mutations,
      domain relationship graph, normalized 24D feature vector, risk score,
      threat level, and explainable reasons.
    """
    t0 = time.perf_counter()

    # Determine primary URL and domain
    effective_url = page_url or (raw_ds.get("final_url") if raw_ds else "") or (raw_ds.get("original_url") if raw_ds else "")
    effective_domain = target_domain or _extract_domain(effective_url)

    # Use dom_snapshot from raw_ds if dom_raw was not directly provided
    if not dom_raw and raw_ds:
        dom_raw = raw_ds.get("dom_snapshot") or raw_ds.get("html_raw") or ""

    if not dom_raw:
        # Graceful handling when no DOM content is present at all
        return _empty_dom_behavior_result(effective_domain, is_whitelisted, t0)

    # ── 1. Structural DOM Parsing ───────────────────────────────────────────
    parser = DOMStructuralParser()
    try:
        # Limit parse size to prevent resource exhaustion on pathological inputs
        parser.feed(dom_raw[:300_000])
    except Exception:
        # In case of malformed HTML, proceed with partial parse
        pass

    # ── 2. Ingest Temporal Telemetry from VM Agent (if present) ─────────────
    vm_behavior = (raw_ds.get("dom_behavior") or {}) if raw_ds else {}
    vm_mutations = vm_behavior.get("mutation_metrics", {})
    vm_events = vm_behavior.get("behavioral_events", [])
    vm_snapshots = vm_behavior.get("temporal_snapshots", {})

    temporal_available = bool(vm_snapshots or vm_mutations or vm_events)
    mutation_count = int(vm_mutations.get("total_mutations", 0))
    dynamic_nodes_added = int(vm_mutations.get("added_nodes", 0))
    dynamic_attributes_changed = int(vm_mutations.get("modified_attributes", 0))
    dynamic_password_injection = bool(vm_behavior.get("dynamic_password_injection", False))
    dynamic_form_action_changed = bool(vm_behavior.get("dynamic_form_action_changed", False))

    # ── 3. Credential & Form Exfiltration Analysis ──────────────────────────
    password_fields: list[str] = []
    email_fields: list[str] = []
    otp_fields: list[str] = []
    payment_fields: list[str] = []
    hidden_credential_fields = 0
    all_form_actions: list[str] = []
    suspicious_exfil_targets: list[str] = []
    cross_origin_actions: list[str] = []

    # Combine parser inputs with raw_ds inputs
    for inp in parser.inputs:
        itype = inp.get("type", "text")
        iname = (inp.get("name") or "").lower()
        iph = (inp.get("placeholder") or "").lower()
        combined = f"{iname} {iph}"

        is_pw = itype == "password" or "password" in combined or "passwort" in combined or "motdepasse" in combined
        is_em = itype == "email" or any(k in combined for k in ("email", "username", "user_id", "login_id", "login"))
        is_otp = any(k in combined for k in ("otp", "2fa", "mfa", "token", "verification", "authcode"))
        is_pay = any(k in combined for k in ("card", "cvv", "cvc", "cc_num", "expir", "creditcard"))

        if is_pw:
            password_fields.append(inp.get("name") or "password")
            if inp.get("hidden") == "true":
                hidden_credential_fields += 1
        if is_em:
            email_fields.append(inp.get("name") or "email")
            if inp.get("hidden") == "true":
                hidden_credential_fields += 1
        if is_otp:
            otp_fields.append(inp.get("name") or "otp")
        if is_pay:
            payment_fields.append(inp.get("name") or "payment")

    # Ingest forms from VM if parser didn't catch (e.g. shadow DOM or dynamic)
    if raw_ds:
        if raw_ds.get("password_fields"):
            password_fields.extend(raw_ds["password_fields"])
        if raw_ds.get("email_fields"):
            email_fields.extend(raw_ds["email_fields"])
        if raw_ds.get("otp_fields"):
            otp_fields.extend(raw_ds["otp_fields"])
        if raw_ds.get("payment_fields"):
            payment_fields.extend(raw_ds["payment_fields"])
        if raw_ds.get("form_actions"):
            all_form_actions.extend(raw_ds["form_actions"])

    # Collect form actions from parser
    for form in parser.forms:
        act = form.get("action", "")
        if act:
            all_form_actions.append(act)

    password_fields = list(set(password_fields))
    email_fields = list(set(email_fields))
    otp_fields = list(set(otp_fields))
    payment_fields = list(set(payment_fields))
    all_form_actions = list(set(all_form_actions))

    # Evaluate each form action for cross-origin exfiltration
    for action in all_form_actions:
        resolved_action = urljoin(effective_url, action) if effective_url else action
        is_sus, reason = _is_suspicious_exfiltration_url(resolved_action, effective_domain)
        if is_sus:
            suspicious_exfil_targets.append(resolved_action)
            cross_origin_actions.append(resolved_action)
        else:
            action_dom = _extract_domain(resolved_action)
            if action_dom and action_dom != effective_domain:
                cross_origin_actions.append(resolved_action)

    has_credential_harvesting = len(password_fields) > 0 and (len(email_fields) > 0 or len(otp_fields) > 0)

    # ── 4. Deceptive UI & Overlay Hijacking Detection ───────────────────────
    dom_lower = dom_raw.lower()

    fake_dialog_detected = bool(
        re.search(r'(?:class|id)\s*=\s*["\'][^"\']*(?:fake-dialog|browser-modal|system-alert|session-expired-modal|security-alert-box)[^"\']*["\']', dom_lower)
        or re.search(r'<(?:div|section)[^>]+(?:id|class)\s*=\s*["\'][^"\']*(?:dialog|modal)[^"\']*["\'][^>]*>.*?credential.*?password', dom_lower, re.DOTALL)
    )

    hidden_overlay_detected = parser.has_fullscreen_overlay or bool(
        re.search(r'position\s*:\s*fixed\s*;[^"\']*(?:width\s*:\s*100%|inset\s*:\s*0)[^"\']*z-index\s*:\s*(?:999\d+|[1-9]\d{4,})', dom_lower)
    )

    # Iframe credential traps (login/password inside an iframe)
    iframe_credential_trap = False
    for ifr in parser.iframes:
        src = ifr.get("src", "")
        if src:
            src_domain = _extract_domain(src)
            if src_domain and src_domain != effective_domain and any(k in src.lower() for k in ("login", "auth", "signin", "password", "oauth")):
                iframe_credential_trap = True
                break

    # ── 5. Script Evasion & Anti-Analysis Patterns ─────────────────────────
    script_contents: list[str] = [s.get("content", "") for s in parser.scripts if s.get("content")]

    # Anti-debugging patterns (debugger loop, devtools detection)
    anti_debugging_detected = bool(
        re.search(r'\bdebugger\s*;', dom_lower) or
        re.search(r'(?:console\.clear|console\.log)\s*\(\s*\);\s*setinterval', dom_lower) or
        re.search(r'function\s*\w*\s*\(\s*\)\s*\{\s*debugger\s*\}', dom_lower) or
        "devtools-detector" in dom_lower or
        "__devtools" in dom_lower
    )

    # Context menu / Selection suppression
    contextmenu_suppressed = False
    for event, val in parser.inline_event_handlers:
        if event in ("oncontextmenu", "ondragstart", "onselectstart") and ("return false" in val.lower() or "preventdefault" in val.lower()):
            contextmenu_suppressed = True
            break
    if not contextmenu_suppressed and ("event.preventdefault()" in dom_lower or "return false" in dom_lower):
        if any(h in dom_lower for h in ("contextmenu", "selectstart")):
            contextmenu_suppressed = True

    # Keystroke interception
    keystroke_interception = bool(
        re.search(r'addeventlistener\s*\(\s*["\']key(?:down|press|up)["\']', dom_lower) and
        re.search(r'(?:fetch|xmlhttprequest|\.send\(|\.post\()', dom_lower)
    )

    # Eval / Obfuscation packers
    eval_obfuscation = bool(
        re.search(r'eval\s*\(\s*(?:unescape|decodeuricomponent|atob|string\.fromcharcode)\b', dom_lower) or
        re.search(r'document\.write\s*\(\s*unescape\b', dom_lower) or
        re.search(r'function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)', dom_lower)  # Dean Edwards packer
    )

    # Meta refresh redirect
    meta_refresh_detected = bool(parser.meta_refresh)

    # ── 6. Domain Relationship Graph & Resource Mapping ─────────────────────
    script_domains: set[str] = set()
    iframe_domains: set[str] = set()
    for s in parser.scripts:
        src = s.get("src", "")
        d = _extract_domain(src)
        if d:
            script_domains.add(d)

    for ifr in parser.iframes:
        src = ifr.get("src", "")
        d = _extract_domain(src)
        if d:
            iframe_domains.add(d)

    form_action_domains = set(_extract_domain(a) for a in all_form_actions if _extract_domain(a))

    all_external_domains = (script_domains | iframe_domains | form_action_domains) - {effective_domain, ""}
    # Filter out known safe CDNs
    filtered_untrusted_domains = {
        d for d in all_external_domains
        if not any(safe in d for safe in _LEGITIMATE_THIRD_PARTIES)
        and not any(auth in d for auth in _RECOGNIZED_AUTH_PROVIDERS)
        and not (effective_domain and d.endswith("." + effective_domain))
    }

    total_entity_count = max(1, len(parser.scripts) + len(parser.iframes) + len(parser.forms))
    cross_origin_ratio = round(len(all_external_domains) / total_entity_count, 3)

    # ── 7. Indicator Compilation & Threat Flags ────────────────────────────
    indicators: list[str] = []
    behavioral_reasons: list[str] = []

    # Flag: Suspicious exfiltration endpoints
    if suspicious_exfil_targets:
        indicators.append("EXFILTRATION_ENDPOINT_DETECTED")
        behavioral_reasons.append(
            f"Form action exfiltrates data to suspicious external endpoint: {suspicious_exfil_targets[0][:100]}"
        )

    # Flag: Dynamic credential injection (temporal)
    if dynamic_password_injection:
        indicators.append("DYNAMIC_CREDENTIAL_INJECTION")
        behavioral_reasons.append("Password input dynamically inserted into DOM after initial page load (temporal evasion)")

    # Flag: Dynamic form action mutation
    if dynamic_form_action_changed:
        indicators.append("DYNAMIC_ACTION_MUTATION")
        behavioral_reasons.append("Form action target dynamically altered via JavaScript post-navigation")

    # Flag: Hidden credential collection
    if hidden_credential_fields > 0:
        indicators.append("HIDDEN_CREDENTIAL_COLLECTION")
        behavioral_reasons.append(f"{hidden_credential_fields} credential field(s) hidden via CSS display:none or opacity:0")

    # Flag: Deceptive fake dialog or modal
    if fake_dialog_detected:
        indicators.append("DECEPTIVE_BROWSER_MODAL")
        behavioral_reasons.append("Rendered DOM simulates browser or operating system security dialog box")

    # Flag: Fullscreen overlay / Clickjacking trap
    if hidden_overlay_detected:
        indicators.append("CLICKJACKING_OVERLAY_DETECTED")
        behavioral_reasons.append("Fullscreen invisible or elevated z-index overlay configured over active viewport")

    # Flag: Iframe credential trapping
    if iframe_credential_trap:
        indicators.append("CROSS_DOMAIN_IFRAME_CREDENTIALS")
        behavioral_reasons.append("Third-party iframe embedded with authentication collection signatures")

    # Flag: Anti-debugging & evasion
    if anti_debugging_detected:
        indicators.append("ANTI_DEBUGGING_ACTIVE")
        behavioral_reasons.append("Active anti-analysis code detected (debugger loop / devtools detection)")

    # Flag: Context menu / Clipboard suppression
    if contextmenu_suppressed:
        indicators.append("CONTEXT_MENU_SUPPRESSION")
        behavioral_reasons.append("Right-click context menu or text inspection explicitly suppressed via DOM handlers")

    # Flag: Keystroke logging
    if keystroke_interception:
        indicators.append("KEYSTROKE_INTERCEPTION")
        behavioral_reasons.append("Global keypress event listener capturing keystrokes and streaming to network")

    # Flag: Eval / Packer obfuscation
    if eval_obfuscation:
        indicators.append("EVAL_PACKER_OBFUSCATION")
        behavioral_reasons.append("Obfuscated JavaScript unpacking routine (eval/unescape) dynamically reconstructing DOM")

    # Flag: Meta refresh redirect
    if meta_refresh_detected:
        indicators.append("META_REFRESH_REDIRECT")
        behavioral_reasons.append(f"Client-side meta refresh redirect instruction found: {parser.meta_refresh[:60]}")

    # Flag: Credential harvesting
    if has_credential_harvesting:
        indicators.append("ACTIVE_CREDENTIAL_FORM")
        behavioral_reasons.append("Active username and password credential input fields present in rendered DOM")

    # ── 8. Calibrated Risk Score Calculation ────────────────────────────────
    risk_score = 0.0

    if is_whitelisted:
        # Whitelisted domains: minimal baseline, only genuine compromises raise risk
        if suspicious_exfil_targets:
            risk_score = 75.0
        elif dynamic_password_injection and cross_origin_actions:
            risk_score = 65.0
        else:
            risk_score = 2.0
    else:
        # Threat scoring weights
        if suspicious_exfil_targets:
            risk_score += 45.0
        if dynamic_password_injection:
            risk_score += 35.0
        if dynamic_form_action_changed:
            risk_score += 25.0
        if fake_dialog_detected:
            risk_score += 22.0
        if hidden_overlay_detected:
            risk_score += 18.0
        if iframe_credential_trap:
            risk_score += 20.0
        if hidden_credential_fields > 0:
            risk_score += 15.0
        if anti_debugging_detected:
            risk_score += 12.0
        if keystroke_interception:
            risk_score += 22.0
        if eval_obfuscation:
            risk_score += 12.0
        if contextmenu_suppressed:
            risk_score += 8.0
        if has_credential_harvesting:
            risk_score += 12.0
        if cross_origin_actions:
            risk_score += min(len(cross_origin_actions) * 10.0, 20.0)

        # Baseline presence of untrusted third parties with credential inputs
        if has_credential_harvesting and len(filtered_untrusted_domains) > 2:
            risk_score += 14.0

    risk_score = max(0.0, min(100.0, round(risk_score, 1)))

    # Threat Level Categorization
    if risk_score >= 80.0:
        threat_level = "CRITICAL"
    elif risk_score >= 60.0:
        threat_level = "HIGH"
    elif risk_score >= 35.0:
        threat_level = "MODERATE"
    elif risk_score >= 15.0:
        threat_level = "LOW"
    else:
        threat_level = "SAFE"

    # ── 9. Construct 24D Standardized ML Feature Vector ───────────────────────
    # Normalized [0.0, 1.0] numerical values for neural/gradient-boosted models
    feature_dict: dict[str, float] = {
        "f01_temporal_available": 1.0 if temporal_available else 0.0,
        "f02_mutation_count_norm": min(1.0, mutation_count / 100.0),
        "f03_nodes_added_norm": min(1.0, dynamic_nodes_added / 50.0),
        "f04_attrs_changed_norm": min(1.0, dynamic_attributes_changed / 50.0),
        "f05_dynamic_password": 1.0 if dynamic_password_injection else 0.0,
        "f06_dynamic_action_change": 1.0 if dynamic_form_action_changed else 0.0,
        "f07_has_password": 1.0 if len(password_fields) > 0 else 0.0,
        "f08_password_count_norm": min(1.0, len(password_fields) / 5.0),
        "f09_has_email": 1.0 if len(email_fields) > 0 else 0.0,
        "f10_has_otp": 1.0 if len(otp_fields) > 0 else 0.0,
        "f11_has_payment": 1.0 if len(payment_fields) > 0 else 0.0,
        "f12_hidden_creds": min(1.0, hidden_credential_fields / 3.0),
        "f13_cross_origin_form": 1.0 if cross_origin_actions else 0.0,
        "f14_suspicious_exfil": 1.0 if suspicious_exfil_targets else 0.0,
        "f15_hidden_overlay": 1.0 if hidden_overlay_detected else 0.0,
        "f16_fake_dialog": 1.0 if fake_dialog_detected else 0.0,
        "f17_iframe_trap": 1.0 if iframe_credential_trap else 0.0,
        "f18_anti_debugging": 1.0 if anti_debugging_detected else 0.0,
        "f19_contextmenu_suppressed": 1.0 if contextmenu_suppressed else 0.0,
        "f20_keystroke_interception": 1.0 if keystroke_interception else 0.0,
        "f21_eval_obfuscation": 1.0 if eval_obfuscation else 0.0,
        "f22_meta_refresh": 1.0 if meta_refresh_detected else 0.0,
        "f23_cross_origin_ratio": min(1.0, cross_origin_ratio),
        "f24_untrusted_domains_count": min(1.0, len(filtered_untrusted_domains) / 10.0),
    }

    feature_vector = [round(v, 4) for v in feature_dict.values()]

    execution_time_ms = round((time.perf_counter() - t0) * 1000, 2)

    # ── Temporary DEBUG Telemetry ──────────────────────────────────────────
    debug_telemetry = {
        "engine_started": True,
        "playwright_executed": bool(raw_ds and (raw_ds.get("executed") or raw_ds.get("page_available") or raw_ds.get("screenshot_available"))),
        "vm_scan_executed": bool(raw_ds and raw_ds.get("available")),
        "t0_captured": bool(vm_snapshots.get("t0_html_len") is not None or vm_snapshots.get("t0_input_count") is not None),
        "mutation_observer_injected": bool(vm_behavior.get("mutation_observer_injected", temporal_available)),
        "stabilization_wait_ms": vm_behavior.get("stabilization_wait_ms", 2500 if (raw_ds and raw_ds.get("available") and raw_ds.get("executed")) else 0),
        "t1_captured": bool(vm_snapshots.get("t1_html_len") is not None or bool(dom_raw)),
        "mutation_event_count": mutation_count,
        "dynamic_password_injection": dynamic_password_injection,
        "dynamic_form_action_mutated": dynamic_form_action_changed,
        "iframe_injection": bool(vm_behavior.get("iframe_injection", False) or "dynamic_iframe_injection" in vm_events),
        "dom_engine_executed": True,
        "fallback_used": not temporal_available,
        "analysis_duration_ms": execution_time_ms,
        "vm_scan_time_ms": raw_ds.get("scan_time_ms", 0.0) if raw_ds else 0.0,
    }

    print(
        f"[DOM_BEHAVIOR_DEBUG] engine_started={debug_telemetry['engine_started']} "
        f"playwright_executed={debug_telemetry['playwright_executed']} "
        f"vm_scan_executed={debug_telemetry['vm_scan_executed']} "
        f"t0_captured={debug_telemetry['t0_captured']} "
        f"mutation_observer_injected={debug_telemetry['mutation_observer_injected']} "
        f"stabilization_wait_ms={debug_telemetry['stabilization_wait_ms']} "
        f"t1_captured={debug_telemetry['t1_captured']} "
        f"mutation_event_count={debug_telemetry['mutation_event_count']} "
        f"dynamic_password_injection={debug_telemetry['dynamic_password_injection']} "
        f"dynamic_form_action_mutated={debug_telemetry['dynamic_form_action_mutated']} "
        f"iframe_injection={debug_telemetry['iframe_injection']} "
        f"dom_engine_executed={debug_telemetry['dom_engine_executed']} "
        f"fallback_used={debug_telemetry['fallback_used']} "
        f"analysis_duration_ms={debug_telemetry['analysis_duration_ms']}",
        flush=True
    )

    # Human-readable summary
    if risk_score >= 60.0:
        summary = f"High-risk DOM behavioral anomalies detected ({len(indicators)} indicators). Suspicious exfiltration or dynamic injection present."
    elif risk_score >= 35.0:
        summary = f"Moderate DOM behavioral risk ({len(indicators)} indicators). Cross-domain dependencies or authentication structures present."
    else:
        summary = "Rendered DOM structure exhibits benign characteristics with standard document flow."

    return {
        "available": True,
        "dom_behavior_score": risk_score,
        "threat_level": threat_level,
        "summary": summary,
        "indicators": indicators,
        "behavioral_reasons": behavioral_reasons,
        "temporal_analysis": {
            "available": temporal_available,
            "mutation_count": mutation_count,
            "nodes_added": dynamic_nodes_added,
            "attributes_changed": dynamic_attributes_changed,
            "dynamic_password_injection": dynamic_password_injection,
            "dynamic_form_action_changed": dynamic_form_action_changed,
            "recorded_events": vm_events,
        },
        "form_exfiltration": {
            "has_credential_harvesting": has_credential_harvesting,
            "password_fields_count": len(password_fields),
            "email_fields_count": len(email_fields),
            "otp_fields_count": len(otp_fields),
            "payment_fields_count": len(payment_fields),
            "hidden_credential_fields": hidden_credential_fields,
            "cross_origin_form_actions": cross_origin_actions,
            "suspicious_exfil_targets": suspicious_exfil_targets,
            "all_form_actions": all_form_actions,
        },
        "ui_deception": {
            "hidden_overlay_detected": hidden_overlay_detected,
            "fake_dialog_detected": fake_dialog_detected,
            "iframe_credential_trap": iframe_credential_trap,
            "high_zindex_elements": parser.high_zindex_elements,
            "hidden_elements_count": parser.hidden_elements,
        },
        "script_evasion": {
            "anti_debugging_detected": anti_debugging_detected,
            "contextmenu_suppressed": contextmenu_suppressed,
            "keystroke_interception": keystroke_interception,
            "eval_obfuscation": eval_obfuscation,
            "meta_refresh_detected": meta_refresh_detected,
        },
        "domain_relationship_graph": {
            "page_domain": effective_domain,
            "script_domains": sorted(list(script_domains)),
            "iframe_domains": sorted(list(iframe_domains)),
            "form_action_domains": sorted(list(form_action_domains)),
            "untrusted_external_domains": sorted(list(filtered_untrusted_domains)),
            "cross_origin_ratio": cross_origin_ratio,
        },
        "ml_feature_vector": feature_vector,
        "ml_feature_dict": feature_dict,
        "execution_time_ms": execution_time_ms,
        "debug": debug_telemetry,
    }


def _empty_dom_behavior_result(domain: str, is_whitelisted: bool, t0: float) -> dict[str, Any]:
    """Generates a safe default payload when no DOM is available."""
    exec_ms = round((time.perf_counter() - t0) * 1000, 2)
    debug_telemetry = {
        "engine_started": True,
        "playwright_executed": False,
        "vm_scan_executed": False,
        "t0_captured": False,
        "mutation_observer_injected": False,
        "stabilization_wait_ms": 0,
        "t1_captured": False,
        "mutation_event_count": 0,
        "dynamic_password_injection": False,
        "dynamic_form_action_mutated": False,
        "iframe_injection": False,
        "dom_engine_executed": True,
        "fallback_used": True,
        "analysis_duration_ms": exec_ms,
        "vm_scan_time_ms": 0.0,
    }
    return {
        "available": False,
        "dom_behavior_score": 0.0,
        "threat_level": "SAFE",
        "summary": "DOM behavioral inspection unavailable (no rendered snapshot captured).",
        "indicators": [],
        "behavioral_reasons": [],
        "temporal_analysis": {
            "available": False,
            "mutation_count": 0,
            "nodes_added": 0,
            "attributes_changed": 0,
            "dynamic_password_injection": False,
            "dynamic_form_action_changed": False,
            "recorded_events": [],
        },
        "form_exfiltration": {
            "has_credential_harvesting": False,
            "password_fields_count": 0,
            "email_fields_count": 0,
            "otp_fields_count": 0,
            "payment_fields_count": 0,
            "hidden_credential_fields": 0,
            "cross_origin_form_actions": [],
            "suspicious_exfil_targets": [],
            "all_form_actions": [],
        },
        "ui_deception": {
            "hidden_overlay_detected": False,
            "fake_dialog_detected": False,
            "iframe_credential_trap": False,
            "high_zindex_elements": 0,
            "hidden_elements_count": 0,
        },
        "script_evasion": {
            "anti_debugging_detected": False,
            "contextmenu_suppressed": False,
            "keystroke_interception": False,
            "eval_obfuscation": False,
            "meta_refresh_detected": False,
        },
        "domain_relationship_graph": {
            "page_domain": domain,
            "script_domains": [],
            "iframe_domains": [],
            "form_action_domains": [],
            "untrusted_external_domains": [],
            "cross_origin_ratio": 0.0,
        },
        "ml_feature_vector": [0.0] * 24,
        "ml_feature_dict": {f"f{i+1:02d}": 0.0 for i in range(24)},
        "execution_time_ms": exec_ms,
        "debug": debug_telemetry,
    }
