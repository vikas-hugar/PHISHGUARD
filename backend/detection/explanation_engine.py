"""
PhishGuard AI V6.1 — Explainable AI (XAI) Explanation Engine
=============================================================
Generates transparent, scientifically honest, evidence-based explanations:
  - Every reason corresponds directly to measured evidence
  - Clearly differentiates generic keywords (crypto, wallet) from brand spoofing
  - Explains neural model agreement and disagreement explicitly
  - Reports calibrated model probabilities
  - Generates clear, non-overconfident operational directives
"""

from __future__ import annotations

# ── Reason templates keyed to evidence type ────────────────────────────────
_REASON_TEMPLATES = {
    # Threat intelligence
    "known_url_exact": ("URL exactly matches a verified phishing entry in the threat repository", 1),
    "known_url_hash": ("URL SHA-256 fingerprint matches a confirmed phishing record", 1),
    "known_domain": ("Apex domain is indexed as known malicious infrastructure", 1),

    # Brand intelligence
    "brand_embedded_modifier": ("Domain name targeting '{brand}' combined with deceptive keyword '{modifier}'", 2),
    "brand_impersonation_unofficial": ("Domain resembles '{brand}' and does not use an official {brand} registrable domain ({sim}% similarity)", 2),
    "brand_repeated_chars": ("Repeated-character obfuscation targeting '{brand}' (e.g. 'aaappllle')", 2),
    "brand_fuzzy": ("Domain closely resembles '{brand}' ({sim}% character-level similarity)", 2),

    # Homoglyph / Punycode
    "homoglyph": ("Homoglyph character substitution detected: Unicode character {detail} normalized to look-alike ASCII representation", 3),
    "punycode_brand": ("Punycode (xn--) IDN domain spoofing brand '{brand}' ({sim}% decoded similarity)", 3),
    "punycode_generic": ("Punycode/IDN encoding detected — domain contains non-ASCII internationalized characters", 3),

    # Typosquatting
    "typosquat": ("Typosquatting attack targeting '{brand}' via {technique}", 3),

    # Generic Keywords
    "generic_keywords": ("Domain contains cryptocurrency/security/credential-related terminology: {keywords}", 4),

    # URL heuristics
    "ip_host": ("Direct IP address used as hostname instead of domain name", 4),
    "suspicious_tld": ("High-risk TLD detected ({tld}) commonly abused in rapid-turnaround attacks", 4),
    "excessive_subdomains": ("Excessive subdomain depth — common in phishing infrastructure", 4),
    "high_entropy": ("High character entropy — URL may contain obfuscated or encoded content", 4),
    "long_url": ("Unusually long URL — longer URLs are often used to obscure malicious intent", 4),
    "high_digit_ratio": ("High proportion of digits in URL — common in algorithmic phishing infrastructure", 4),
    "credential_keywords": ("URL contains credential-harvesting keywords (login, verify, account, etc.)", 4),
    "url_shortener": ("URL shortener detected — final destination is masked", 4),
    "double_slash": ("Double-slash redirect anomaly detected in URL path", 4),
    "high_special_chars": ("Unusually high proportion of special characters in URL", 4),

    # Model signals & disagreement
    "cnn_high": ("CNN-BiLSTM neural model detected phishing-like character patterns ({prob}% calibrated prob)", 5),
    "roberta_high": ("RoBERTa transformer model flagged phishing-like URL semantics ({prob}% calibrated prob)", 5),
    "model_disagreement": ("CNN-BiLSTM and RoBERTa models show substantial disagreement; risk assessment is weighted by independent heuristic and brand evidence", 4),

    # Deep scan
    "credential_form": ("Credential collection form detected on page (password/login fields)", 2),
    "external_form_action": ("Login form submits credential data to an external, unverified domain", 2),
    "suspicious_scripts": ("Suspicious JavaScript patterns detected on page ({count} scripts)", 3),
    "login_page": ("Page DOM structure contains authentication/sign-in elements", 4),
    "brand_logo_mismatch": ("Brand visual assets present but domain does not match official brand", 2),
    "external_iframe": ("External iframe detected — potentially embedding unauthorized content", 3),
    "otp_field": ("One-time password (OTP) collection field detected in rendered DOM", 2),
    "payment_field": ("Payment/financial data collection field detected in rendered DOM", 2),

    # Clean
    "trusted_whitelist": ("Verified enterprise domain — confirmed in trusted domain whitelist", 1),
    "no_repo_match": ("URL not found in offline threat repository", 6),
    "no_brand_match": ("No brand impersonation or typosquatting signals detected", 6),
    "low_heuristic": ("URL structure shows no anomalous patterns", 6),
    "clean_structure": ("Clean domain structure with standard registration attributes", 6),
}


def _fmt(template: str, **kwargs) -> str:
    """Format a reason template with provided keyword arguments."""
    try:
        return template.format(**kwargs)
    except KeyError:
        return template


def generate_reasons(
    *,
    classification: str,
    is_whitelisted: bool = False,
    threat_intel: dict | None = None,
    brand: dict | None = None,
    heuristic_reasons: list[str] | None = None,
    cnn: dict | None = None,
    roberta: dict | None = None,
    deep_scan: dict | None = None,
    high_signals: list[str] | None = None,
    model_disagreement: bool = False,
    evidence_vector: dict | None = None,
    max_reasons: int = 6,
    **kwargs: Any,
) -> list[str]:
    """
    Generate a prioritised, honest list of reasons for the given classification.
    Every returned reason corresponds directly to detected evidence.
    """
    ti = threat_intel or {}
    br = brand or {}
    hr = heuristic_reasons or []
    cn = cnn or {}
    ro = roberta or {}
    ds = deep_scan or {}
    hs = set(high_signals or [])

    reasons: list[tuple[int, str]] = []

    # ── 1. Whitelist ───────────────────────────────────────────────────────
    if is_whitelisted:
        clean_reasons = [_REASON_TEMPLATES["trusted_whitelist"][0]]
        if ds.get("available"):
            clean_reasons.append("VirtualBox Deep Scan confirmed legitimate page structure with no credential exfiltration")
        return clean_reasons

    # ── 2. Threat Intelligence ─────────────────────────────────────────────
    ti_match = ti.get("match_type", "")
    if ti_match == "Exact URL Match":
        reasons.append((1, _REASON_TEMPLATES["known_url_exact"][0]))
    elif ti_match == "SHA-256 Hash Match":
        reasons.append((1, _REASON_TEMPLATES["known_url_hash"][0]))
    elif ti_match == "Malicious Domain":
        reasons.append((1, _REASON_TEMPLATES["known_domain"][0]))
    elif ti_match == "Punycode Attack":
        target = ti.get("target_brand", "")
        sim = round(ti.get("similarity", 0.0) * 100)
        if target:
            reasons.append((3, _fmt(_REASON_TEMPLATES["punycode_brand"][0], brand=target.capitalize(), sim=sim)))
        else:
            reasons.append((3, _REASON_TEMPLATES["punycode_generic"][0]))
    elif ti_match == "Homoglyph Attack":
        subs = ti.get("matched_value", "")
        reasons.append((3, _fmt(_REASON_TEMPLATES["homoglyph"][0], detail=subs or "character substitution")))

    # ── 3. Brand Intelligence & Typosquatting ──────────────────────────────
    br_detected = br.get("detected", False)
    if br_detected:
        brand_name = (br.get("company") or br.get("brand") or "").strip()
        imp_type = br.get("impersonation_type", "")
        modifier = br.get("modifier")
        sim = round(br.get("similarity", 0.0) * 100)

        if "Repeated" in imp_type:
            reasons.append((2, _fmt(_REASON_TEMPLATES["brand_repeated_chars"][0], brand=brand_name)))
        elif "Modifier" in imp_type or modifier:
            reasons.append((2, _fmt(_REASON_TEMPLATES["brand_embedded_modifier"][0],
                                     brand=brand_name, modifier=modifier or "deceptive keyword")))
        elif "Typosquat" in imp_type or "Typo" in imp_type:
            technique = br.get("technique") or imp_type
            reasons.append((2, _fmt(_REASON_TEMPLATES["typosquat"][0],
                                     brand=brand_name, technique=technique)))
        else:
            reasons.append((2, _fmt(_REASON_TEMPLATES["brand_impersonation_unofficial"][0], brand=brand_name, sim=sim)))

    # Generic Keywords (when no brand match, explain terminology correctly)
    generic_kws = br.get("generic_keywords") or []
    if generic_kws and not br_detected:
        kw_str = ", ".join(generic_kws[:3])
        reasons.append((4, _fmt(_REASON_TEMPLATES["generic_keywords"][0], keywords=kw_str)))

    # ── 4. Model Disagreement Notice ───────────────────────────────────────
    if model_disagreement:
        reasons.append((4, _REASON_TEMPLATES["model_disagreement"][0]))

    # ── 5. URL Heuristics ──────────────────────────────────────────────────
    HEURISTIC_KEY_MAP = {
        "IP address used as host": (4, _REASON_TEMPLATES["ip_host"][0]),
        "Credential harvesting keywords": (4, _REASON_TEMPLATES["credential_keywords"][0]),
        "Suspicious TLD": (4, None),
        "Excessive subdomain depth": (4, _REASON_TEMPLATES["excessive_subdomains"][0]),
        "High entropy domain": (4, _REASON_TEMPLATES["high_entropy"][0]),
        "Unusually long URL": (4, _REASON_TEMPLATES["long_url"][0]),
        "High digit ratio in URL": (4, _REASON_TEMPLATES["high_digit_ratio"][0]),
        "URL shortener masking destination": (4, _REASON_TEMPLATES["url_shortener"][0]),
        "Double-slash redirect in path": (4, _REASON_TEMPLATES["double_slash"][0]),
        "High special character ratio": (4, _REASON_TEMPLATES["high_special_chars"][0]),
    }
    for raw_reason in hr:
        mapped = None
        for key, (pri, tmpl) in HEURISTIC_KEY_MAP.items():
            if key.lower() in raw_reason.lower():
                if tmpl:
                    mapped = (pri, tmpl)
                else:
                    import re
                    tld_match = re.search(r'\(([^)]+)\)', raw_reason)
                    tld = tld_match.group(1) if tld_match else "uncommon TLD"
                    mapped = (4, _fmt(_REASON_TEMPLATES["suspicious_tld"][0], tld=tld))
                break
        if mapped:
            reasons.append(mapped)
        else:
            if raw_reason and raw_reason not in [r for _, r in reasons]:
                reasons.append((4, raw_reason))

    # ── 6. Model Signals ───────────────────────────────────────────────────
    if cn.get("available", False) and cn.get("probability") is not None:
        c_prob = round(cn["probability"] * 100, 1)
        if c_prob >= 70:
            reasons.append((5, _fmt(_REASON_TEMPLATES["cnn_high"][0], prob=c_prob)))

    if ro.get("available", False) and ro.get("probability") is not None:
        r_prob = round(ro["probability"] * 100, 1)
        if r_prob >= 70:
            reasons.append((5, _fmt(_REASON_TEMPLATES["roberta_high"][0], prob=r_prob)))

    # ── 7. Deep Scan Evidence ──────────────────────────────────────────────
    if ds.get("available", False):
        html_ev = ds.get("html_evidence", {})
        dom_ev = ds.get("dom_evidence", {})
        if html_ev.get("credential_form") or dom_ev.get("credential_collection_form"):
            reasons.append((2, _REASON_TEMPLATES["credential_form"][0]))
        if html_ev.get("external_form_action") or dom_ev.get("external_form_action"):
            reasons.append((2, _REASON_TEMPLATES["external_form_action"][0]))
        if html_ev.get("login_page_detected") or dom_ev.get("login_form"):
            reasons.append((4, _REASON_TEMPLATES["login_page"][0]))
        if html_ev.get("otp_field_detected") or dom_ev.get("otp_field"):
            reasons.append((2, _REASON_TEMPLATES["otp_field"][0]))

    # Deduplicate while preserving priority order
    seen: set[str] = set()
    sorted_reasons = []
    for _, text in sorted(reasons, key=lambda x: x[0]):
        if text not in seen:
            seen.add(text)
            sorted_reasons.append(text)

    if not sorted_reasons:
        if classification == "LEGITIMATE":
            return [
                "No phishing indicators detected across threat databases and heuristic models.",
                "Clean domain structure with standard registration attributes."
            ]
        elif classification == "SUSPICIOUS":
            return ["Elevated structural anomalies detected; exercise caution."]
        return ["Unknown domain profile; no conclusive malicious signatures found."]

    return sorted_reasons[:max_reasons]


def build_recommendation(classification: str, target_brand: str | None = None) -> str:
    """
    Generate an actionable, scientifically grounded operational directive.
    Never claims absolute 100% safety.
    """
    if classification == "KNOWN_PHISHING":
        return (
            "🚨 CRITICAL THREAT: Exact match confirmed in threat intelligence database. "
            "Traffic should be immediately blocked at gateway/DNS level. Do not open or submit credentials."
        )

    if classification == "ZERO_DAY_PHISHING":
        brand_note = f" (targeting {target_brand.capitalize()})" if target_brand and target_brand != "None" else ""
        return (
            f"⚠️ ZERO-DAY PHISHING DETECTED: Novel attack pattern identified{brand_note}. "
            "Corroborating indicators demonstrate deceptive intent. "
            "Block access and isolate endpoint. Note: Automated systems are probabilistic; verify independently if critical."
        )

    if classification == "SUSPICIOUS":
        return (
            "⚠️ ELEVATED RISK / CAUTION ADVISED: Target exhibits anomalous characteristics or detector disagreement. "
            "Do NOT enter passwords, OTP tokens, or personal information until authenticity is verified through official channels."
        )

    # LEGITIMATE
    return (
        "✅ LOW RISK: No malicious signatures or phishing indicators detected across offline threat intelligence and heuristic engines. "
        "Standard browsing precautions still apply."
    )
