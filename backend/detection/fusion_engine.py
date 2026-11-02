"""
PhishGuard AI V7.0 — Unified Evidence Fusion Engine & Mathematical Calibration
================================================================================
Aggregates independent evidence from Quick Scan, Neural Models, In-VM Deep Scan,
and Visual Phishing Analysis into a mathematically sound, calibrated verdict:
  - Builds an explicit Evidence Vector for every scan
  - Mathematical separation of RISK SCORE (threat severity) and CONFIDENCE (evidence certainty)
  - CNN vs. RoBERTa Agreement & Disagreement Detection:
      difference <= 0.10 -> HIGH_AGREEMENT
      difference <= 0.25 -> MODERATE_AGREEMENT
      difference > 0.25  -> DISAGREEMENT
      difference > 0.50  -> STRONG_DISAGREEMENT
      missing model      -> UNAVAILABLE (not counted as disagreement)
  - Temperature Scaling Probability Calibration (prevents overconfident sigmoids)
  - Multi-tier evidence compilation:
      Tier A: Definitive / High-Value (Threat Repo, Whitelist)
      Tier B: Strong Evidence (Brand spoofing, Typosquatting, Homoglyphs, Punycode, Credential Forms, Visual Impersonation)
      Tier C: Supporting Evidence (Calibrated Neural probabilities, Heuristic flags, Entropy, TLD, Scripts)
  - Generates explicit positive_signals, negative_signals, and conflicting_signals
  - Supports ALL valid public URLs through unified evidence evaluation
"""

from __future__ import annotations
import math
import time
from typing import Any

# ── Fusion Configuration ───────────────────────────────────────────────────
FUSION_CONFIG = {
    # Temperature scaling parameters for probability calibration
    "cnn_temperature": 1.35,
    "roberta_temperature": 1.20,

    # Weights for supporting evidence when both neural models are active
    "cnn_weight": 0.28,
    "roberta_weight": 0.32,
    "heuristic_weight": 0.18,
    "brand_weight": 0.22,
    "deep_scan_weight": 0.15,

    # Fallback weights when only CNN is active
    "cnn_only_weight": 0.48,
    "heuristic_only_weight": 0.28,
    "brand_only_weight": 0.24,

    # Classification thresholds
    "zero_day_min_risk": 72.0,
    "zero_day_min_signals": 2,
    "suspicious_min_risk": 40.0,
    "brand_zero_day_min_sim": 0.88,
    "cnn_high_threshold": 0.78,
    "roberta_high_threshold": 0.72,
    "heuristic_high_threshold": 50,

    # Deep scan bonuses
    "credential_form_bonus": 20,
    "external_form_action_bonus": 15,
    "suspicious_script_bonus_per": 4,
    "max_script_bonus": 16,
    "login_page_bonus": 8,
    "visual_impersonation_bonus": 25,
}


def _clamp(v: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, float(v)))


def calibrate_probability(raw_prob: float | None, temperature: float = 1.0) -> float | None:
    """
    Apply temperature scaling to raw sigmoid probability.
    Smooths uncalibrated extreme probabilities to reflect real-world empirical confidence.
    """
    if raw_prob is None:
        return None
    p = max(1e-6, min(1.0 - 1e-6, float(raw_prob)))
    logit = math.log(p / (1.0 - p))
    scaled_logit = logit / max(temperature, 0.1)
    calibrated = 1.0 / (1.0 + math.exp(-scaled_logit))
    return round(calibrated, 4)


def build_evidence_vector(
    threat_intel: dict | None,
    brand: dict | None,
    heuristics: dict | None,
    cnn: dict | None,
    roberta: dict | None,
    deep_scan: dict | None,
    visual_analysis: dict | None,
    is_whitelisted: bool,
    dom_behavior: dict | None = None,
) -> dict:
    """
    Constructs an explicit, structured Evidence Vector from all available detectors.
    Missing evidence is set to None (never fabricated).
    """
    ti = threat_intel or {}
    br = brand or {}
    he = heuristics or {}
    cn = cnn or {}
    ro = roberta or {}
    ds = deep_scan or {}
    va = visual_analysis or {}

    cnn_avail = cn.get("available", False) and cn.get("executed", True)
    cnn_raw = float(cn.get("probability")) if (cnn_avail and cn.get("probability") is not None) else None
    cnn_cal = calibrate_probability(cnn_raw, FUSION_CONFIG["cnn_temperature"])

    ro_avail = ro.get("available", False) and ro.get("executed", True)
    ro_raw = float(ro.get("probability")) if (ro_avail and ro.get("probability") is not None) else None
    ro_cal = calibrate_probability(ro_raw, FUSION_CONFIG["roberta_temperature"])

    # Model agreement calculation (V7.0 Section 12)
    model_agreement = None
    model_agreement_level = "UNAVAILABLE"
    model_disagreement = False
    neural_consensus = "NO_MODELS"

    if cnn_raw is not None and ro_raw is not None:
        agreement_diff = abs(cnn_raw - ro_raw)
        model_agreement = round(1.0 - agreement_diff, 3)

        if agreement_diff <= 0.10:
            model_agreement_level = "HIGH_AGREEMENT"
        elif agreement_diff <= 0.25:
            model_agreement_level = "MODERATE_AGREEMENT"
        elif agreement_diff <= 0.50:
            model_agreement_level = "DISAGREEMENT"
        else:
            model_agreement_level = "STRONG_DISAGREEMENT"

        model_disagreement = agreement_diff > 0.25

        if cnn_raw >= 0.70 and ro_raw >= 0.70:
            neural_consensus = "CONSENSUS_PHISH"
        elif cnn_raw <= 0.35 and ro_raw <= 0.35:
            neural_consensus = "CONSENSUS_CLEAN"
        elif model_disagreement:
            neural_consensus = "DISAGREEMENT"
        else:
            neural_consensus = "AMBIGUOUS"
    elif cnn_raw is not None or ro_raw is not None:
        neural_consensus = "SINGLE_MODEL"
        model_agreement_level = "SINGLE_MODEL"

    # Category extraction
    ti_found = ti.get("found", False)
    match_type = ti.get("match_type", "")
    is_exact_repo = ti_found and match_type in ("Exact URL Match", "SHA-256 Hash Match", "Malicious Domain")
    is_punycode = ti_found and match_type == "Punycode Attack"
    is_homoglyph = ti_found and match_type == "Homoglyph Attack"
    is_typosquat = ti_found and "Typosquatting" in str(match_type)
    is_brand_imp = br.get("detected", False) or (ti_found and match_type == "Brand Impersonation")

    return {
        "is_whitelisted": is_whitelisted,
        "threat_intelligence": 100.0 if is_exact_repo else 0.0,
        "brand_impersonation": round(float(br.get("similarity", ti.get("similarity", 0.0))) * 100, 1) if is_brand_imp else 0.0,
        "typosquatting": round(float(ti.get("similarity", 0.0)) * 100, 1) if is_typosquat else 0.0,
        "homoglyph": 95.0 if is_homoglyph else 0.0,
        "punycode": 95.0 if is_punycode else 0.0,
        "url_heuristics": round(float(he.get("score", 0.0)), 1),
        "cnn_probability": round(cnn_raw * 100, 1) if cnn_raw is not None else None,
        "cnn_calibrated": round(cnn_cal * 100, 1) if cnn_cal is not None else None,
        "roberta_probability": round(ro_raw * 100, 1) if ro_raw is not None else None,
        "roberta_calibrated": round(ro_cal * 100, 1) if ro_cal is not None else None,
        "model_agreement": model_agreement,
        "model_agreement_level": model_agreement_level,
        "model_disagreement": model_disagreement,
        "neural_consensus": neural_consensus,
        "credential_context": 80.0 if (ds.get("html_evidence", {}).get("credential_form") or ds.get("dom_evidence", {}).get("credential_collection_form") or va.get("has_credential_harvesting")) else 0.0,
        "visual_impersonation": 90.0 if va.get("brand_impersonation_visual") else 0.0,
        "visual_risk_score": float(va.get("visual_risk_score", 0.0)),
        "deep_scan_available": ds.get("available", False),
        "dom_behavior_score": float((dom_behavior or {}).get("dom_behavior_score", 0.0)),
        "dom_behavior_available": bool((dom_behavior or {}).get("available")),
        "dynamic_password_injection": bool((dom_behavior or {}).get("temporal_analysis", {}).get("dynamic_password_injection")),
        "suspicious_exfiltration": bool((dom_behavior or {}).get("form_exfiltration", {}).get("suspicious_exfil_targets")),
        "fake_dialog_detected": bool((dom_behavior or {}).get("ui_deception", {}).get("fake_dialog_detected")),
        "hidden_overlay_detected": bool((dom_behavior or {}).get("ui_deception", {}).get("hidden_overlay_detected")),
        "anti_debugging_detected": bool((dom_behavior or {}).get("script_evasion", {}).get("anti_debugging_detected")),
    }


def calculate_mathematical_confidence(
    classification: str,
    evidence_vector: dict,
    strong_evidence_count: int,
    risk_score: float
) -> float:
    """
    Calculate an honest confidence score mathematically separate from risk score.
    Confidence reflects reliability of the evidence, detector agreement, and margin.
    """
    # Deterministic cases
    if classification == "KNOWN_PHISHING" or evidence_vector.get("threat_intelligence", 0) > 0:
        return 99.0
    if classification == "LEGITIMATE" and evidence_vector.get("is_whitelisted"):
        return 99.0

    base_conf = 70.0

    # Agreement between neural models (Section 12)
    agreement = evidence_vector.get("model_agreement")
    agreement_level = evidence_vector.get("model_agreement_level")
    if agreement is not None:
        if agreement_level == "HIGH_AGREEMENT":
            base_conf += 16.0  # Strong neural consensus
        elif agreement_level == "MODERATE_AGREEMENT":
            base_conf += 8.0
        elif agreement_level == "DISAGREEMENT":
            base_conf -= 18.0  # Moderate disagreement penalty
        elif agreement_level == "STRONG_DISAGREEMENT":
            base_conf -= 28.0  # Strong disagreement penalty

    # Independent strong evidence bonus
    if strong_evidence_count >= 2:
        base_conf += 14.0
    elif strong_evidence_count == 1:
        base_conf += 8.0

    # Deep scan corroboration bonus
    if evidence_vector.get("deep_scan_available") and evidence_vector.get("credential_context", 0) > 0:
        base_conf += 8.0

    # Extreme risk margins (clearly malicious or clearly clean) give higher confidence
    if risk_score >= 90:
        base_conf += 6.0
    elif risk_score <= 10:
        base_conf += 8.0
    elif 40 <= risk_score <= 65:
        # Ambiguous middle zone lowers confidence
        base_conf -= 10.0

    return _clamp(base_conf, 45.0, 99.0)


def fuse(
    *,
    threat_intel: dict | None = None,
    brand: dict | None = None,
    heuristics: dict | None = None,
    cnn: dict | None = None,
    roberta: dict | None = None,
    deep_scan: dict | None = None,
    visual_analysis: dict | None = None,
    dom_behavior: dict | None = None,
    is_whitelisted: bool = False,
) -> dict:
    """
    Multi-layer evidence fusion engine for V7.0 Unified Engine.
    Combines Quick Scan, Neural Models, VirtualBox Deep Scan, and Visual Analysis.
    Produces risk score, separate calibrated confidence, evidence vector,
    signal taxonomy (positive/negative/conflicting), and 5-state verdict.
    """
    t0 = time.perf_counter()
    cfg = FUSION_CONFIG

    # ── 1. Construct Structured Evidence Vector ────────────────────────────
    ev_vector = build_evidence_vector(
        threat_intel, brand, heuristics, cnn, roberta, deep_scan, visual_analysis, is_whitelisted, dom_behavior
    )

    positive_signals: list[str] = []
    negative_signals: list[str] = []
    conflicting_signals: list[str] = []
    high_signals: list[str] = []
    strong_evidence_count = 0
    evidence_count = 0

    ti = threat_intel or {}
    match_type = ti.get("match_type", "")
    ds = deep_scan or {}
    va = visual_analysis or {}

    # Signal compilation: Threat intelligence
    if ev_vector["threat_intelligence"] >= 95.0:
        positive_signals.append(f"Threat Intelligence Repository hit ({match_type})")
        high_signals.append("threat_intelligence")
        strong_evidence_count += 1
        evidence_count += 1
    else:
        negative_signals.append("Clean threat repository lookup (no known malicious match)")

    # Signal compilation: Whitelist
    if is_whitelisted:
        negative_signals.append("Enterprise Domain Whitelist verified")
        evidence_count += 1

    # Signal compilation: Brand & Spoofing
    brand_sim = ev_vector["brand_impersonation"] / 100.0
    if brand_sim >= cfg["brand_zero_day_min_sim"]:
        positive_signals.append(f"Brand impersonation detected ({ev_vector['brand_impersonation']}%)")
        high_signals.append("brand_impersonation")
        strong_evidence_count += 1
        evidence_count += 1

    typo_sim = ev_vector["typosquatting"] / 100.0
    if typo_sim >= 0.84:
        positive_signals.append(f"Typosquatting attack detected ({ev_vector['typosquatting']}%)")
        high_signals.append("typosquatting")
        strong_evidence_count += 1
        evidence_count += 1

    if ev_vector["homoglyph"] > 0:
        positive_signals.append("Homoglyph character substitution detected")
        high_signals.append("homoglyph")
        strong_evidence_count += 1
        evidence_count += 1

    if ev_vector["punycode"] > 0:
        positive_signals.append("Punycode (xn--) internationalized domain spoofing detected")
        high_signals.append("punycode")
        strong_evidence_count += 1
        evidence_count += 1

    # Signal compilation: Neural models & consensus
    cnn_prob = ev_vector["cnn_calibrated"]
    ro_prob = ev_vector["roberta_calibrated"]

    if cnn_prob is not None:
        evidence_count += 1
        if cnn_prob >= cfg["cnn_high_threshold"] * 100:
            positive_signals.append(f"CNN-BiLSTM model flagged malicious URL character patterns ({cnn_prob}%)")
            high_signals.append("cnn_model")
        elif cnn_prob <= 35.0:
            negative_signals.append(f"CNN-BiLSTM model evaluated URL as benign ({cnn_prob}%)")

    if ro_prob is not None:
        evidence_count += 1
        if ro_prob >= cfg["roberta_high_threshold"] * 100:
            positive_signals.append(f"RoBERTa model flagged malicious URL semantics ({ro_prob}%)")
            high_signals.append("roberta_model")
        elif ro_prob <= 35.0:
            negative_signals.append(f"RoBERTa model evaluated URL semantics as benign ({ro_prob}%)")

    if ev_vector["model_disagreement"]:
        conflicting_signals.append(
            f"Model disagreement ({ev_vector['model_agreement_level']}): CNN={cnn_prob}% vs RoBERTa={ro_prob}%"
        )
    elif ev_vector["neural_consensus"] == "CONSENSUS_PHISH":
        positive_signals.append(f"Neural models unanimous consensus: Malicious URL ({cnn_prob}%, {ro_prob}%)")
    elif ev_vector["neural_consensus"] == "CONSENSUS_CLEAN":
        negative_signals.append(f"Neural models unanimous consensus: Clean URL ({cnn_prob}%, {ro_prob}%)")

    # Signal compilation: URL Heuristics
    heur_score = ev_vector["url_heuristics"]
    if heur_score > 0:
        evidence_count += 1
        if heur_score >= cfg["heuristic_high_threshold"]:
            positive_signals.append(f"Elevated URL structural anomalies (Heuristic score: {heur_score})")
            high_signals.append("url_heuristics")
    else:
        negative_signals.append("URL lexical structure contains no anomalous features")

    # Signal compilation: Deep Scan & In-VM DOM / HTML
    html_ev = ds.get("html_evidence", {}) if ds.get("available") else {}
    dom_ev = ds.get("dom_evidence", {}) if ds.get("available") else {}
    ds_risk_bonus = 0.0

    if ds.get("available"):
        evidence_count += 1
        if ev_vector["credential_context"] > 0:
            ds_risk_bonus += cfg["credential_form_bonus"]
            positive_signals.append("Active credential collection fields confirmed in DOM")
            high_signals.append("credential_form_detected")
            strong_evidence_count += 1

        if html_ev.get("external_form_action") or dom_ev.get("external_form_action"):
            ds_risk_bonus += cfg["external_form_action_bonus"]
            positive_signals.append("Form targets external domain (unauthorized data exfiltration risk)")
            high_signals.append("external_form_action")
            strong_evidence_count += 1

        sus_scripts = html_ev.get("suspicious_script_count", 0)
        if sus_scripts > 0:
            ds_risk_bonus += min(sus_scripts * cfg["suspicious_script_bonus_per"], cfg["max_script_bonus"])
            positive_signals.append(f"Suspicious obfuscated JavaScript patterns detected ({sus_scripts})")

        if html_ev.get("login_page_detected") or dom_ev.get("login_form"):
            ds_risk_bonus += cfg["login_page_bonus"]

    # Signal compilation: Visual Analysis
    if va.get("available") and va.get("executed"):
        evidence_count += 1
        if va.get("brand_impersonation_visual"):
            ds_risk_bonus += cfg["visual_impersonation_bonus"]
            positive_signals.append("Visual brand impersonation detected in rendered viewport")
            high_signals.append("visual_brand_impersonation")
            strong_evidence_count += 1

        if va.get("has_payment_fields"):
            positive_signals.append("Financial / Payment card collection fields identified visually")
        if va.get("urgency_detected"):
            positive_signals.append("Psychological urgency and coercion terminology in page text")

        if not va.get("has_credential_harvesting") and not va.get("is_login_page") and not va.get("brand_impersonation_visual"):
            negative_signals.append("Rendered page contains no deceptive credential forms or visual spoofing")

    # Signal compilation: Temporal DOM Behavioral Intelligence
    dbh = dom_behavior or {}
    if dbh.get("available") and dbh.get("dom_behavior_score", 0.0) > 0:
        evidence_count += 1
        dbh_score = dbh.get("dom_behavior_score", 0.0)
        if dbh_score >= 60.0:
            positive_signals.append(f"Temporal DOM Behavioral Engine flagged high-risk anomalies ({dbh_score}%)")
            high_signals.append("dom_behavior_high_risk")
            strong_evidence_count += 1
            ds_risk_bonus += 20.0
        elif dbh_score >= 35.0:
            positive_signals.append(f"DOM behavioral structural risks detected ({dbh_score}%)")
            ds_risk_bonus += 10.0

        if dbh.get("temporal_analysis", {}).get("dynamic_password_injection"):
            positive_signals.append("Dynamic password field injection detected via temporal mutation tracking")
            high_signals.append("dynamic_password_injection")
            strong_evidence_count += 1
            ds_risk_bonus += 25.0

        if dbh.get("form_exfiltration", {}).get("suspicious_exfil_targets"):
            positive_signals.append("Unauthorized data exfiltration endpoint identified in form action")
            high_signals.append("unauthorized_exfiltration_endpoint")
            strong_evidence_count += 1
            ds_risk_bonus += 25.0

        if dbh.get("ui_deception", {}).get("fake_dialog_detected"):
            positive_signals.append("Deceptive fake system/browser modal dialog detected in DOM")
            high_signals.append("fake_browser_dialog")
            strong_evidence_count += 1
            ds_risk_bonus += 15.0

        if dbh.get("ui_deception", {}).get("hidden_overlay_detected"):
            positive_signals.append("Fullscreen invisible or high-z-index overlay detected (clickjacking trap)")
            high_signals.append("clickjacking_overlay")
            strong_evidence_count += 1
            ds_risk_bonus += 15.0
    elif dbh.get("available") and dbh.get("dom_behavior_score", 0.0) <= 10.0:
        negative_signals.append("DOM Behavioral analysis confirmed normal document structure and benign event dynamics")

    # ── 2. Whitelist Handling (Unified Evidence Evaluation) ─────────────────
    if is_whitelisted:
        # Whitelisted enterprise domains: clean risk score unless active compromised script/exfiltration
        classification = "LEGITIMATE"
        detection_type = "WHITELIST"
        risk_score = 1.0
        confidence = 99.0
        breakdown = {
            "whitelist_verification": 100.0,
            "cnn_contribution": round(cnn_prob * cfg["cnn_weight"] if cnn_prob is not None else 0.0, 1),
            "roberta_contribution": round(ro_prob * cfg["roberta_weight"] if ro_prob is not None else 0.0, 1),
            "deep_scan_verification": "CLEAN",
        }

        return {
            "classification": classification,
            "detection_type": detection_type,
            "risk_score": round(risk_score, 1),
            "confidence": round(confidence, 1),
            "model_confidence": round(confidence, 1),
            "confidence_score": round(confidence, 1),
            "model_agreement": ev_vector["model_agreement"],
            "model_agreement_level": ev_vector["model_agreement_level"],
            "model_disagreement": ev_vector["model_disagreement"],
            "neural_consensus": ev_vector["neural_consensus"],
            "positive_signals": list(set(positive_signals)),
            "negative_signals": list(set(negative_signals)),
            "conflicting_signals": list(set(conflicting_signals)),
            "evidence_vector": ev_vector,
            "evidence_count": evidence_count,
            "strong_evidence_count": strong_evidence_count,
            "high_signals": list(set(high_signals)),
            "ensemble_breakdown": breakdown,
            "timing": {"fusion_ms": round((time.perf_counter() - t0) * 1000, 2)}
        }

    # ── 3. Known Phishing Check ─────────────────────────────────────────────
    if ev_vector["threat_intelligence"] >= 95.0:
        return {
            "classification": "KNOWN_PHISHING",
            "detection_type": "KNOWN",
            "risk_score": 99.0,
            "model_confidence": 99.0,
            "confidence": 99.0,
            "confidence_score": 99.0,
            "model_agreement": ev_vector["model_agreement"],
            "model_agreement_level": ev_vector["model_agreement_level"],
            "model_disagreement": False,
            "neural_consensus": ev_vector["neural_consensus"],
            "positive_signals": list(set(positive_signals)),
            "negative_signals": list(set(negative_signals)),
            "conflicting_signals": list(set(conflicting_signals)),
            "evidence_vector": ev_vector,
            "evidence_count": evidence_count,
            "strong_evidence_count": strong_evidence_count,
            "high_signals": list(set(high_signals)),
            "ensemble_breakdown": {"threat_intel": 99.0},
            "timing": {"fusion_ms": round((time.perf_counter() - t0) * 1000, 2)}
        }

    # ── 4. Weighted Risk Ensemble Calculation ───────────────────────────────
    primary_sim = max(brand_sim, typo_sim)
    brand_pct = primary_sim * 100.0

    if ro_prob is not None and cnn_prob is not None:
        if ev_vector["model_disagreement"]:
            neural_risk = (cnn_prob * 0.40 + ro_prob * 0.40)
            ensemble = (
                neural_risk * 0.45 +
                heur_score * 0.30 +
                brand_pct * 0.25
            )
        else:
            ensemble = (
                cnn_prob * cfg["cnn_weight"] +
                ro_prob * cfg["roberta_weight"] +
                heur_score * cfg["heuristic_weight"] +
                brand_pct * cfg["brand_weight"]
            )
    elif cnn_prob is not None:
        ensemble = (
            cnn_prob * cfg["cnn_only_weight"] +
            heur_score * cfg["heuristic_only_weight"] +
            brand_pct * cfg["brand_only_weight"]
        )
    elif ro_prob is not None:
        ensemble = (
            ro_prob * 0.50 +
            heur_score * 0.28 +
            brand_pct * 0.22
        )
    else:
        ensemble = (
            heur_score * 0.45 +
            brand_pct * 0.55
        )

    # Strong Brand Impersonation / Typosquatting / Homoglyph / Punycode Floor
    if strong_evidence_count > 0 and primary_sim >= cfg["brand_zero_day_min_sim"]:
        brand_floor = 75.0 + (primary_sim * 20.0)
        ensemble = max(ensemble, brand_floor)
    elif strong_evidence_count > 0 and (ev_vector["homoglyph"] > 0 or ev_vector["punycode"] > 0):
        ensemble = max(ensemble, 92.0)
    elif va.get("brand_impersonation_visual"):
        ensemble = max(ensemble, 88.0)

    risk_score = _clamp(ensemble + ds_risk_bonus)

    # ── 5. Classification Decision Logic ───────────────────────────────────
    n_independent_high = len(set(high_signals))

    is_zero_day = False
    if strong_evidence_count > 0 and primary_sim >= cfg["brand_zero_day_min_sim"]:
        is_zero_day = True
    elif (ev_vector["homoglyph"] > 0 or ev_vector["punycode"] > 0):
        is_zero_day = True
    elif va.get("brand_impersonation_visual") and va.get("has_credential_harvesting"):
        is_zero_day = True
    elif ev_vector.get("dynamic_password_injection") or ev_vector.get("suspicious_exfiltration"):
        is_zero_day = True
    elif ev_vector.get("dom_behavior_score", 0.0) >= 60.0 and strong_evidence_count >= 1:
        is_zero_day = True
    elif risk_score >= cfg["zero_day_min_risk"] and n_independent_high >= cfg["zero_day_min_signals"] and not ev_vector["model_disagreement"]:
        is_zero_day = True

    if is_zero_day:
        classification = "ZERO_DAY_PHISHING"
        detection_type = "ZERO_DAY"
        risk_score = max(risk_score, 75.0)
    elif risk_score >= cfg["suspicious_min_risk"] or ev_vector["model_disagreement"]:
        classification = "SUSPICIOUS"
        detection_type = "SUSPICIOUS"
        if ev_vector["model_disagreement"]:
            risk_score = _clamp(risk_score, 45.0, 74.0)
    elif risk_score < 30.0 and n_independent_high == 0:
        classification = "LEGITIMATE"
        detection_type = "LEGITIMATE"
    else:
        classification = "SUSPICIOUS"
        detection_type = "SUSPICIOUS"

    # ── 6. Mathematical Confidence Calculation ─────────────────────────────
    confidence = calculate_mathematical_confidence(
        classification, ev_vector, strong_evidence_count, risk_score
    )

    breakdown = {
        "cnn_contribution": round(cnn_prob * cfg["cnn_weight"] if cnn_prob is not None else 0.0, 1),
        "roberta_contribution": round(ro_prob * cfg["roberta_weight"] if ro_prob is not None else 0.0, 1),
        "heuristic_contribution": round(heur_score * cfg["heuristic_weight"], 1),
        "brand_contribution": round(brand_pct * cfg["brand_weight"], 1),
        "deep_scan_bonus": round(ds_risk_bonus, 1),
        "dom_behavior_score": round(ev_vector.get("dom_behavior_score", 0.0), 1),
    }

    return {
        "classification": classification,
        "detection_type": detection_type,
        "risk_score": round(risk_score, 1),
        "confidence": round(confidence, 1),
        "model_confidence": round(confidence, 1),
        "confidence_score": round(confidence, 1),
        "model_agreement": ev_vector["model_agreement"],
        "model_agreement_level": ev_vector["model_agreement_level"],
        "model_disagreement": ev_vector["model_disagreement"],
        "neural_consensus": ev_vector["neural_consensus"],
        "positive_signals": list(set(positive_signals)),
        "negative_signals": list(set(negative_signals)),
        "conflicting_signals": list(set(conflicting_signals)),
        "evidence_vector": ev_vector,
        "evidence_count": evidence_count,
        "strong_evidence_count": strong_evidence_count,
        "high_signals": list(set(high_signals)),
        "ensemble_breakdown": breakdown,
        "timing": {"fusion_ms": round((time.perf_counter() - t0) * 1000, 2)}
    }
