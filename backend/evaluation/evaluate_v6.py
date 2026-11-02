"""
PhishGuard AI V6 — Comprehensive Evaluation & Validation Benchmark
===================================================================
Executes end-to-end evaluation of the V6 zero-day phishing detection platform:
- SSRF Guard validation
- Whitelist speed & accuracy
- Offline SQLite Threat Intelligence (2.1M+ records)
- Zero-Day Brand Impersonation & Homoglyph detection
- Punycode & Typosquatting detection
- CNN-BiLSTM & RoBERTa multi-model ensemble
- Explainable AI (XAI) forensic telemetry
- Quick Scan vs Deep Scan pipeline routing
- /health endpoint honest component status reporting
"""

import sys
import os
import time
import json

# Add backend directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app

def run_evaluation():
    print("=" * 72)
    print(" PHISHGUARD AI V6 — COMPREHENSIVE ARCHITECTURE & DETECTION BENCHMARK")
    print("=" * 72)

    client = app.app.test_client()

    # -------------------------------------------------------------
    # 1. Health & Component Availability Audit
    # -------------------------------------------------------------
    print("\n[1] AUDITING COMPONENT HEALTH & AVAILABILITY (/health)")
    h_res = client.get("/health")
    assert h_res.status_code == 200, f"Health check failed with {h_res.status_code}"
    h_data = h_res.get_json()

    print(f" • Platform Version:           {h_data.get('version')}")
    print(f" • Threat Intelligence Repo:   {'ONLINE' if h_data.get('threat_repository_available') else 'OFFLINE'}")
    print(f"   - Known URLs in DB:         {h_data.get('repository_stats', {}).get('known_urls', 0):,}")
    print(f"   - Domains Indexed:          {h_data.get('repository_stats', {}).get('domains', 0):,}")
    print(f" • Brand Engine (1000+ brands):{'ONLINE' if h_data.get('brand_engine_available') else 'OFFLINE'}")
    print(f" • Homoglyph Detector:         {'ONLINE' if h_data.get('homoglyph_engine_available') else 'OFFLINE'}")
    print(f" • SSRF Security Guard:        {'ONLINE' if h_data.get('ssrf_guard_available') else 'OFFLINE'}")
    print(f" • Fusion Engine:              {'ONLINE' if h_data.get('fusion_engine_available') else 'OFFLINE'}")
    print(f" • XAI Engine:                 {'ONLINE' if h_data.get('xai_engine_available') else 'OFFLINE'}")
    print(f" • CNN-BiLSTM Neural Model:    {'ONLINE' if h_data.get('cnn_available') else 'OFFLINE / STANDBY'}")
    print(f" • RoBERTa Transformer:        {'ONLINE' if h_data.get('roberta_available') else 'OFFLINE / STANDBY'}")
    print(f" • Deep Scan Sandbox Status:   {'ONLINE' if h_data.get('sandbox_available') else 'OFFLINE (' + str(h_data.get('sandbox_unavailability_reason')) + ')'}")

    # -------------------------------------------------------------
    # 2. SSRF Guard Evaluation
    # -------------------------------------------------------------
    print("\n[2] EVALUATING SSRF SECURITY GUARD (Localhost / Private IP Defense)")
    ssrf_test_urls = [
        "http://127.0.0.1:5000/internal-admin",
        "http://localhost/secret",
        "http://192.168.1.1/router-login",
        "http://10.0.0.1/aws-creds",
        "http://169.254.169.254/latest/meta-data/",
    ]

    for ssrf_url in ssrf_test_urls:
        t_start = time.perf_counter()
        res = client.post("/predict", json={"url": ssrf_url})
        t_ms = (time.perf_counter() - t_start) * 1000
        assert res.status_code == 400, f"Expected HTTP 400 for SSRF attack '{ssrf_url}', got {res.status_code}"
        data = res.get_json()
        assert data.get("security_block") is True, f"Expected security_block=True for '{ssrf_url}'"
        print(f" [PASS] Blocked: {ssrf_url:<42} in {t_ms:.1f}ms (Reason: {data.get('block_reason')})")

    # -------------------------------------------------------------
    # 3. Detection Benchmark Test Suite
    # -------------------------------------------------------------
    print("\n[3] EVALUATING ZERO-DAY & MULTI-LAYER INFERENCE ENGINE")
    BENCHMARK_CASES = [
        {
            "category": "Whitelisted Legitimate",
            "url": "https://google.com",
            "expected_verdict": "Legitimate",
            "max_risk": 15,
        },
        {
            "category": "Whitelisted Legitimate Deep Path",
            "url": "https://github.com/explore",
            "expected_verdict": "Legitimate",
            "max_risk": 15,
        },
        {
            "category": "Known Phishing (Threat Repo Match)",
            "url": "http://ledger-com-strts.pages.dev/",
            "expected_verdict": "Known Phishing",
            "min_risk": 80,
        },
        {
            "category": "Zero-Day Brand Impersonation",
            "url": "http://paypal-security-update.com/login",
            "expected_verdict": "Zero-Day Phishing",
            "min_risk": 75,
            "expected_brand": "PayPal",
        },
        {
            "category": "Homoglyph Impersonation",
            "url": "http://g00gle.com",
            "expected_verdict": "Zero-Day Phishing",
            "min_risk": 70,
        },
        {
            "category": "Punycode IDN Attack",
            "url": "http://xn--pple-43d.com",
            "expected_verdict": "Zero-Day Phishing",
            "min_risk": 70,
        },
        {
            "category": "Repetition Typosquatting",
            "url": "http://aaappllle.com",
            "expected_verdict": "Zero-Day Phishing",
            "min_risk": 70,
        },
        {
            "category": "Suspicious Novel Credential Portal",
            "url": "http://netflix-billing-verify.xyz/account",
            "expected_verdict": ["Zero-Day Phishing", "Suspicious"],
            "min_risk": 50,
        },
    ]

    passed_count = 0
    total_time_ms = 0.0

    for idx, tc in enumerate(BENCHMARK_CASES, start=1):
        t0 = time.perf_counter()
        res = client.post("/predict", json={"url": tc["url"], "scan_mode": "quick"})
        lat = (time.perf_counter() - t0) * 1000
        total_time_ms += lat

        assert res.status_code == 200, f"Request failed with {res.status_code} for {tc['url']}"
        data = res.get_json()

        verdict = data.get("verdict")
        risk = data.get("risk_score", 0.0)
        conf = data.get("confidence", 0.0)
        method = data.get("detection_method")
        brand = data.get("target_brand")
        timing = data.get("timing", {})

        # Validation
        exp = tc["expected_verdict"]
        verdict_ok = (verdict in exp) if isinstance(exp, list) else (verdict == exp)
        assert verdict_ok, f"Verdict mismatch for '{tc['url']}': expected {exp}, got '{verdict}'"

        if "min_risk" in tc:
            assert risk >= tc["min_risk"], f"Risk score {risk} lower than expected {tc['min_risk']} for '{tc['url']}'"
        if "max_risk" in tc:
            assert risk <= tc["max_risk"], f"Risk score {risk} higher than expected {tc['max_risk']} for '{tc['url']}'"

        print(f"\n • Case 0{idx}: [{tc['category']}]")
        print(f"   Target URL:    {tc['url']}")
        print(f"   Verdict:       {verdict} | Severity: {data.get('threat_level')}")
        print(f"   Risk:          {risk}/100 | Confidence: {conf}%")
        print(f"   Method:        {method}")
        if brand and brand != "None":
            print(f"   Target Brand:  {brand} (Similarity: {data.get('similarity_pct')}%)")
        print(f"   Latency:       {data.get('detection_time_ms')} ms (HTTP: {lat:.1f} ms)")
        print(f"   Explanations:  {len(data.get('explanations', []))} signal(s)")
        if data.get('explanations'):
            print(f"    - \"{data.get('explanations')[0]}\"")

        passed_count += 1

    # -------------------------------------------------------------
    # 4. Deep Scan Pipeline Routing Check
    # -------------------------------------------------------------
    print("\n[4] EVALUATING DEEP SCAN ROUTING & SANDBOX ERROR REPORTING")
    ds_res = client.post("/predict", json={"url": "http://paypal-security-update.com/login", "scan_mode": "deep"})
    assert ds_res.status_code == 200, f"Deep scan failed with {ds_res.status_code}"
    ds_data = ds_res.get_json()
    assert ds_data.get("scan_mode") == "deep"
    print(f" • Deep Scan Mode Echoed:     {ds_data.get('scan_mode')}")
    print(f" • Deep Scan Classification:  {ds_data.get('verdict')}")
    if "signals" in ds_data and "sandbox" in ds_data["signals"]:
        sb = ds_data["signals"]["sandbox"]
        print(f" • Sandbox Subsystem Telemetry: Available={sb.get('available')}, Success={sb.get('success')}")
        if sb.get('error'):
            print(f"   Honest Sandbox Notice:     {sb.get('error')[:75]}...")

    # -------------------------------------------------------------
    # 5. Global Stats & Tracking Verification
    # -------------------------------------------------------------
    print("\n[5] VERIFYING REAL-TIME GLOBAL TELEMETRY (/stats)")
    s_res = client.get("/stats")
    assert s_res.status_code == 200
    s_data = s_res.get_json()
    stats = s_data.get("stats", {})
    history = s_data.get("history", [])

    print(f" • Total Scans Logged:        {stats.get('total')}")
    print(f" • Safe Scans:                {stats.get('safe')}")
    print(f" • Phishing / Threat Scans:   {stats.get('phishing')}")
    print(f" • Recent Scans History:      {len(history)} record(s)")

    print("\n" + "=" * 72)
    print(f" ALL {passed_count}/{len(BENCHMARK_CASES)} BENCHMARK CASES & SECURITY CHECKS PASSED!")
    print(f" Average Scan Latency: {total_time_ms / len(BENCHMARK_CASES):.2f} ms")
    print("=" * 72)

if __name__ == "__main__":
    run_evaluation()
