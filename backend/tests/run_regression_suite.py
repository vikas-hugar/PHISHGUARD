"""
PhishGuard AI — 8 URL Types Regression Test Suite
Executes safe regression tests for Task 6 across:
1. Known legitimate URL
2. Suspicious-looking URL
3. Known phishing URL from repository / test fixtures
4. Zero-day synthetic phishing URL
5. Credential-collection URL behavior
6. Redirect URL
7. Malformed URL
8. Private / internal IP URL
"""
import urllib.request
import json
import time

tests = [
    ("1. Known Legitimate", "https://example.com", "deep"),
    ("2. Suspicious Looking", "http://paypal-security-update-verification.com/login", "quick"),
    ("3. Known Phishing (fixture)", "http://chase-bank-verify-account-update.com/login", "quick"),
    ("4. Zero-day Synthetic", "http://netflix-billing-renew-reactivate-2026.net/signin", "quick"),
    ("5. Credential Collection", "http://bank-account-security-token-entry.com/otp-verify", "quick"),
    ("6. Redirect URL", "https://google.com", "deep"),
    ("7. Malformed URL", "htp://invalid url with spaces", "quick"),
    ("8. Private IP URL", "http://192.168.1.1/admin", "deep")
]

results = []

for name, url, mode in tests:
    print("=" * 60)
    print(f"TEST: {name} | Mode: {mode} | URL: {url}")
    t0 = time.perf_counter()
    data = json.dumps({"url": url, "scan_mode": mode}).encode()
    req = urllib.request.Request(
        "http://localhost:5000/predict",
        data=data,
        headers={"Content-Type": "application/json"}
    )
    try:
        res = urllib.request.urlopen(req, timeout=35)
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
        obj = json.loads(res.read().decode())
        print(f"  HTTP Code: 200 (in {elapsed_ms} ms)")
        print(f"  Classification: {obj.get('classification')}")
        print(f"  Risk Level: {obj.get('risk_level')} (Score: {obj.get('risk_score')})")
        print(f"  Confidence: {obj.get('confidence')}")
        print(f"  CNN Score: {obj.get('cnn_score')}, RoBERTa Score: {obj.get('roberta_score')}")
        print(f"  Model Agreement: {obj.get('model_agreement')}")
        if mode == "deep":
            sb = obj.get("signals", {}).get("sandbox", {})
            scr = obj.get("signals", {}).get("screenshot", {})
            print(f"  Deep Scan Success: {sb.get('success')}, Final URL: {sb.get('final_url')}, Redirects: {sb.get('redirect_count')}")
            print(f"  OCR Available: {scr.get('ocr_available')}, Word Count: {scr.get('ocr_word_count')}, Error: {scr.get('error')}")
            if scr.get("visual_text_preview"):
                print(f"  Visual Text Preview: {repr(scr.get('visual_text_preview')[:120])}")
        results.append((name, "SUCCESS", obj.get("classification"), obj.get("risk_level")))
    except urllib.error.HTTPError as e:
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
        err_body = e.read().decode()
        print(f"  HTTP Error: {e.code} (in {elapsed_ms} ms) - {err_body[:200]}")
        results.append((name, f"HTTP_{e.code}", "BLOCKED_OR_REJECTED", "Safe/Rejected"))
    except Exception as e:
        print(f"  Exception: {e}")
        results.append((name, "ERROR", str(e), "Failed"))

print("\n" + "=" * 60)
print("REGRESSION TEST SUMMARY:")
for name, status, cls, risk in results:
    print(f"  [{status}] {name}: {cls} ({risk})")
print("=" * 60)
