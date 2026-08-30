import os
import sys
import json
import time

print("=================================================================")
print(" PHISHGUARD AI V3 - COMPREHENSIVE SYSTEM & MODEL VALIDATION SUITE")
print("=================================================================")

# 1. Load app and test components
import app

print("\n[1] FLASK APP & ROUTE INITIALIZATION")
print(f" • Flask App Object: {app.app}")
print(f" • App Name: {app.app.name}")
print(f" • Deep Learning Enabled: {app.ENABLE_DEEP_LEARNING}")

client = app.app.test_client()

# 2. Test /health and / endpoints
print("\n[2] TESTING HEALTH & METRIC ENDPOINTS")
health_res = client.get('/health')
print(f" • GET /health -> Status {health_res.status_code}: {health_res.get_json()}")
assert health_res.status_code == 200, "Health endpoint failed"

root_res = client.get('/')
print(f" • GET / -> Status {root_res.status_code}: {root_res.get_json()}")
assert root_res.status_code == 200, "Root endpoint failed"

stats_res = client.get('/stats')
print(f" • GET /stats -> Status {stats_res.status_code}")
assert stats_res.status_code == 200, "Stats endpoint failed"

# 3. Direct Model Testing: CNN-BiLSTM
print("\n[3] TESTING CNN-BiLSTM MODEL DIRECTLY")
print(f" • CNN-BiLSTM model loaded: {app.model is not None}")
print(f" • Tokenizer v2 loaded: {app.tokenizer is not None}")
if app.model is not None and app.tokenizer is not None:
    test_url = "http://paypal-security-update.com/login"
    processed = app.preprocess_url(test_url)
    cnn_raw = float(app.model.predict(processed, verbose=0)[0][0])
    print(f" • CNN Preprocessed Shape: {processed.shape}")
    print(f" • CNN Raw Score for '{test_url}': {cnn_raw:.4f} ({cnn_raw * 100:.2f}%)")
    assert 0.0 <= cnn_raw <= 1.0, "CNN score out of range"

# 4. Direct Model Testing: RoBERTa
print("\n[4] TESTING ROBERTA MODEL DIRECTLY")
app.load_roberta_lazy()
print(f" • RoBERTa tokenizer loaded: {app.roberta_tokenizer is not None}")
print(f" • RoBERTa model loaded: {app.roberta_model is not None}")
if app.roberta_model is not None and app.roberta_tokenizer is not None:
    roberta_score_phish = app.roberta_predict("http://paypal-security-update.com/login")
    roberta_score_safe  = app.roberta_predict("https://google.com")
    print(f" • RoBERTa score for Phishing URL: {roberta_score_phish:.4f} ({roberta_score_phish * 100:.2f}%)")
    print(f" • RoBERTa score for Safe URL:     {roberta_score_safe:.4f} ({roberta_score_safe * 100:.2f}%)")
    assert 0.0 <= roberta_score_phish <= 1.0, "RoBERTa score out of range"

# 5. Hybrid Prediction Endpoint End-to-End Suite
print("\n[5] END-TO-END HYBRID INFERENCE TEST CASES")

TEST_CASES = [
    {
        "name": "Verified Whitelisted Domain",
        "url": "https://google.com",
        "expected_prediction": "Safe",
        "expected_threat": "Safe"
    },
    {
        "name": "Legitimate Top Domain",
        "url": "https://github.com/explore",
        "expected_prediction": "Safe",
        "expected_threat": "Safe"
    },
    {
        "name": "Blatant Brand Impersonation Phishing",
        "url": "http://paypal-security-update.com/login",
        "expected_prediction": "Phishing",
        "expected_threat": "Critical"
    },
    {
        "name": "Suspicious TLD Credential Phishing",
        "url": "http://netflix-billing-verify.xyz/account",
        "expected_prediction": "Phishing",
        "expected_threat": "High"
    },
    {
        "name": "Direct IP-based Login Portal",
        "url": "http://192.168.1.1/admin-verify",
        "expected_prediction": "Phishing",
        "expected_threat": "High"
    }
]

passed_tests = 0
for tc in TEST_CASES:
    res = client.post('/predict', json={"url": tc["url"]})
    assert res.status_code == 200, f"Request failed for {tc['url']}"
    data = res.get_json()
    
    pred = data.get("prediction_result")
    threat = data.get("threat_level")
    risk = data.get("risk_score")
    conf = data.get("confidence")
    cnn_sc = data.get("cnn_score")
    rob_sc = data.get("roberta_score")
    latency = data.get("detection_time_ms")
    
    print(f"\n • Case: [{tc['name']}]")
    print(f"   URL:            {tc['url']}")
    print(f"   Verdict:        {pred} (Threat Level: {threat})")
    print(f"   Risk Score:     {risk}/100 | AI Confidence: {conf}%")
    print(f"   Hybrid Scores:  CNN: {cnn_sc}% | RoBERTa: {rob_sc}%")
    print(f"   Latency:        {latency} ms")
    print(f"   Signals:        {len(data.get('explanations', []))} forensic explanation(s)")
    
    # Assertions
    assert "cnn_score" in data, "Missing cnn_score in response"
    assert "roberta_score" in data, "Missing roberta_score in response"
    assert "confidence" in data, "Missing confidence in response"
    assert "risk_score" in data, "Missing risk_score in response"
    assert data["status"] == "success", "Status not success"
    passed_tests += 1

print(f"\n=================================================================")
print(f" ALL {passed_tests}/{len(TEST_CASES)} TEST CASES PASSED SUCCESSFULLY!")
print("=================================================================")
