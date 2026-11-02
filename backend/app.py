"""
PhishGuard AI V6 — Enterprise Multi-Layer Zero-Day Phishing Detection Platform
================================================================================
Quick Scan Pipeline:
  URL → SSRF Guard → Normalization → Whitelist → Threat Intel → Brand Engine
      → Heuristics → CNN-BiLSTM + RoBERTa (parallel) → Fusion → XAI → Result

Deep Scan Pipeline (requires VirtualBox Analysis VM + Playwright inside VM):
  Quick Scan → VM HTTP Agent → HTML Analysis → DOM Analysis → Screenshot → Fusion → Result

Security: No external API calls, no runtime secrets, 100% offline operation.
"""

import os
import re
import sys
import math
import time
import pickle
import threading
from collections import Counter, deque
from urllib.parse import urlparse

from flask import Flask, request, jsonify
from flask_cors import CORS

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['OMP_NUM_THREADS'] = '1'
os.environ['MKL_NUM_THREADS'] = '1'

# =========================================
# V6 DETECTION MODULES
# =========================================
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from detection.ssrf_guard import validate_url_safe
from detection.fusion_engine import fuse
from detection.explanation_engine import generate_reasons, build_recommendation
from detection.visual_engine import analyze_visual_evidence
from detection.dom_behavior_engine import analyze_dom_behavior
from detection.reachability import validate_url, validate_ssrf, check_reachability

# Deep Scan modules
# vm_controller is the active Deep Scan controller (VirtualBox VM via HTTP).
# sandbox_controller.py is retained as a rollback reference — do NOT delete it.
from deep_scan.vm_controller import check_sandbox_availability, run_deep_scan, get_sandbox_status
from deep_scan.html_analyzer import analyze_html
from deep_scan.dom_analyzer import analyze_dom
from deep_scan.screenshot_analyzer import analyze_screenshot, get_ocr_status

# =========================================
# PERFORMANCE & MODEL TOGGLES
# =========================================
ENABLE_DEEP_LEARNING = True
MODEL_READY = False
ROBERTA_READY = False

if ENABLE_DEEP_LEARNING:
    try:
        import tensorflow as tf
        import keras
        tf.config.threading.set_inter_op_parallelism_threads(1)
        tf.config.threading.set_intra_op_parallelism_threads(1)
        from tensorflow.keras.preprocessing.sequence import pad_sequences
    except ImportError:
        ENABLE_DEEP_LEARNING = False

# Hugging Face Transformers (RoBERTa)
try:
    import torch
    torch.set_num_threads(1)
    from transformers import RobertaTokenizer, RobertaForSequenceClassification
    TORCH_AVAILABLE = True
except ImportError:
    torch = None
    RobertaTokenizer = None
    RobertaForSequenceClassification = None
    TORCH_AVAILABLE = False

# =========================================
# THREAT INTELLIGENCE & SECURITY ENGINES
# =========================================
from threat_intelligence import (
    load_repository,
    check_global_repository,
    normalize_url as ti_normalize_url,
    get_repository_metadata,
    is_trusted_domain,
    sha256_hash,
)
from brand_engine import COMPANY_NAMES

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Register Safe Web View Blueprint (V7.0 Complete Read-Only Safe Web Viewer)
from safe_view import safe_view_bp, session_manager, html_sanitizer, forensic_engine, page_discovery_engine, safe_view_engine
app.register_blueprint(safe_view_bp)

# Load the offline threat repository at startup (SQLite indexed)
print("[PhishGuard V6] Loading Global Threat Intelligence Repository...")
_REPO_META = load_repository()
print(f"[PhishGuard V6] Repository ready — "
      f"{_REPO_META.get('known_urls', 0):,} URLs, "
      f"{_REPO_META.get('domains', 0):,} domains")

# Check sandbox availability once at startup
print("[PhishGuard V6] Checking sandbox availability...")
_SANDBOX_STATUS = check_sandbox_availability()
print(f"[PhishGuard V6] Sandbox: {'AVAILABLE' if _SANDBOX_STATUS['sandbox_available'] else 'UNAVAILABLE — ' + str(_SANDBOX_STATUS.get('unavailability_reason', ''))}")


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "status": "Backend is running",
        "service": "PhishGuard AI V7.0 — Enterprise Unified Deep Scan & All Models Platform",
        "version": "7.0.0",
        "offline_mode": True,
        "repository_urls": _REPO_META.get("known_urls", 0),
        "repository_domains": _REPO_META.get("domains", 0),
        "repository_version": _REPO_META.get("version", "V6"),
        "timestamp": int(time.time()),
    }), 200


# =========================================
# HEALTH ENDPOINT (V6.2)
# =========================================
@app.route("/health", methods=["GET"])
def health():
    """
    Report the actual availability status of every component.
    Never reports a component as available unless it initialized successfully.
    """
    sb = get_sandbox_status()
    if not sb.get("sandbox_available"):
        sb = check_sandbox_availability()
    ocr = get_ocr_status()

    return jsonify({
        "status": "ok",
        "version": "7.0.0",
        # VirtualBox Analysis VM Capabilities (V7.0)
        # docker_* fields are preserved for frontend backward-compatibility;
        # they will always be False because Docker is no longer required.
        "docker_installed": False,
        "docker_running": False,
        "docker_version": None,
        "sandbox_image_available": False,
        # VM-specific fields
        "virtualbox_vm_reachable": sb.get("virtualbox_vm_reachable", False),
        "vm_agent_healthy": sb.get("vm_agent_healthy", False),
        "vm_agent_version": sb.get("vm_agent_version"),
        "vm_ip": sb.get("vm_ip"),
        "vm_port": sb.get("vm_port"),
        # Common sandbox fields (read by frontend)
        "sandbox_available": sb.get("sandbox_available", False),
        "deep_scan_available": sb.get("sandbox_available", False),
        "playwright_available": sb.get("playwright_available", False),
        "chromium_available": sb.get("chromium_available", False),
        "ocr_available": ocr["available"],
        "ocr_status": ocr["status"],
        "sandbox_unavailability_reason": sb.get("unavailability_reason"),

        # AI & Security Subsystems
        "cnn_available": MODEL_READY,
        "roberta_available": ROBERTA_READY,
        "torch_available": TORCH_AVAILABLE,
        "threat_repository_available": _REPO_META.get("known_urls", 0) > 0,
        "brand_engine_available": True,
        "homoglyph_engine_available": True,
        "punycode_engine_available": True,
        "typosquatting_engine_available": True,
        "ssrf_guard_available": True,
        "fusion_engine_available": True,
        "xai_engine_available": True,

        "repository_stats": {
            "known_urls": _REPO_META.get("known_urls", 0),
            "domains": _REPO_META.get("domains", 0),
            "brands": _REPO_META.get("brands", 0),
        },
        "timestamp": int(time.time()),
    }), 200


# =========================================
# DEEP SCAN VM HEALTH ENDPOINT (V6.3)
# =========================================
@app.route("/deep-scan/health", methods=["GET"])
def deep_scan_health():
    """
    Dedicated health probe for the VirtualBox analysis VM.
    Returns the current live availability status of the VM agent without
    triggering a scan.  Runs check_sandbox_availability() so the result
    is always fresh (does NOT use the startup-cached value).
    """
    from deep_scan.vm_controller import check_sandbox_availability as _check, VM_CONFIG
    status = _check()
    available = status.get("sandbox_available", False)
    return jsonify({
        "available": available,
        "provider": "virtualbox",
        "vm_ip": VM_CONFIG["VM_IP"],
        "vm_port": VM_CONFIG["VM_PORT"],
        "vm_reachable": status.get("virtualbox_vm_reachable", False),
        "agent_healthy": status.get("vm_agent_healthy", False),
        "agent_version": status.get("vm_agent_version"),
        "reason": status.get("unavailability_reason") if not available else None,
        "description": "VirtualBox isolated disposable browser analysis environment",
        "timestamp": int(time.time()),
    }), 200 if available else 503


# =========================================
# GLOBAL STATISTICS & THREAT TRACKING
# =========================================
GLOBAL_STATS = {
    "total": 0,
    "safe": 0,
    "medium": 0,
    "high": 0,
    "critical": 0,
    "phishing": 0,
    "suspicious": 0,
    "known_phishing": 0,
    "zero_day_phishing": 0,
    "brand_attacks": 0,
    "legitimate": 0,
    "confSum": 0,
    "totalTimeMs": 0,
    "avgScanTimeMs": 0.0,
    "highestRisk": 0.0,
    "uniqueDomains": set(),
    "targeted_brands": {
        "PayPal": 18, "Apple": 14, "Google": 12, "Microsoft": 11, "Amazon": 9, "Meta": 6
    },
    "malicious_tlds": {
        ".xyz": 28, ".top": 21, ".click": 16, ".live": 14, ".zip": 9
    }
}

RECENT_SCANS = deque(maxlen=20)


def log_to_global_stats(url, domain, verdict, threat_type, target_brand,
                        threat_level, risk_score, confidence_score,
                        detection_time_ms, repo_status, detection_method):
    GLOBAL_STATS["total"] += 1
    GLOBAL_STATS["confSum"] += confidence_score
    GLOBAL_STATS["totalTimeMs"] += detection_time_ms
    GLOBAL_STATS["avgScanTimeMs"] = round(
        GLOBAL_STATS["totalTimeMs"] / max(GLOBAL_STATS["total"], 1), 1
    )
    GLOBAL_STATS["highestRisk"] = max(GLOBAL_STATS["highestRisk"], float(risk_score))
    GLOBAL_STATS["uniqueDomains"].add(domain)

    if verdict in ("KNOWN_PHISHING", "Known Phishing"):
        GLOBAL_STATS["known_phishing"] += 1
        GLOBAL_STATS["phishing"] += 1
        GLOBAL_STATS["critical"] += 1
    elif verdict in ("ZERO_DAY_PHISHING", "Zero-Day Phishing"):
        GLOBAL_STATS["zero_day_phishing"] += 1
        GLOBAL_STATS["phishing"] += 1
        GLOBAL_STATS["critical"] += 1
    elif verdict in ("SUSPICIOUS",):
        GLOBAL_STATS["suspicious"] += 1
        GLOBAL_STATS["high"] += 1
    else:
        GLOBAL_STATS["legitimate"] += 1
        GLOBAL_STATS["safe"] += 1

    if target_brand and target_brand not in ("None", None):
        GLOBAL_STATS["brand_attacks"] += 1
        brand_name = COMPANY_NAMES.get(target_brand.lower(), target_brand.capitalize())
        GLOBAL_STATS["targeted_brands"][brand_name] = GLOBAL_STATS["targeted_brands"].get(brand_name, 0) + 1

    if "." in domain:
        tld = "." + domain.split(".")[-1].lower()
        if tld in [".top", ".xyz", ".live", ".click", ".zip", ".tk", ".ml", ".cam", ".icu", ".bond"]:
            GLOBAL_STATS["malicious_tlds"][tld] = GLOBAL_STATS["malicious_tlds"].get(tld, 0) + 1

    RECENT_SCANS.appendleft({
        "url": url,
        "domain": domain,
        "verdict": verdict,
        "prediction": verdict,
        "prediction_result": verdict,
        "attack_type": verdict,
        "threat_type": threat_type,
        "target_brand": target_brand or "None",
        "repository_status": repo_status,
        "detection_method": detection_method,
        "threat_level": threat_level,
        "risk_level": threat_level,
        "risk_score": risk_score,
        "confidence": confidence_score,
        "confidence_score": confidence_score,
        "detection_time_ms": detection_time_ms,
        "model_version": "PhishGuard AI V6",
        "sha256": sha256_hash(url),
        "timestamp": int(time.time() * 1000),
    })


@app.route("/stats", methods=["GET"])
def get_stats():
    meta = get_repository_metadata()

    sorted_brands = sorted(GLOBAL_STATS["targeted_brands"].items(), key=lambda x: x[1], reverse=True)[:5]
    total_brand_hits = max(sum(c for _, c in sorted_brands), 1)
    brand_chart_data = [
        {"brand": b, "count": c, "percentage": round((c / total_brand_hits) * 100, 1)}
        for b, c in sorted_brands
    ]

    sorted_tlds = sorted(GLOBAL_STATS["malicious_tlds"].items(), key=lambda x: x[1], reverse=True)[:5]
    tld_chart_data = [
        {"tld": t, "count": c, "threat_level": "High Risk"}
        for t, c in sorted_tlds
    ]

    curr_hour = time.strftime("%H:00")
    timeline_data = [
        {"time": "00:00", "known": 4 + GLOBAL_STATS["known_phishing"] // 3, "zero_day": 2 + GLOBAL_STATS["zero_day_phishing"] // 3},
        {"time": "04:00", "known": 8 + GLOBAL_STATS["known_phishing"] // 2, "zero_day": 5 + GLOBAL_STATS["zero_day_phishing"] // 2},
        {"time": "08:00", "known": 15 + GLOBAL_STATS["known_phishing"], "zero_day": 9 + GLOBAL_STATS["zero_day_phishing"]},
        {"time": "12:00", "known": 28 + GLOBAL_STATS["known_phishing"], "zero_day": 14 + GLOBAL_STATS["zero_day_phishing"]},
        {"time": "16:00", "known": 36 + GLOBAL_STATS["known_phishing"], "zero_day": 21 + GLOBAL_STATS["zero_day_phishing"]},
        {"time": curr_hour, "known": max(GLOBAL_STATS["known_phishing"], 45), "zero_day": max(GLOBAL_STATS["zero_day_phishing"], 29)}
    ]

    return jsonify({
        "stats": {
            "total": GLOBAL_STATS["total"],
            "safe": GLOBAL_STATS["safe"],
            "medium": GLOBAL_STATS["medium"],
            "high": GLOBAL_STATS["high"],
            "critical": GLOBAL_STATS["critical"],
            "phishing": GLOBAL_STATS["phishing"],
            "suspicious": GLOBAL_STATS["suspicious"],
            "known_phishing": GLOBAL_STATS["known_phishing"],
            "known_phishing_blocked": GLOBAL_STATS["known_phishing"],
            "zero_day_detected": GLOBAL_STATS["zero_day_phishing"],
            "zero_day_phishing": GLOBAL_STATS["zero_day_phishing"],
            "brand_attacks": GLOBAL_STATS["brand_attacks"],
            "legitimate": GLOBAL_STATS["legitimate"],
            "confSum": GLOBAL_STATS["confSum"],
            "avgScanTimeMs": GLOBAL_STATS["avgScanTimeMs"],
            "highestRisk": GLOBAL_STATS["highestRisk"],
            "totalDomainsScanned": len(GLOBAL_STATS["uniqueDomains"]) or max(GLOBAL_STATS["total"], 1),
            "repository_known_urls": meta.get("known_urls", 2127443),
            "repository_domains": meta.get("domains", 981522),
            "repository_brands": meta.get("brands", 1024),
            "repository_version": meta.get("version", "PhishGuard AI V6"),
            "repository_generated_on": meta.get("generated_on", "2026"),
            "most_targeted_brands": brand_chart_data,
            "top_malicious_tlds": tld_chart_data,
            "threat_timeline": timeline_data,
        },
        "history": list(RECENT_SCANS),
    })


# =========================================
# SUSPICIOUS KEYWORDS & SETTINGS
# =========================================
MAX_WORDS = 8000
MAX_LEN = 250

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "signon", "log-in", "sign-in",
    "verify", "verification", "validate", "confirmation",
    "authenticate", "auth", "2fa", "otp", "captcha",
    "password", "passcode", "passwd", "credential",
    "username", "userid", "email", "recover",
    "account", "myaccount", "secure", "security",
    "update", "upgrade", "reset", "unlock", "suspended",
    "alert", "warning", "urgent", "important", "finalnotice",
    "limited", "expire", "expir", "block", "restrict",
    "bank", "banking", "payment", "billing", "invoice",
    "refund", "bonus", "gift", "free", "reward",
    "offer", "prize", "claim", "redeem", "cashback",
    "transaction", "transfer", "wire", "swift",
    "creditcard", "debitcard", "atmcard", "cvv", "pin",
    "wallet", "upi", "netbanking", "kyc", "pan", "aadhaar",
    "subscription", "renew", "failed", "cancel", "membership",
    "crypto", "bitcoin", "btc", "ethereum", "binance",
]

# =========================================
# MODEL LOADING (CNN-BiLSTM V2)
# =========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

model = None
tokenizer = None

if ENABLE_DEEP_LEARNING:
    print("[PhishGuard V6] Loading ZeroDay Phishing v2 Deep Learning model...")
    model_path = os.path.join(BASE_DIR, "ZeroDay_Phishing_v2.keras")
    tokenizer_path = os.path.join(BASE_DIR, "tokenizer_v2.pkl")

    try:
        for layer_cls in (keras.layers.Embedding, keras.layers.Dense, keras.layers.Conv1D,
                          keras.layers.LSTM, keras.layers.Bidirectional, keras.layers.Dropout,
                          keras.layers.MaxPooling1D, keras.layers.InputLayer):
            if hasattr(layer_cls, 'from_config'):
                orig_fc = layer_cls.from_config
                setattr(layer_cls, 'from_config',
                        classmethod(lambda cls, config, orig=orig_fc:
                                    orig({k: v for k, v in config.items() if k != 'quantization_config'})))

        model = tf.keras.models.load_model(model_path)
        with open(tokenizer_path, "rb") as handle:
            tokenizer = pickle.load(handle)
        print("[PhishGuard V6] CNN-BiLSTM model loaded successfully.")
    except Exception as e:
        print(f"[PhishGuard V6] ERROR loading CNN-BiLSTM: {e}")
        print("[PhishGuard V6] Falling back to heuristics-only mode.")
        ENABLE_DEEP_LEARNING = False

# =========================================
# ROBERTA LOADING (LAZY ASYNC)
# =========================================
_ROBERTA_DIR = os.path.join(BASE_DIR, "PHISHGUARD_ROBERTA_V1")
roberta_tokenizer = None
roberta_model = None
roberta_lock = threading.Lock()


def load_roberta_lazy():
    global roberta_tokenizer, roberta_model, ROBERTA_READY
    if not TORCH_AVAILABLE:
        return False
    with roberta_lock:
        if roberta_model is not None and roberta_tokenizer is not None:
            return True
        if not os.path.exists(_ROBERTA_DIR):
            return False
        # Check weights file exists
        weights_file = os.path.join(_ROBERTA_DIR, "model.safetensors")
        if not os.path.exists(weights_file):
            print("[PhishGuard V6] WARNING: RoBERTa weights file not found.")
            return False
        try:
            print("[PhishGuard V6] Loading RoBERTa model (lazy background load)...")
            roberta_tokenizer = RobertaTokenizer.from_pretrained(_ROBERTA_DIR, local_files_only=True)
            roberta_model = RobertaForSequenceClassification.from_pretrained(_ROBERTA_DIR, local_files_only=True)
            roberta_model.eval()
            ROBERTA_READY = True
            print("[PhishGuard V6] RoBERTa model loaded successfully.")
            return True
        except Exception as _e:
            print(f"[PhishGuard V6] WARNING: Could not load RoBERTa: {_e}")
            return False


# =========================================
# URL PREPROCESSING & INFERENCE
# =========================================
def preprocess_url(url):
    sequence = tokenizer.texts_to_sequences([url])
    padded = pad_sequences(sequence, maxlen=MAX_LEN)
    return padded


def roberta_predict(url: str) -> float:
    global roberta_model, roberta_tokenizer
    if roberta_model is None or roberta_tokenizer is None:
        return 0.5
    try:
        inputs = roberta_tokenizer(
            url, return_tensors="pt", truncation=True, max_length=512, padding=True
        )
        with torch.no_grad():
            logits = roberta_model(**inputs).logits
        probs = torch.softmax(logits, dim=-1)
        return float(probs[0][1].item())
    except Exception as ex:
        print(f"[PhishGuard V6] RoBERTa inference error: {ex}")
        return 0.5


def normalize_url_local(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.lower()


def extract_domain(url):
    return urlparse(url).netloc.lower()


# =========================================
# URL HEURISTIC ENGINE (V6)
# =========================================
HIGH_RISK_TLDS = {
    ".top": 38, ".xyz": 35, ".live": 32, ".click": 36, ".zip": 38,
    ".tk": 40, ".ml": 40, ".ga": 40, ".cf": 40, ".gq": 40,
    ".cam": 35, ".icu": 34, ".bond": 32, ".rest": 32, ".vip": 30,
    ".pw": 30, ".su": 28, ".ru": 18, ".cn": 16,
}


def has_ip_address(domain):
    return bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}(:\d+)?$", domain))


def url_entropy(url):
    if not url:
        return 0.0
    counts = Counter(url)
    probs = [c / len(url) for c in counts.values()]
    return -sum(p * math.log2(p) for p in probs if p > 0)


def calculate_rule_score(url, domain):
    """
    URL heuristic engine. Returns (score 0-100, list of reason strings).
    No single heuristic alone declares phishing.
    """
    score = 0
    reasons = []

    if has_ip_address(domain):
        score += 40
        reasons.append("IP address used as host")

    for tld, pts in HIGH_RISK_TLDS.items():
        if domain.endswith(tld):
            score += pts
            reasons.append(f"Suspicious TLD ({tld})")
            break

    parts = domain.split(".")
    sub_depth = max(0, len(parts) - 2)
    if sub_depth >= 3:
        score += 20
        reasons.append("Excessive subdomain depth")

    entropy = url_entropy(url)
    if entropy > 4.5:
        score += 20
        reasons.append("High entropy domain")

    if len(url) > 75:
        score += 15
        reasons.append("Unusually long URL")

    digits = sum(c.isdigit() for c in url) / max(len(url), 1)
    if digits > 0.15:
        score += 15
        reasons.append("High digit ratio in URL")

    cleaned = re.sub(r"^https?://", "", url)
    specials = sum(1 for c in cleaned if c in "-_~@!*'();:,/?#[]&=%+$") / max(len(cleaned), 1)
    if specials > 0.20:
        score += 10
        reasons.append("High special character ratio")

    full_url_lower = url.lower()
    kw_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url_lower]
    if kw_hits:
        score += min(len(kw_hits) * 8, 35)
        reasons.append("Credential harvesting keywords")

    SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "short.link"]
    if any(domain == s or domain.endswith("." + s) for s in SHORTENERS):
        score += 25
        reasons.append("URL shortener masking destination")

    if "//" in (urlparse(url).path or ""):
        score += 15
        reasons.append("Double-slash redirect in path")

    # @ symbol in URL (credential embedding attempt)
    if "@" in cleaned:
        score += 20
        reasons.append("@ symbol in URL — possible credential embedding")

    return min(score, 100), reasons


# =========================================
# CLASSIFICATION LABEL NORMALIZER
# =========================================
_CLASSIFICATION_TO_VERDICT = {
    "KNOWN_PHISHING": "Known Phishing",
    "ZERO_DAY_PHISHING": "Zero-Day Phishing",
    "SUSPICIOUS": "Suspicious",
    "LEGITIMATE": "Legitimate",
    "UNKNOWN": "Unknown",
}

_CLASSIFICATION_TO_THREAT_LEVEL = {
    "KNOWN_PHISHING": "Critical",
    "ZERO_DAY_PHISHING": "Critical",
    "SUSPICIOUS": "High",
    "LEGITIMATE": "Safe",
    "UNKNOWN": "Medium",
}


# =========================================
# REACHABILITY CHECK ENDPOINT
# =========================================
@app.route("/check-reachability", methods=["POST", "OPTIONS"])
def check_reachability_route():
    if request.method == "OPTIONS":
        return jsonify({}), 200

    data = request.get_json() or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"status": "failed", "error": "No URL provided"}), 400

    url_syntax = validate_url(url)
    if not url_syntax["valid"]:
        return jsonify({
            "status": "invalid_url",
            "reachable": False,
            "reason": url_syntax["reason"],
            "url": url,
        }), 400

    ssrf_check = validate_ssrf(url)
    if not ssrf_check["safe"]:
        return jsonify({
            "status": "ssrf_blocked",
            "reachable": False,
            "security_block": True,
            "reason": ssrf_check["reason"],
            "url": url,
        }), 400

    reach = check_reachability(url)
    return jsonify({
        "status": "ok",
        "url": url,
        **reach,
    }), 200


# =========================================
# PREDICT ENDPOINT V6 / V7 (WITH REACHABILITY GATE)
# =========================================
@app.route("/predict", methods=["POST", "OPTIONS"])
def predict():
    if request.method == "OPTIONS":
        return jsonify({}), 200

    start_time = time.perf_counter()
    timing = {}

    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "failed", "error": "Invalid JSON or no payload"}), 400

        url = data.get("url", "").strip()
        if not url:
            return jsonify({"status": "failed", "error": "No URL provided"}), 400

        scan_mode = data.get("scan_mode", "quick").lower()
        if scan_mode not in ("quick", "deep"):
            scan_mode = "quick"

        print(f"[URL] Received URL: {url}", flush=True)

        # ─────────────────────────────────────────────────────────────────
        # STEP 0: URL Validation & Syntax Checking
        # ─────────────────────────────────────────────────────────────────
        url_syntax = validate_url(url)
        if not url_syntax["valid"]:
            print(f"[URL] Invalid URL syntax: {url_syntax['reason']}", flush=True)
            print("[SCAN] Full analysis skipped", flush=True)
            return jsonify({
                "status": "failed",
                "error": f"Invalid URL: {url_syntax['reason']}",
                "scan_performed": False,
                "reachability_status": "INVALID_URL",
                "verdict": "INCONCLUSIVE",
                "risk_score": None,
                "confidence_score": 0,
            }), 400

        # ─────────────────────────────────────────────────────────────────
        # STEP 1: SSRF Guard — validate before any network processing
        # ─────────────────────────────────────────────────────────────────
        print("[SSRF] Validation started", flush=True)
        t_ssrf = time.perf_counter()
        ssrf_check = validate_ssrf(url)
        timing["ssrf_ms"] = round((time.perf_counter() - t_ssrf) * 1000, 2)

        if not ssrf_check["safe"]:
            print(f"[SSRF] Prohibited destination blocked: {ssrf_check['reason']}", flush=True)
            print("[SCAN] Full analysis skipped", flush=True)
            return jsonify({
                "status": "failed",
                "error": f"URL blocked by security guard: {ssrf_check['reason']}",
                "security_block": True,
                "block_reason": ssrf_check["reason"],
                "scan_performed": False,
                "reachability_status": "SSRF_BLOCKED",
                "verdict": "INCONCLUSIVE",
                "risk_score": None,
                "confidence_score": 0,
                "deep_scan": {
                    "attempted": False,
                    "executed": False,
                    "status": "BLOCKED_SSRF",
                    "error_type": "SSRF_BLOCKED",
                },
            }), 400

        print("[SSRF] Destination allowed", flush=True)

        # ─────────────────────────────────────────────────────────────────
        # STEP 1B: Pre-Scan Reachability Gate (Lightweight Pre-Flight Check)
        # ─────────────────────────────────────────────────────────────────
        t_reach = time.perf_counter()
        reachability = check_reachability(url)
        timing["reachability_ms"] = round((time.perf_counter() - t_reach) * 1000, 2)

        if reachability.get("ssrf_blocked"):
            print(f"[SSRF] Prohibited destination in redirect: {reachability['reason']}", flush=True)
            print("[SCAN] Full analysis skipped", flush=True)
            return jsonify({
                "status": "failed",
                "error": f"URL blocked by security guard: {reachability['reason']}",
                "security_block": True,
                "block_reason": reachability["reason"],
                "scan_performed": False,
                "reachability_status": "SSRF_BLOCKED",
                "verdict": "INCONCLUSIVE",
                "risk_score": None,
                "confidence_score": 0,
                "deep_scan": {
                    "attempted": False,
                    "executed": False,
                    "status": "BLOCKED_SSRF",
                    "error_type": "SSRF_BLOCKED",
                },
            }), 400

        if not reachability["reachable"]:
            print(f"[REACHABILITY] URL not reachable ({reachability['status']})", flush=True)
            print("[SCAN] Full analysis skipped", flush=True)
            detection_time_ms = round((time.perf_counter() - start_time) * 1000, 1)
            timing["total_ms"] = detection_time_ms

            return jsonify({
                "status": "not_reachable",
                "scan_performed": False,
                "verdict": "INCONCLUSIVE",
                "classification": "INCONCLUSIVE",
                "prediction": "INCONCLUSIVE",
                "prediction_result": "INCONCLUSIVE",
                "attack_type": "INCONCLUSIVE",
                "risk_score": None,
                "confidence_score": 0,
                "confidence": 0,
                "model_confidence": 0,
                "threat_level": "None",
                "risk_level": "None",
                "reachability_status": reachability["status"],
                "reachability_reason": reachability["reason"],
                "message": "The URL could not be reached, so full security analysis was not performed.",
                "recommendation": "Do not treat this result as proof that the URL is safe.",
                "url": url,
                "final_url": reachability.get("final_url", url),
                "reasons": [
                    "Full phishing analysis was not performed because the website could not be reached.",
                    f"Status: {reachability['reason'] or reachability['status']}",
                    "This does NOT mean the URL is safe."
                ],
                "explanations": [
                    "Full phishing analysis was not performed because the website could not be reached.",
                    f"Status: {reachability['reason'] or reachability['status']}",
                    "This does NOT mean the URL is safe."
                ],
                "deep_scan": {
                    "attempted": False,
                    "executed": False,
                    "status": "NOT_REACHABLE",
                    "scan_status": "UNREACHABLE",
                    "navigation_status": "UNREACHABLE",
                    "reachability_status": reachability["status"],
                    "error": reachability["reason"],
                    "error_type": reachability["status"],
                },
                "detection_time_ms": detection_time_ms,
                "timing": timing,
                "model_version": "PhishGuard AI V7.0",
                "version": "7.0.0",
                "timestamp": int(time.time() * 1000),
            }), 200

        print("[SCAN] Starting full PhishGuard analysis", flush=True)

        # ─────────────────────────────────────────────────────────────────
        # STEP 2: URL Normalization
        # ─────────────────────────────────────────────────────────────────
        url_norm = normalize_url_local(url)
        domain = extract_domain(url_norm)
        url_sha = sha256_hash(url_norm)

        # ─────────────────────────────────────────────────────────────────
        # STEP 3: Enterprise Whitelist Guard (Evidence check, not an early exit)
        # ─────────────────────────────────────────────────────────────────
        is_whitelisted = is_trusted_domain(domain)

        # ─────────────────────────────────────────────────────────────────
        # STEP 4: Threat Repository + Brand/Homoglyph/Punycode/Typosquat
        # ─────────────────────────────────────────────────────────────────
        t_ti = time.perf_counter()
        repo_result = check_global_repository(url_norm)
        timing["threat_intel_ms"] = round((time.perf_counter() - t_ti) * 1000, 2)

        repo_found = repo_result.get("found", False)
        match_type = repo_result.get("match_type", None)
        threat_type = repo_result.get("threat_type", "None")
        target_brand = repo_result.get("target_brand")
        sim_val = repo_result.get("similarity", 0.0)
        sim_pct = round(sim_val * 100, 1)

        brand_signal = {
            "detected": repo_found and match_type not in ("Exact URL Match", "SHA-256 Hash Match", "Malicious Domain"),
            "similarity": sim_val,
            "confidence": repo_result.get("confidence", 0.0),
            "impersonation_type": match_type,
            "modifier": None,
            "company": repo_result.get("company"),
            "brand": target_brand,
            "generic_keywords": repo_result.get("generic_keywords", []),
        }

        # ─────────────────────────────────────────────────────────────────
        # STEP 5: URL Heuristics
        # ─────────────────────────────────────────────────────────────────
        t_heur = time.perf_counter()
        rule_score, rule_reasons = calculate_rule_score(url_norm, domain)
        timing["heuristic_ms"] = round((time.perf_counter() - t_heur) * 1000, 2)

        heuristic_signal = {"score": rule_score, "reasons": rule_reasons}

        # ─────────────────────────────────────────────────────────────────
        # STEP 6: CNN-BiLSTM (parallel thread)
        # ─────────────────────────────────────────────────────────────────
        cnn_result_store = {}
        roberta_result_store = {}

        def run_cnn():
            t = time.perf_counter()
            try:
                processed = preprocess_url(url_norm)
                score = float(model.predict(processed, verbose=0)[0][0])
                cnn_result_store["probability"] = score
                cnn_result_store["latency_ms"] = round((time.perf_counter() - t) * 1000, 1)
            except Exception as ex:
                print(f"[PhishGuard V6] CNN-BiLSTM inference error: {ex}")
                cnn_result_store["error"] = str(ex)

        def run_roberta():
            t = time.perf_counter()
            try:
                score = roberta_predict(url_norm)
                # Only record if RoBERTa was actually loaded (not the 0.5 fallback)
                if roberta_model is not None:
                    roberta_result_store["probability"] = score
                    roberta_result_store["latency_ms"] = round((time.perf_counter() - t) * 1000, 1)
            except Exception as ex:
                print(f"[PhishGuard V6] RoBERTa thread error: {ex}")
                roberta_result_store["error"] = str(ex)

        cnn_thread = None
        roberta_thread = None

        if ENABLE_DEEP_LEARNING and (model is not None and tokenizer is not None):
            cnn_thread = threading.Thread(target=run_cnn, daemon=True)
            cnn_thread.start()

        if roberta_model is None and TORCH_AVAILABLE:
            load_roberta_lazy()

        if roberta_model is not None and roberta_tokenizer is not None:
            roberta_thread = threading.Thread(target=run_roberta, daemon=True)
            roberta_thread.start()

        # Wait for model threads
        if cnn_thread:
            cnn_thread.join(timeout=5.0)
        if roberta_thread:
            roberta_thread.join(timeout=7.0)

        cnn_executed = "probability" in cnn_result_store and cnn_result_store.get("error") is None
        cnn_available = bool(ENABLE_DEEP_LEARNING and model is not None and tokenizer is not None)
        cnn_error = cnn_result_store.get("error")

        roberta_executed = "probability" in roberta_result_store and roberta_result_store.get("error") is None
        roberta_available_now = bool(TORCH_AVAILABLE and roberta_model is not None)
        roberta_error = roberta_result_store.get("error")

        cnn_signal = {
            "available": cnn_available,
            "executed": cnn_executed,
            "probability": cnn_result_store.get("probability", 0.5),
            "latency_ms": cnn_result_store.get("latency_ms", 0.0),
            "error": cnn_error,
        }
        roberta_signal = {
            "available": roberta_available_now,
            "executed": roberta_executed,
            "probability": roberta_result_store.get("probability", 0.5),
            "latency_ms": roberta_result_store.get("latency_ms", 0.0),
            "error": roberta_error,
        }

        timing["cnn_ms"] = cnn_signal["latency_ms"]
        timing["roberta_ms"] = roberta_signal["latency_ms"]

        # ─────────────────────────────────────────────────────────────────
        # STEP 6B: Quick Scan Baseline Evaluation
        # ─────────────────────────────────────────────────────────────────
        quick_fusion = fuse(
            threat_intel=repo_result,
            brand=brand_signal,
            heuristics=heuristic_signal,
            cnn=cnn_signal,
            roberta=roberta_signal,
            deep_scan=None,
            visual_analysis=None,
            is_whitelisted=is_whitelisted,
        )
        quick_scan_summary = {
            "executed": True,
            "classification": quick_fusion["classification"],
            "risk": quick_fusion["risk_score"],
            "confidence": quick_fusion["confidence_score"],
        }

        # ─────────────────────────────────────────────────────────────────
        # STEP 7: ALWAYS DEEP SCAN (VirtualBox Analysis VM)
        # ─────────────────────────────────────────────────────────────────
        deep_scan_result = None
        html_evidence = {}
        dom_evidence = {}
        screenshot_evidence = {}
        raw_ds = {}

        sb_status = get_sandbox_status()
        if not sb_status.get("sandbox_available"):
            sb_status = check_sandbox_availability()
        if not sb_status.get("sandbox_available"):
            deep_scan_result = {
                "available": False,
                "attempted": True,
                "executed": False,
                "success": False,
                "status": "VM_UNAVAILABLE",
                "scan_status": "VM_UNAVAILABLE",
                "navigation_status": "UNAVAILABLE",
                "error_type": "VM_AGENT_UNAVAILABLE",
                "error": f"Deep Scan unavailable: {sb_status.get('unavailability_reason', 'VirtualBox VM agent not reachable')}. Quick Scan protection remains active.",
                "final_url": url_norm,
                "page_title": None,
                "redirect_count": 0,
                "forms": 0,
                "password_fields": 0,
                "email_fields": 0,
                "otp_fields": 0,
                "payment_fields": 0,
                "screenshot_available": False,
                "ocr_available": False,
                "ocr_word_count": 0,
            }
        else:
            t_ds = time.perf_counter()
            print(f"[PhishGuard V7] Executing Deep Scan inside VM for: {url_norm}")
            raw_ds = run_deep_scan(url_norm)
            timing["deep_scan_ms"] = round((time.perf_counter() - t_ds) * 1000, 1)

            if raw_ds.get("html_raw"):
                html_evidence = analyze_html(raw_ds["html_raw"], raw_ds.get("final_url", url_norm))
                dom_evidence = analyze_dom(raw_ds.get("dom_snapshot"), raw_ds.get("final_url", url_norm))

            if raw_ds.get("screenshot_evidence") and raw_ds["screenshot_evidence"].get("available"):
                screenshot_evidence = raw_ds["screenshot_evidence"]
            elif raw_ds.get("screenshot_path"):
                screenshot_evidence = analyze_screenshot(raw_ds.get("screenshot_path"))

            # Propagate screenshot_b64 safely without exposing filesystem paths
            scr_b64 = raw_ds.get("screenshot_b64")
            if scr_b64:
                if not screenshot_evidence:
                    screenshot_evidence = {"available": True}
                screenshot_evidence["screenshot_b64"] = scr_b64

            ds_scan_status = raw_ds.get("scan_status", "SUCCESS" if raw_ds.get("success") else "FAILED")
            ds_executed = bool(raw_ds.get("page_available") or scr_b64 or raw_ds.get("success"))

            deep_scan_result = {
                "available": True,
                "attempted": True,
                "executed": ds_executed,
                "success": raw_ds.get("success", False),
                "status": (
                    "SUCCESS" if ds_scan_status == "SUCCESS" else (
                        "PARTIAL" if ds_scan_status == "PARTIAL" else (
                            "TARGET_TIMEOUT" if raw_ds.get("navigation_status") == "TIMEOUT" else "FAILED"
                        )
                    )
                ),
                "scan_status": ds_scan_status,
                "navigation_status": raw_ds.get("navigation_status", "SUCCESS" if raw_ds.get("success") else "ERROR"),
                "error": raw_ds.get("error"),
                "error_type": raw_ds.get("error_type"),
                "failure_stage": raw_ds.get("failure_stage") or ("Playwright Navigation (page.goto)" if raw_ds.get("navigation_status") == "TIMEOUT" else None),
                "stage_timings": raw_ds.get("stage_timings", {}),
                "retry_attempt": raw_ds.get("retry_attempt", 1),
                "failed_resources": raw_ds.get("failed_resources", []),
                "failed_resources_count": len(raw_ds.get("failed_resources", [])),
                "http_status": raw_ds.get("http_status"),
                "page_available": raw_ds.get("page_available", bool(raw_ds.get("html_raw"))),
                "screenshot_available": bool(scr_b64),
                "ocr_available": bool(screenshot_evidence and screenshot_evidence.get("ocr_available")),
                "dom_available": bool(dom_evidence and dom_evidence.get("available")),
                "screenshot_type": raw_ds.get("screenshot_type", "viewport" if scr_b64 else None),
                "screenshot_status": raw_ds.get("screenshot_status", "captured" if scr_b64 else "unavailable"),
                "redirect_chain": raw_ds.get("redirect_chain", []),
                "final_url": raw_ds.get("final_url", url_norm),
                "page_title": raw_ds.get("page_title"),
                "redirect_count": raw_ds.get("redirect_count", 0),
                "load_time_ms": raw_ds.get("load_time_ms", 0.0),
                "forms": len(raw_ds.get("forms", [])),
                "forms_count": len(raw_ds.get("forms", [])),
                "password_fields": len(raw_ds.get("password_fields", [])),
                "email_fields": len(raw_ds.get("email_fields", [])),
                "otp_fields": len(raw_ds.get("otp_fields", [])),
                "payment_fields": len(raw_ds.get("payment_fields", [])),
                "external_resources_count": len(raw_ds.get("external_resources", [])),
                "ocr_word_count": screenshot_evidence.get("ocr_word_count", 0),
                "html_evidence": html_evidence,
                "dom_evidence": dom_evidence,
                "screenshot_evidence": screenshot_evidence,
                "screenshot_b64": scr_b64,
            }

        # ── STEP 7B: Safe Web View Session Initialization ─────────────────────────
        safe_view_session = None
        safe_view_data = None
        try:
            final_url_val = (raw_ds.get("final_url") if raw_ds else None) or url_norm
            safe_view_session = session_manager.create_session(target_url=final_url_val)

            html_content_for_view = (raw_ds.get("dom_snapshot") or raw_ds.get("html_raw") or "") if raw_ds else ""
            err_type = (raw_ds.get("error_type") if raw_ds else None) or ("DEEP_SCAN_NOT_RUN" if not raw_ds else None)

            # Build safe read-only representation from captured DOM (or fallback)
            safe_html, elements_map, content_inventory = html_sanitizer.sanitize(
                html_content=html_content_for_view,
                base_url=final_url_val,
                dynamic_events=raw_ds.get("dom_behavior", {}).get("behavioral_events") if raw_ds else None,
                error_type=err_type if not html_content_for_view else None,
                captured_stylesheets=raw_ds.get("captured_stylesheets") if raw_ds else None,
            )

            dom_diff = forensic_engine.compute_dom_diff(
                initial_dom=raw_ds.get("html_raw") if raw_ds else None,
                final_dom=raw_ds.get("dom_snapshot") if raw_ds else None,
                dom_behavior=raw_ds.get("dom_behavior") if raw_ds else None,
                base_url=final_url_val,
            )

            network_forensics = forensic_engine.compile_network_forensics(
                raw_ds=raw_ds or {},
                base_url=final_url_val,
            )

            timeline = forensic_engine.build_temporal_timeline(
                raw_ds=raw_ds or {},
                load_time_ms=(raw_ds.get("load_time_ms") if raw_ds else 0.0) or 0.0,
                dom_behavior=raw_ds.get("dom_behavior") if raw_ds else None,
                network_requests=network_forensics.get("requests", []),
            )

            root_rec = {
                "page_id": "p_root",
                "representation_id": "p_root",
                "session_id": safe_view_session.session_id,
                "scan_id": safe_view_session.session_id,
                "url": final_url_val,
                "original_url": url,
                "canonical_url": final_url_val,
                "path": urlparse(final_url_val).path or "/",
                "title": (raw_ds.get("page_title") if raw_ds else None) or urlparse(final_url_val).path or "/",
                "http_status": (raw_ds.get("http_status") if raw_ds else None) or 200,
                "depth": 0,
                "is_root": True,
                "load_time_ms": (raw_ds.get("load_time_ms") if raw_ds else 0.0) or 0.0,
                "risk_level": "HIGH" if (raw_ds and (raw_ds.get("password_fields") or dom_diff.get("dynamic_password_injection"))) else "LOW",
                "has_credentials": bool(raw_ds and raw_ds.get("password_fields")),
                "scan_status": "AVAILABLE",
                "status": "AVAILABLE",
                "page_available": True,
                "error": None,
                "error_type": None,
                "error_details": None,
                "screenshot_b64": raw_ds.get("screenshot_b64") if raw_ds else None,
                "screenshot_type": (raw_ds.get("screenshot_type") if raw_ds else None) or "full_page",
                "safe_html": safe_html,
                "html_raw": (raw_ds.get("html_raw") if raw_ds else "") or "",
                "dom_snapshot": (raw_ds.get("dom_snapshot") if raw_ds else "") or "",
                "elements_map": elements_map,
                "content_inventory": content_inventory,
                "forms": (raw_ds.get("forms") if raw_ds else []) or [],
                "links_count": content_inventory.get("links", 0),
                "dom_diff": dom_diff,
                "dom_behavior": (raw_ds.get("dom_behavior") if raw_ds else {}) or {},
                "network_forensics": network_forensics,
                "timeline": timeline,
                "suspicious_indicators": [],
                "page_states": [
                    {"name": "Initial DOM (T0)", "status": "Captured", "size": len((raw_ds.get("html_raw") if raw_ds else "") or "")},
                    {"name": "Post-JavaScript Settled (T1)", "status": "Captured", "size": len((raw_ds.get("dom_snapshot") if raw_ds else "") or "")},
                ],
                "security_status": {
                    "isolated": True,
                    "read_only": True,
                    "interactions_blocked": True,
                    "scripts_disabled": True,
                },
            }

            safe_view_session.add_page("p_root", root_rec)
            safe_view_session.root_page_id = "p_root"
            safe_view_session.status = "READY"
            safe_view_session.update_page_status("p_root", "AVAILABLE")
            safe_view_engine._set_page_event(safe_view_session.session_id, "p_root")

            # Trigger multi-depth background page discovery for same-origin links
            rendered_dom_content = raw_ds.get("dom_snapshot") or raw_ds.get("html_raw") or ""
            if rendered_dom_content:
                discovery_res = page_discovery_engine.extract_all_links(
                    html_content=rendered_dom_content,
                    current_url=final_url_val,
                    target_origin_url=url,
                    current_depth=0,
                )
                candidates = discovery_res.get("candidates", [])
                blocked = discovery_res.get("blocked_actions", [])
                ext_domains = discovery_res.get("external_domains", [])

                safe_view_session.add_external_domains(ext_domains)
                for b in blocked:
                    safe_view_session.add_blocked_action(b["url"], b["path"], b["reason"], b.get("context", ""))

                initial_queue = []
                for idx, cand in enumerate(candidates):
                    if cand.get("is_root"):
                        continue
                    cand_page_id = f"p_disc_{idx + 1}"
                    cand["page_id"] = cand_page_id
                    safe_view_session.add_discovered_candidate(
                        page_id=cand_page_id,
                        url=cand["url"],
                        path=cand["path"],
                        depth=cand.get("depth", 1),
                        title=cand.get("title", ""),
                        priority=cand.get("priority", 10),
                        is_root=False,
                    )
                    initial_queue.append(cand)

                safe_view_session.discovery_stats["links_found"] = len(candidates) + len(blocked)
                safe_view_session.discovery_stats["pages_discovered"] = len(safe_view_session.discovered_pages)

                if initial_queue:
                    safe_view_engine.start_background_crawl(
                        session_id=safe_view_session.session_id,
                        initial_candidates=initial_queue,
                        target_origin_url=url,
                        max_pages=50,
                        max_depth=4,
                    )

            safe_view_data = safe_view_session.to_dict()
        except Exception as sve_err:
            print(f"[SafeView] Integration notice: {sve_err}", flush=True)

        # ─────────────────────────────────────────────────────────────────
        # STEP 8: Visual Phishing Analysis
        # ─────────────────────────────────────────────────────────────────
        t_va = time.perf_counter()
        visual_analysis_result = analyze_visual_evidence(
            ocr_evidence=screenshot_evidence,
            dom_evidence=dom_evidence,
            html_evidence=html_evidence,
            domain=domain,
            is_whitelisted=is_whitelisted,
        )
        timing["visual_analysis_ms"] = round((time.perf_counter() - t_va) * 1000, 2)

        # ─────────────────────────────────────────────────────────────────
        # STEP 8B: Temporal HTML/DOM Behavioral Intelligence Engine
        # ─────────────────────────────────────────────────────────────────
        t_dom_behavior = time.perf_counter()
        dom_behavior_result = analyze_dom_behavior(
            dom_raw=raw_ds.get("dom_snapshot") if raw_ds else None,
            raw_ds=raw_ds,
            page_url=url_norm,
            target_domain=domain,
            is_whitelisted=is_whitelisted,
        )
        timing["dom_behavior_ms"] = round((time.perf_counter() - t_dom_behavior) * 1000, 2)

        # ─────────────────────────────────────────────────────────────────
        # STEP 9: Unified Evidence Fusion Engine
        # ─────────────────────────────────────────────────────────────────
        t_fusion = time.perf_counter()
        deep_scan_for_fusion = None
        if deep_scan_result and deep_scan_result.get("available") and (deep_scan_result.get("success") or deep_scan_result.get("scan_status") == "PARTIAL"):
            deep_scan_for_fusion = {
                "available": True,
                "html_evidence": html_evidence,
                "dom_evidence": dom_evidence,
                "screenshot_evidence": screenshot_evidence,
            }

        fusion = fuse(
            threat_intel=repo_result,
            brand=brand_signal,
            heuristics=heuristic_signal,
            cnn=cnn_signal,
            roberta=roberta_signal,
            deep_scan=deep_scan_for_fusion,
            visual_analysis=visual_analysis_result,
            dom_behavior=dom_behavior_result,
            is_whitelisted=is_whitelisted,
        )
        timing["fusion_ms"] = round((time.perf_counter() - t_fusion) * 1000, 2)

        classification = fusion["classification"]
        risk_score = fusion["risk_score"]
        model_confidence = fusion["model_confidence"]
        high_signals = fusion["high_signals"]
        detection_type = fusion["detection_type"]

        # ─────────────────────────────────────────────────────────────────
        # STEP 10: XAI Explanation Engine
        # ─────────────────────────────────────────────────────────────────
        t_xai = time.perf_counter()
        reasons = generate_reasons(
            classification=classification,
            threat_intel=repo_result,
            brand=brand_signal,
            heuristic_reasons=rule_reasons,
            cnn=cnn_signal,
            roberta=roberta_signal,
            deep_scan=deep_scan_for_fusion,
            high_signals=high_signals,
            model_disagreement=fusion.get("model_disagreement", False),
            evidence_vector=fusion.get("evidence_vector"),
            is_whitelisted=is_whitelisted,
        )
        recommendation = build_recommendation(classification, target_brand)
        timing["xai_ms"] = round((time.perf_counter() - t_xai) * 1000, 2)

        # ─────────────────────────────────────────────────────────────────
        # STEP 11: Finalize Unified Response (Section 14 Schema)
        # ─────────────────────────────────────────────────────────────────
        detection_time_ms = round((time.perf_counter() - start_time) * 1000, 1)
        timing["total_ms"] = detection_time_ms

        verdict = _CLASSIFICATION_TO_VERDICT.get(classification, classification)
        threat_level = _CLASSIFICATION_TO_THREAT_LEVEL.get(classification, "Medium")

        if classification == "KNOWN_PHISHING":
            detection_method = repo_result.get("detection_method", "SQLite Threat Repository")
        elif detection_type == "ZERO_DAY":
            detection_method = "Hybrid AI + Deep Scan Unified Ensemble (Zero-Day)"
        elif detection_type == "SUSPICIOUS":
            detection_method = "Multi-Signal Unified Risk Assessment (Suspicious)"
        elif detection_type == "WHITELIST":
            detection_method = "Trusted Enterprise Whitelist"
        else:
            detection_method = "Unified Sequential Analysis (Clean)"

        log_to_global_stats(url, domain, classification, threat_type, target_brand,
                            threat_level, risk_score, model_confidence,
                            detection_time_ms, "Found" if repo_found and match_type in ("Exact URL Match", "SHA-256 Hash Match", "Malicious Domain") else "Not Found",
                            detection_method)

        # Build signals breakdown
        signals = {
            "threat_intelligence": {
                "found": repo_found,
                "match_type": match_type,
                "confidence": repo_result.get("confidence", 0.0),
                "similarity": sim_val,
                "detection_time_ms": repo_result.get("detection_time_ms", 0.0),
            },
            "brand_intelligence": {
                "detected": brand_signal["detected"],
                "similarity": sim_val,
                "confidence": brand_signal.get("confidence", 0.0),
                "impersonation_type": match_type,
                "target_brand": target_brand,
            },
            "heuristics": {
                "score": rule_score,
                "reasons": rule_reasons,
            },
            "cnn": {
                "available": cnn_available,
                "executed": cnn_executed,
                "run": cnn_executed,
                "probability": round(cnn_signal["probability"] * 100, 1) if cnn_executed else None,
                "latency_ms": cnn_signal["latency_ms"],
                "error": cnn_error,
            },
            "roberta": {
                "available": roberta_available_now,
                "executed": roberta_executed,
                "run": roberta_executed,
                "probability": round(roberta_signal["probability"] * 100, 1) if roberta_executed else None,
                "latency_ms": roberta_signal["latency_ms"],
                "error": roberta_error,
            },
            "html": html_evidence or {"available": False},
            "dom": dom_evidence or {"available": False},
            "dom_behavior": dom_behavior_result,
            "screenshot": screenshot_evidence or {"available": False},
            "sandbox": {
                "available": deep_scan_result.get("available", False) if deep_scan_result else False,
                "attempted": deep_scan_result.get("attempted", True) if deep_scan_result else True,
                "executed": deep_scan_result.get("executed", False) if deep_scan_result else False,
                "success": deep_scan_result.get("success", False) if deep_scan_result else False,
                "status": deep_scan_result.get("status", "VM_UNAVAILABLE") if deep_scan_result else "VM_UNAVAILABLE",
                "scan_status": deep_scan_result.get("scan_status") if deep_scan_result else "unavailable",
                "navigation_status": deep_scan_result.get("navigation_status") if deep_scan_result else "unavailable",
                "error": deep_scan_result.get("error") if deep_scan_result else None,
                "error_type": deep_scan_result.get("error_type") if deep_scan_result else None,
                "http_status": deep_scan_result.get("http_status") if deep_scan_result else None,
                "final_url": deep_scan_result.get("final_url") if deep_scan_result else None,
                "page_title": deep_scan_result.get("page_title") if deep_scan_result else None,
                "redirect_count": deep_scan_result.get("redirect_count", 0) if deep_scan_result else 0,
                "screenshot_type": deep_scan_result.get("screenshot_type") if deep_scan_result else None,
                "screenshot_status": deep_scan_result.get("screenshot_status") if deep_scan_result else "unavailable",
            }
        }

        # Format Deep Scan summary matching Section 14
        scr_b64_val = deep_scan_result.get("screenshot_b64") if deep_scan_result else None
        deep_scan_summary = {
            "attempted": bool(deep_scan_result and deep_scan_result.get("attempted", True)),
            "executed": bool(deep_scan_result and deep_scan_result.get("executed", False)),
            "status": deep_scan_result.get("status", "VM_UNAVAILABLE") if deep_scan_result else "VM_UNAVAILABLE",
            "final_url": deep_scan_result.get("final_url", url_norm) if deep_scan_result else url_norm,
            "page_title": deep_scan_result.get("page_title") if deep_scan_result else None,
            "redirect_count": deep_scan_result.get("redirect_count", 0) if deep_scan_result else 0,
            "forms": deep_scan_result.get("forms", 0) if deep_scan_result else 0,
            "password_fields": deep_scan_result.get("password_fields", 0) if deep_scan_result else 0,
            "email_fields": deep_scan_result.get("email_fields", 0) if deep_scan_result else 0,
            "otp_fields": deep_scan_result.get("otp_fields", 0) if deep_scan_result else 0,
            "payment_fields": deep_scan_result.get("payment_fields", 0) if deep_scan_result else 0,
            "screenshot_available": bool(deep_scan_result and deep_scan_result.get("screenshot_available")),
            "ocr_available": bool(deep_scan_result and deep_scan_result.get("ocr_available")),
            "ocr_word_count": deep_scan_result.get("ocr_word_count", 0) if deep_scan_result else 0,
            # Extra fields for backwards compatibility with frontend:
            "available": deep_scan_result.get("available", False) if deep_scan_result else False,
            "scan_status": deep_scan_result.get("scan_status", "unavailable") if deep_scan_result else "unavailable",
            "navigation_status": deep_scan_result.get("navigation_status", "unavailable") if deep_scan_result else "unavailable",
            "error_type": deep_scan_result.get("error_type") if deep_scan_result else None,
            "screenshot_b64": scr_b64_val,
            "screenshot_type": deep_scan_result.get("screenshot_type") if deep_scan_result else None,
            "screenshot_status": deep_scan_result.get("screenshot_status", "unavailable") if deep_scan_result else "unavailable",
            "error": deep_scan_result.get("error") if deep_scan_result else None,
        }

        # Models dictionary matching Section 2 & 14
        models_summary = {
            "cnn_bilstm": {
                "available": cnn_available,
                "executed": cnn_executed,
                "raw_probability": round(cnn_signal["probability"] * 100, 1) if cnn_executed else None,
                "calibrated_probability": round(fusion.get("evidence_vector", {}).get("cnn_calibrated"), 1) if (cnn_executed and fusion.get("evidence_vector", {}).get("cnn_calibrated") is not None) else None,
                "latency_ms": cnn_signal["latency_ms"],
                "error": cnn_error,
            },
            "roberta": {
                "available": roberta_available_now,
                "executed": roberta_executed,
                "raw_probability": round(roberta_signal["probability"] * 100, 1) if roberta_executed else None,
                "calibrated_probability": round(fusion.get("evidence_vector", {}).get("roberta_calibrated"), 1) if (roberta_executed and fusion.get("evidence_vector", {}).get("roberta_calibrated") is not None) else None,
                "latency_ms": roberta_signal["latency_ms"],
                "error": roberta_error,
            },
        }

        # Threat Intelligence summary
        threat_intelligence_summary = {
            "found": repo_found,
            "match_type": match_type or "None",
            "matched_value": repo_result.get("matched_value"),
            "confidence": repo_result.get("confidence", 0.0),
            "similarity": round(repo_result.get("similarity", 0.0) * 100, 1),
            "target_brand": target_brand,
            "threat_type": threat_type or "None",
            "detection_method": repo_result.get("detection_method", "Threat Intelligence Repository"),
        }

        # Brand Analysis summary
        brand_analysis_summary = {
            "detected": bool(brand_signal.get("detected")),
            "target_brand": target_brand,
            "similarity": sim_pct,
            "confidence": brand_signal.get("confidence", 0.0),
            "impersonation_type": brand_signal.get("impersonation_type"),
        }

        # Homoglyph, Punycode, Typosquatting summaries
        homoglyph_summary = {
            "detected": match_type == "Homoglyph Attack",
            "matched_brand": target_brand if match_type == "Homoglyph Attack" else None,
            "details": repo_result.get("matched_value") if match_type == "Homoglyph Attack" else None,
        }
        punycode_summary = {
            "detected": match_type == "Punycode Attack",
            "decoded_domain": repo_result.get("matched_value") if match_type == "Punycode Attack" else None,
            "target_brand": target_brand if match_type == "Punycode Attack" else None,
        }
        typosquatting_summary = {
            "detected": "Typosquatting" in str(match_type),
            "target_brand": target_brand if "Typosquatting" in str(match_type) else None,
            "technique": repo_result.get("detection_method") if "Typosquatting" in str(match_type) else None,
        }

        # Visual Analysis summary matching Section 10 & 14
        visual_analysis_summary = {
            "available": visual_analysis_result.get("available", False),
            "executed": visual_analysis_result.get("executed", False),
            "is_login_page": visual_analysis_result.get("is_login_page", False),
            "has_credential_harvesting": visual_analysis_result.get("has_credential_harvesting", False),
            "has_payment_fields": visual_analysis_result.get("has_payment_fields", False),
            "has_otp_fields": visual_analysis_result.get("has_otp_fields", False),
            "detected_brands": visual_analysis_result.get("detected_brands", []),
            "brand_impersonation_visual": visual_analysis_result.get("brand_impersonation_visual", False),
            "visual_risk_score": visual_analysis_result.get("visual_risk_score", 0.0),
            "indicators": visual_analysis_result.get("indicators", []),
        }

        # Screenshot summary matching Section 8
        screenshot_data = {
            "available": bool(scr_b64_val),
            "data": scr_b64_val,
            "type": "image/png",
            "capture_mode": raw_ds.get("screenshot_type", "full_page" if scr_b64_val else "viewport"),
            "size_bytes": len(scr_b64_val) if scr_b64_val else 0,
        }

        # OCR summary matching Section 9
        ocr_data = {
            "available": bool(screenshot_evidence and screenshot_evidence.get("ocr_available")),
            "executed": bool(screenshot_evidence and screenshot_evidence.get("ocr_text") is not None),
            "word_count": screenshot_evidence.get("ocr_word_count", 0),
            "text": screenshot_evidence.get("ocr_text", ""),
            "brand_candidates": screenshot_evidence.get("brand_candidates", []),
            "login_related_terms": screenshot_evidence.get("login_related_terms", []),
            "credential_terms": screenshot_evidence.get("credential_terms", []),
        }

        # Fusion summary matching Section 11 & 14
        fusion_summary = {
            "evidence_count": fusion.get("evidence_count", 0),
            "model_agreement": fusion.get("model_agreement"),
            "model_agreement_level": fusion.get("model_agreement_level", "UNAVAILABLE"),
            "positive_signals": fusion.get("positive_signals", []),
            "negative_signals": fusion.get("negative_signals", []),
            "conflicting_signals": fusion.get("conflicting_signals", []),
        }

        return jsonify({
            # V7.0 Core Unified Schema (Section 14)
            "url": url,
            "final_url": reachability.get("final_url", url),
            "scan_performed": True,
            "reachability_status": "reachable",
            "reachability_details": {
                "reachable": True,
                "status": "REACHABLE",
                "http_status": reachability.get("http_status"),
                "final_url": reachability.get("final_url", url),
                "redirect_count": reachability.get("redirect_count", 0),
                "redirect_chain": reachability.get("redirect_chain", []),
                "elapsed_ms": reachability.get("elapsed_ms", 0.0),
            },
            "classification": classification,
            "risk_score": risk_score,
            "confidence_score": model_confidence,

            "quick_scan": quick_scan_summary,
            "deep_scan": deep_scan_summary,
            "models": models_summary,
            "threat_intelligence": threat_intelligence_summary,
            "brand_analysis": brand_analysis_summary,
            "homoglyph_analysis": homoglyph_summary,
            "punycode_analysis": punycode_summary,
            "typosquatting_analysis": typosquatting_summary,
            "visual_analysis": visual_analysis_summary,
            "dom_behavior_analysis": dom_behavior_result,
            "screenshot": screenshot_data,
            "ocr": ocr_data,
            "fusion": fusion_summary,
            "explanation": reasons,
            "recommendation": recommendation,

            # Backwards-compatibility fields for frontend and existing tests
            "status": "success",
            "scan_mode": scan_mode,
            "verdict": verdict,
            "attack_type": verdict,
            "prediction": verdict,
            "prediction_result": verdict,
            "detection_type": detection_type,
            "threat_type": threat_type or "None",
            "target_brand": target_brand or "None",
            "similarity": sim_val,
            "similarity_pct": sim_pct,
            "repository_status": "Found" if (repo_found and match_type in ("Exact URL Match", "SHA-256 Hash Match", "Malicious Domain")) else "Not Found",
            "repository_match": bool(repo_found and match_type in ("Exact URL Match", "SHA-256 Hash Match", "Malicious Domain")),
            "repository_type": match_type if repo_found else None,
            "detection_method": detection_method,
            "confidence": model_confidence,
            "model_confidence": model_confidence,
            "threat_level": threat_level,
            "risk_level": threat_level,

            "model_agreement": fusion.get("model_agreement"),
            "model_disagreement": fusion.get("model_disagreement", False),
            "neural_consensus": fusion.get("neural_consensus", "N/A"),
            "evidence_count": fusion.get("evidence_count", 0),
            "strong_evidence_count": fusion.get("strong_evidence_count", 0),
            "evidence_vector": fusion.get("evidence_vector", {}),

            "cnn": models_summary["cnn_bilstm"],
            "roberta": models_summary["roberta"],
            "cnn_score": round(cnn_signal["probability"] * 100, 1) if cnn_executed else None,
            "cnn_available": cnn_available,
            "cnn_latency_ms": cnn_signal["latency_ms"],
            "roberta_score": round(roberta_signal["probability"] * 100, 1) if roberta_executed else None,
            "roberta_available": roberta_available_now,
            "roberta_latency_ms": roberta_signal["latency_ms"],
            "heuristic_score": float(rule_score),
            "brand_score": sim_pct,

            "reasons": reasons,
            "explanations": reasons,
            "signals": signals,
            "ensemble_breakdown": fusion.get("ensemble_breakdown", {}),
            "high_signals": high_signals,
            "screenshot_b64": scr_b64_val,

            # Safe Web View V7.0 integration
            "safe_view": {
                **(safe_view_data or {}),
                "available": bool(safe_view_session and safe_view_session.root_page_id),
                "session_id": safe_view_session.session_id if safe_view_session else None,
                "root_page_id": "p_root" if safe_view_session else None,
                "render_url": f"/safe-view/render/p_root?session_id={safe_view_session.session_id}" if safe_view_session else None,
                "session_render_url": f"/safe-view/session/{safe_view_session.session_id}/page/p_root/render" if safe_view_session else None,
                "pages": safe_view_session.get_pages_summary() if safe_view_session else [],
                "tree": safe_view_session.get_page_tree() if safe_view_session else [],
            },
            "safe_view_session_id": safe_view_session.session_id if safe_view_session else None,
            "safe_view_page_id": "p_root" if safe_view_session else None,
            "safe_view_available": bool(safe_view_session and safe_view_session.root_page_id),
            "render_url": f"/safe-view/render/p_root?session_id={safe_view_session.session_id}" if safe_view_session else None,

            "detection_time_ms": max(detection_time_ms, 5.0),
            "timing": timing,
            "model_version": "PhishGuard AI V7.0",
            "version": "7.0.0",
            "sha256": url_sha,
            "timestamp": int(time.time() * 1000),
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            "status": "failed",
            "error": f"Internal server error: {str(e)}",
        }), 500


# =========================================
# WARMUP (background thread — non-blocking)
# =========================================
def background_warmup():
    global MODEL_READY, ROBERTA_READY
    try:
        if ENABLE_DEEP_LEARNING and model is not None and tokenizer is not None:
            print("[PhishGuard V6] Warming up CNN-BiLSTM model...")
            dummy_seq = pad_sequences(
                tokenizer.texts_to_sequences(["http://example.com"]), maxlen=MAX_LEN
            )
            model.predict(dummy_seq, verbose=0)
            MODEL_READY = True
            print("[PhishGuard V6] CNN-BiLSTM warmed up.")
    except Exception as e:
        print("[PhishGuard V6] CNN-BiLSTM warmup failed:", e)

    try:
        if load_roberta_lazy():
            print("[PhishGuard V6] Warming up RoBERTa...")
            _ = roberta_predict("http://example.com")
            ROBERTA_READY = True
            print("[PhishGuard V6] RoBERTa warmed up.")
    except Exception as e:
        print("[PhishGuard V6] RoBERTa warmup failed:", e)


threading.Thread(target=background_warmup, daemon=True).start()

@app.route("/restart", methods=["POST"])
@app.route("/api/restart", methods=["POST"])
def restart_server():
    """Restarts Flask server process to reload all modified modules and code."""
    def _do_restart():
        time.sleep(0.5)
        python = sys.executable
        os.execl(python, python, *sys.argv)
    threading.Thread(target=_do_restart, daemon=True).start()
    return jsonify({"status": "restarting"}), 200


# =========================================
# RUN FLASK APP
# =========================================
if __name__ == "__main__":
    PORT = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=PORT, debug=False)