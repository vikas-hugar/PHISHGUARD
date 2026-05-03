from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import os
import re
import math
from collections import Counter
from urllib.parse import urlparse
import threading
import time
from collections import deque

import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

# =========================================
# PERFORMANCE TOGGLE
# =========================================
ENABLE_DEEP_LEARNING = True
MODEL_READY = False

if ENABLE_DEEP_LEARNING:
    import tensorflow as tf
    tf.config.threading.set_inter_op_parallelism_threads(1)
    tf.config.threading.set_intra_op_parallelism_threads(1)

    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import Embedding, Conv1D, MaxPooling1D
    from tensorflow.keras.layers import Bidirectional, LSTM, Dense, Dropout
    from tensorflow.keras.preprocessing.sequence import pad_sequences

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "Backend is running", "message": "PhishGuard API is active"})

# =========================================
# GLOBAL STATISTICS TRACKING
# =========================================
GLOBAL_STATS = {
    "total": 0,
    "phishing": 0,
    "safe": 0,
    "suspicious": 0,
    "confSum": 0
}
RECENT_SCANS = deque(maxlen=7)

def log_to_global_stats(url, prediction_result, confidence_score):
    GLOBAL_STATS["total"] += 1
    GLOBAL_STATS["confSum"] += confidence_score
    
    if prediction_result == "Phishing":
        GLOBAL_STATS["phishing"] += 1
    elif prediction_result == "Safe":
        GLOBAL_STATS["safe"] += 1
    else:
        GLOBAL_STATS["suspicious"] += 1

    RECENT_SCANS.appendleft({
        "url": url,
        "result": prediction_result,
        "confidence": confidence_score,
        "timestamp": int(time.time() * 1000)
    })

@app.route("/stats", methods=["GET"])
def get_stats():
    return jsonify({
        "stats": GLOBAL_STATS,
        "history": list(RECENT_SCANS)
    })

# =========================================
# SETTINGS
# =========================================

MAX_WORDS = 5000
MAX_LEN   = 200

# =========================================
# TRUSTED DOMAIN WHITELIST
# Only exact-match domains bypass DL scan
# =========================================

TRUSTED_DOMAINS = {
    # Google
    "google.com", "www.google.com", "mail.google.com",
    "docs.google.com", "drive.google.com", "colab.research.google.com",
    # GitHub
    "github.com", "www.github.com", "gist.github.com",
    # Microsoft
    "microsoft.com", "www.microsoft.com", "login.microsoftonline.com",
    "outlook.com", "www.outlook.com", "office.com",
    # Apple
    "apple.com", "www.apple.com", "icloud.com", "www.icloud.com",
    # Amazon
    "amazon.com", "www.amazon.com", "amazon.in", "www.amazon.in",
    # Meta
    "facebook.com", "www.facebook.com", "instagram.com", "www.instagram.com",
    "whatsapp.com", "www.whatsapp.com",
    # Others
    "netflix.com", "www.netflix.com",
    "linkedin.com", "www.linkedin.com",
    "youtube.com", "www.youtube.com",
    "twitter.com", "www.twitter.com", "x.com",
    "wikipedia.org", "www.wikipedia.org",
    "stackoverflow.com", "www.stackoverflow.com",
    "openai.com", "www.openai.com", "chat.openai.com",
    # Indian banks / UPI
    "sbi.co.in", "www.sbi.co.in",
    "hdfcbank.com", "www.hdfcbank.com",
    "icicibank.com", "www.icicibank.com",
    "axisbank.com", "www.axisbank.com",
    "phonepe.com", "www.phonepe.com",
    "paytm.com", "www.paytm.com",
    "npci.org.in", "www.npci.org.in",
}

# =========================================
# SUSPICIOUS KEYWORDS (path + query)
# =========================================

SUSPICIOUS_KEYWORDS = [
    # Auth / credential harvesting
    "login", "signin", "signon", "log-in", "sign-in",
    "verify", "verification", "validate", "confirmation",
    "authenticate", "auth", "2fa", "otp", "captcha",
    "password", "passcode", "passwd", "credential",
    "username", "userid", "email", "recover",

    # Account / security
    "account", "myaccount", "secure", "security",
    "update", "upgrade", "reset", "unlock", "suspended",
    "alert", "warning", "urgent", "important", "finalnotice",
    "limited", "expire", "expir", "block", "restrict",

    # Financial
    "bank", "banking", "payment", "billing", "invoice",
    "refund", "bonus", "gift", "free", "reward",
    "offer", "prize", "claim", "redeem", "cashback",
    "transaction", "transfer", "wire", "swift",
    "creditcard", "debitcard", "atmcard", "cvv", "pin",
    "wallet", "upi", "netbanking",

    # KYC / Identity
    "kyc", "pan", "aadhaar", "passport", "tax",
    "government", "official", "court", "legal", "notice",

    # Delivery scams
    "delivery", "shipment", "parcel", "tracking", "courier",
    "dispatch", "package", "dhl", "fedex", "usps", "bluedart",

    # Subscription / renewal
    "subscription", "renew", "failed", "cancel", "membership",

    # Crypto
    "crypto", "bitcoin", "btc", "ethereum", "binance",
    "investment", "profit", "trading", "wallet",

    # Brand impersonation
    "paypal", "paytm", "phonepe", "gpay", "amazon",
    "netflix", "instagram", "facebook", "whatsapp",
    "telegram", "linkedin", "google", "gmail",
    "outlook", "office365", "microsoft", "apple", "icloud",
    "steam", "github", "dropbox", "onedrive",
    "sbi", "hdfc", "icici", "axisbank", "kotak",
    "yesbank", "pnb", "canara", "unionbank",
    "airtel", "jio", "vodafone", "bsnl", "flipkart",
]

# =========================================
# KNOWN PHISHING BRAND TARGETS
# =========================================

BRAND_TARGETS = [
    "google", "paypal", "amazon", "netflix", "facebook",
    "instagram", "microsoft", "apple", "github", "linkedin",
    "phonepe", "whatsapp", "telegram", "youtube", "gmail",
    "outlook", "office365", "amazonpay", "flipkart", "paytm",
    "gpay", "sbi", "hdfc", "icici", "axisbank", "kotak",
    "yesbank", "canara", "unionbank", "twitter", "tiktok",
    "snapchat", "discord", "dropbox", "onedrive", "icloud",
    "steam", "ebay", "chase", "wellsfargo", "citibank",
]

# Leet-speak / homoglyph substitution map
LEET_MAP = {
    "a": ["4", "@", "а"],   # last is cyrillic а
    "b": ["8", "ь"],
    "c": ["(", "с"],         # cyrillic с
    "e": ["3", "е"],         # cyrillic е
    "g": ["9", "q"],
    "i": ["1", "l", "!", "і"],
    "k": ["x"],
    "l": ["1", "i", "|"],
    "m": ["rn"],
    "n": ["r", "и"],
    "o": ["0", "q", "о"],   # cyrillic о
    "p": ["9"],
    "s": ["5", "$"],
    "t": ["7"],
    "u": ["v", "υ"],
    "w": ["vv"],
    "x": ["×"],
    "z": ["2"],
}

# =========================================
# MODEL BUILD (EXACT SAME AS TRAINING)
# =========================================

if ENABLE_DEEP_LEARNING:
    print("[PhishGuard] Initializing CNN-BiLSTM architecture...")
    model = Sequential()
    model.add(Embedding(input_dim=MAX_WORDS, output_dim=128))
    model.add(Conv1D(filters=128, kernel_size=5, activation="relu"))
    model.add(MaxPooling1D(pool_size=2))
    model.add(Bidirectional(LSTM(64)))
    model.add(Dropout(0.5))
    model.add(Dense(64, activation="relu"))
    model.add(Dense(1, activation="sigmoid"))
    model.build(input_shape=(None, MAX_LEN))

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(BASE_DIR, "phishing_weights.weights.h5")
    tokenizer_path = os.path.join(BASE_DIR, "tokenizer.pkl")

    try:
        model.load_weights(model_path)
        with open(tokenizer_path, "rb") as handle:
            tokenizer = pickle.load(handle)
        print("[PhishGuard] CNN-BiLSTM model and tokenizer loaded successfully.")
    except Exception as e:
        print(f"[PhishGuard] ERROR loading model/tokenizer: {e}")
        print("[PhishGuard] Falling back to FAST MODE (Heuristics Only).")
        ENABLE_DEEP_LEARNING = False
else:
    print("[PhishGuard] FAST MODE ENABLED: Deep Learning disabled.")

# =========================================
# URL PREPROCESSING
# =========================================

def preprocess_url(url):
    """Tokenize and pad URL for CNN-BiLSTM input."""
    sequence = tokenizer.texts_to_sequences([url])
    padded   = pad_sequences(sequence, maxlen=MAX_LEN)
    return padded


def normalize_url(url):
    """Add protocol if missing and lowercase."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.lower()


def extract_domain(url):
    return urlparse(url).netloc.lower()


# =========================================
# STRUCTURAL FEATURE DETECTORS
# =========================================

def has_ip_address(domain):
    return bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}(:\d+)?$", domain))


def count_hyphens(domain):
    return domain.count("-")


def has_suspicious_tld(domain):
    BAD_TLDS = [
        ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
        ".top", ".club", ".work", ".support", ".click",
        ".zip", ".review", ".cam", ".vip", ".rest",
        ".icu", ".monster", ".cyou", ".bond",
    ]
    return any(domain.endswith(t) for t in BAD_TLDS)


def subdomain_depth(domain):
    """Number of dot-separated labels minus TLD + apex."""
    parts = domain.split(".")
    return max(0, len(parts) - 2)


def has_url_shortener(domain):
    SHORTENERS = [
        "bit.ly", "tinyurl.com", "goo.gl", "t.co",
        "is.gd", "cutt.ly", "shorturl.at", "rebrand.ly",
        "ow.ly", "buff.ly", "bl.ink",
    ]
    return any(s in domain for s in SHORTENERS)


def url_entropy(url):
    """Shannon entropy of the URL — high entropy = obfuscated/random."""
    if not url:
        return 0.0
    counts = Counter(url)
    probs  = [c / len(url) for c in counts.values()]
    return -sum(p * math.log2(p) for p in probs if p > 0)


def digit_ratio(url):
    digits = sum(c.isdigit() for c in url)
    return digits / max(len(url), 1)


def special_char_ratio(url):
    specials = sum(1 for c in url if c in "-_.~@!*'();:,/?#[]&=%+$")
    return specials / max(len(url), 1)


def has_punycode(domain):
    return "xn--" in domain


def has_misleading_prefix(domain):
    """Detect patterns like 'google.com.evil.com' or 'paypal-secure.com'."""
    for brand in BRAND_TARGETS:
        # Brand appears but it's not the apex domain
        if brand in domain:
            apex = ".".join(domain.split(".")[-2:])
            if brand not in apex:
                return True
    return False


def path_has_sensitive_data(url):
    """Check if query string or path encodes suspicious params."""
    SENSITIVE_PARAMS = ["redirect", "return", "next", "goto", "url", "redir", "callback"]
    parsed = urlparse(url)
    query  = (parsed.query or "").lower()
    return any(p in query for p in SENSITIVE_PARAMS)


def brand_in_apex_domain(domain):
    """
    Detect the most common phishing pattern:
    A known brand name embedded INSIDE the apex domain label,
    combined with deceptive modifier words.

    Examples:
      paypal-account-update.com  → ('paypal', True)
      amazon-secure-login.xyz    → ('amazon', True)
      netflixupdate.com          → ('netflix', True)
      applehelp.com              → ('apple', False)
    """
    DECEPTIVE_MODIFIERS = [
        "account", "update", "secure", "security", "login", "signin",
        "verify", "verification", "support", "help", "service", "services",
        "online", "web", "portal", "official", "center", "centre",
        "customer", "user", "member", "access", "auth", "banking",
        "alert", "notice", "confirm", "reset", "password", "wallet",
        "payment", "billing", "invoice", "refund", "reward", "claim",
        "recover", "validation", "suspended", "unlock", "upgrade",
    ]

    parts      = domain.split(".")
    apex_label = parts[-2] if len(parts) >= 2 else domain  # e.g. 'paypal-account-update'
    # Flatten hyphens/underscores for substring matching
    apex_flat  = apex_label.replace("-", "").replace("_", "").lower()

    REGEX_MAP = {
        'o': '[o0]', 'a': '[a4@]', 'i': '[i1!l]', 'l': '[l1!i]',
        'e': '[e3]', 's': '[s5$]', 't': '[t7]', 'b': '[b8]',
        'g': '[g9q]', 'c': '[c<k]'
    }

    for brand in BRAND_TARGETS:
        pattern = ''.join(REGEX_MAP.get(c, re.escape(c)) for c in brand)
        match = re.search(pattern, apex_flat)
        if not match:
            continue
        
        # If the apex label is EXCLUSIVELY the brand (handled by whitelist if legit)
        if match.group() == apex_flat:
            continue
            
        # Brand is embedded with extra text
        has_modifier = any(mod in apex_label for mod in DECEPTIVE_MODIFIERS)
        return True, brand, has_modifier

    return False, None, False


# =========================================
# TYPOSQUATTING & HOMOGLYPH DETECTION
# =========================================

def is_typosquatting(domain):
    """
    Returns (bool, brand_name) — detects leet-speak / homoglyph
    substitutions of known brand names in the domain.
    """
    domain = domain.lower()
    
    REGEX_MAP = {
        'o': '[o0]', 'a': '[a4@]', 'i': '[i1!l]', 'l': '[l1!i]',
        'e': '[e3]', 's': '[s5$]', 't': '[t7]', 'b': '[b8]',
        'g': '[g9q]', 'c': '[c<k]'
    }
    
    for brand in BRAND_TARGETS:
        pattern = ''.join(REGEX_MAP.get(c, re.escape(c)) for c in brand)
        match = re.search(pattern, domain)
        
        if match:
            # If the exact original brand name is in the apex, it's legit or whitelist-handled
            apex = ".".join(domain.split(".")[-2:])
            if brand in apex:
                continue
            return True, brand
            
    return False, None


# =========================================
# COMPOSITE RULE SCORE (0-100)
# Designed to complement the DL model:
# - Low score alone → trust the DL output
# - High score → override / boost toward Phishing
# =========================================

def calculate_rule_score(url, domain):
    score = 0
    reasons = []

    # — Hard indicators (near-certain phishing) —
    if has_ip_address(domain):
        score += 40
        reasons.append("IP address used as domain")

    # Brand embedded in apex domain (e.g. paypal-account-update.com)
    in_apex, apex_brand, apex_has_modifier = brand_in_apex_domain(domain)
    if in_apex:
        if apex_has_modifier:
            score += 85  # brand + deceptive word = very strong phishing signal
            reasons.append(f"Brand '{apex_brand}' combined with deceptive word in domain")
        else:
            score += 55
            reasons.append(f"Brand '{apex_brand}' embedded in domain")

    typo, brand = is_typosquatting(domain)
    if typo:
        score += 70
        reasons.append(f"Typosquatting / brand impersonation: {brand}")

    if has_misleading_prefix(domain):
        score += 55
        reasons.append("Brand name used as misleading subdomain")

    if has_punycode(domain):
        score += 40
        reasons.append("Punycode / homoglyph domain")

    # — Structural signals —
    if has_suspicious_tld(domain):
        score += 25
        reasons.append("Suspicious TLD")

    if subdomain_depth(domain) >= 3:
        score += 20
        reasons.append("Excessive subdomain depth")

    if count_hyphens(domain) >= 2:
        score += 15
        reasons.append("Multiple hyphens in domain")

    if has_url_shortener(domain):
        score += 25
        reasons.append("URL shortener used")

    if "@" in url:
        score += 25
        reasons.append("@ symbol in URL")

    parsed = urlparse(url)
    if "//" in (parsed.path or ""):
        score += 15
        reasons.append("Double-slash redirect in path")

    # — Statistical signals —
    entropy = url_entropy(url)
    if entropy > 4.5:
        score += 20
        reasons.append(f"High URL entropy ({entropy:.2f})")

    if digit_ratio(url) > 0.15:
        score += 15
        reasons.append("High digit ratio in URL")

    if special_char_ratio(url) > 0.20:
        score += 10
        reasons.append("High special char ratio")

    if len(url) > 100:
        score += 15
        reasons.append(f"Very long URL ({len(url)} chars)")
    elif len(url) > 75:
        score += 8

    # — Content signals: scan FULL URL (domain + path + query) —
    # This catches brand names in domain, auth words in path, etc.
    full_url_lower = url.lower()
    kw_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url_lower]
    if kw_hits:
        # Diminishing returns — cap keyword boost
        score += min(len(kw_hits) * 7, 35)
        reasons.append(f"Suspicious keywords: {', '.join(kw_hits[:5])}")

    if path_has_sensitive_data(url):
        score += 15
        reasons.append("Redirect/callback parameter detected")

    return score, reasons


# =========================================
# HYBRID SCORING ENGINE
#
# The CNN-BiLSTM model captures learned
# sequential patterns from 235K+ URLs.
# Rule-based layer catches zero-day patterns
# the model may not have seen.
#
# Formula:
#   dl_score   = model sigmoid output × 100
#   rule_score = heuristic analysis (0-100)
#
#   If rule_score >= 60  → weighted blend (rule dominates)
#   If rule_score < 60   → dl_score is the primary signal,
#                          rule_score adds up to +20 boost
# =========================================

def hybrid_score(dl_raw, rule_score, dl_available=True):
    """Fuse CNN-BiLSTM output with rule-based heuristics.
    
    When both engines are available, uses weighted fusion:
      - If both agree (both high or both low) → high-confidence output
      - If they disagree → the stronger signal dominates, weaker adds a boost
    
    When DL is unavailable, rule_score is scaled up to compensate.
    """
    dl_score = dl_raw * 100

    if not dl_available:
        # DL unavailable: rule engine is sole signal, scale it up
        return round(min(rule_score * 1.15, 99))

    # ── Both engines active: weighted fusion ──
    # Weight: DL gets 45%, Rules get 55% (rules catch zero-day better)
    weighted = (dl_score * 0.45) + (rule_score * 0.55)

    # Agreement bonus: if both engines agree, boost confidence
    both_high = dl_score >= 60 and rule_score >= 50
    both_low  = dl_score < 30 and rule_score < 25

    if both_high:
        # Both say phishing → strong agreement boost
        agreement_boost = min(dl_score, rule_score) * 0.20
        weighted = max(weighted, max(dl_score, rule_score)) + agreement_boost
    elif both_low:
        # Both say safe → suppress any noise
        weighted = min(weighted, min(dl_score, rule_score) + 5)
    else:
        # Disagreement: trust the stronger signal, add minor boost from weaker
        stronger = max(dl_score, rule_score)
        weaker   = min(dl_score, rule_score)
        weighted = stronger + (weaker * 0.15)

    return round(min(weighted, 99))


# =========================================
# RECOMMENDATION GENERATOR
# =========================================

def build_recommendation(result, reasons):
    if result == "Phishing":
        base = "⛔ Do NOT open this URL. Strong phishing indicators were detected."
    elif result == "Suspicious":
        base = "⚠️ Proceed with caution. This URL shows suspicious characteristics."
    else:
        base = "✅ This URL appears legitimate based on current analysis."

    if reasons:
        detail = " Detected signals: " + "; ".join(reasons[:3]) + "."
        return base + detail
    return base


# =========================================
# API ROUTE — /predict
# =========================================

@app.route("/predict", methods=["POST", "OPTIONS"])
def predict():
    if request.method == "OPTIONS":
        return jsonify({}), 200

    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "failed", "error": "Invalid JSON or no payload"}), 400

        url = data.get("url", "").strip()

        if not url:
            return jsonify({"status": "failed", "error": "No URL provided"}), 400

        # Normalize
        url_norm = normalize_url(url)
        domain   = extract_domain(url_norm)

        # ── STEP 1: Whitelist check ──────────────────
        if domain in TRUSTED_DOMAINS:
            log_to_global_stats(url, "Safe", 96)
            return jsonify({
                "status":            "success",
                "url":               url,
                "prediction_result": "Safe",
                "confidence_score":  96,
                "risk_level":        "Low",
                "recommendation":    "✅ This URL belongs to a verified trusted domain.",
            })

        # ── STEP 2: Run BOTH engines in parallel ────
        dl_raw = 0.5
        dl_available = False

        # Start DL inference in a thread (non-blocking)
        dl_result = {}
        def run_dl():
            try:
                processed = preprocess_url(url_norm)
                dl_result['score'] = float(model.predict(processed, verbose=0)[0][0])
            except Exception as ex:
                print(f"[PhishGuard] DL inference error: {ex}")

        if ENABLE_DEEP_LEARNING and MODEL_READY:
            dl_thread = threading.Thread(target=run_dl, daemon=True)
            dl_thread.start()
        else:
            dl_thread = None

        # Run heuristics on main thread (instant)
        rule_score, reasons = calculate_rule_score(url_norm, domain)

        # Wait for DL thread to finish (max 5 seconds)
        if dl_thread is not None:
            dl_thread.join(timeout=5.0)
            if 'score' in dl_result:
                dl_raw = dl_result['score']
                dl_available = True
                print(f"[PhishGuard] Hybrid: DL={dl_raw:.3f}, Rules={rule_score}")
            else:
                print(f"[PhishGuard] DL timed out, using rules only (score={rule_score})")

        # ── STEP 3: Hybrid Fusion ───────────────────
        final_score = hybrid_score(dl_raw, rule_score, dl_available)

        # ── STEP 5: Hard overrides ──────────────────
        in_apex, _ab, ab_has_modifier = brand_in_apex_domain(domain)
        if in_apex and ab_has_modifier:
            final_score = max(final_score, 78)
        elif in_apex:
            final_score = max(final_score, 55)

        typo, _brand = is_typosquatting(domain)
        if typo or has_ip_address(domain):
            final_score = max(final_score, 55)

        if has_misleading_prefix(domain) or has_punycode(domain):
            final_score = max(final_score, 62)

        if dl_raw > 0.80:
            final_score = max(final_score, 82)

        # ── STEP 6: Classification ──────────────────
        if final_score >= 70:
            prediction_result = "Phishing"
            risk_level        = "High"
            confidence_score  = final_score
        elif final_score >= 40:
            prediction_result = "Suspicious"
            risk_level        = "Moderate"
            confidence_score  = final_score
        else:
            prediction_result = "Safe"
            risk_level        = "Low"
            confidence_score  = 100 - final_score

        recommendation = build_recommendation(prediction_result, reasons)

        # ── Update Global Stats ────────────────────
        log_to_global_stats(url, prediction_result, confidence_score)

        return jsonify({
            "status":            "success",
            "url":               url,
            "prediction_result": prediction_result,
            "confidence_score":  confidence_score,
            "risk_level":        risk_level,
            "recommendation":    recommendation,
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            "status": "failed",
            "error": f"Internal server error: {str(e)}"
        }), 500


# =========================================
# WARMUP TO PREVENT COLD-START TIMEOUTS
# =========================================
def background_warmup():
    global MODEL_READY
    try:
        print("[PhishGuard] Warming up deep learning model in background...")
        dummy_seq = pad_sequences(tokenizer.texts_to_sequences(["http://example.com"]), maxlen=MAX_LEN)
        model.predict(dummy_seq, verbose=0)
        MODEL_READY = True
        print("[PhishGuard] Model warmed up and ready to serve requests!")
    except Exception as e:
        print("[PhishGuard] Background warmup failed:", e)

if ENABLE_DEEP_LEARNING:
    threading.Thread(target=background_warmup, daemon=True).start()
else:
    MODEL_READY = False

# =========================================
# RUN FLASK APP
# =========================================

if __name__ == "__main__":
    app.run(debug=True, port=5000)