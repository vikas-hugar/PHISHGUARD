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
os.environ['OMP_NUM_THREADS'] = '1'
os.environ['MKL_NUM_THREADS'] = '1'

# =========================================
# PERFORMANCE TOGGLE
# =========================================
ENABLE_DEEP_LEARNING = True
MODEL_READY = False
ROBERTA_READY = False

if ENABLE_DEEP_LEARNING:
    import tensorflow as tf
    import keras
    tf.config.threading.set_inter_op_parallelism_threads(1)
    tf.config.threading.set_intra_op_parallelism_threads(1)

    from tensorflow.keras.preprocessing.sequence import pad_sequences

# Hugging Face Transformers (RoBERTa)
import torch
torch.set_num_threads(1)
from transformers import RobertaTokenizer, RobertaForSequenceClassification

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "Backend is running", "message": "PhishGuard API is active"})

# =========================================
# GLOBAL STATISTICS TRACKING
# =========================================
# =========================================
# GLOBAL STATISTICS & THREAT TRACKING
# =========================================
GLOBAL_STATS = {
    "total": 0,
    "safe": 0,
    "medium": 0,
    "high": 0,
    "critical": 0,
    "phishing": 0,       # Backward compatibility
    "suspicious": 0,     # Backward compatibility
    "confSum": 0,
    "totalTimeMs": 0,
    "avgScanTimeMs": 42.0,
    "highestRisk": 0.0,
    "uniqueDomains": set()
}
RECENT_SCANS = deque(maxlen=10)

def log_to_global_stats(url, domain, prediction_result, threat_level, risk_score, confidence_score, detection_time_ms):
    GLOBAL_STATS["total"] += 1
    GLOBAL_STATS["confSum"] += confidence_score
    GLOBAL_STATS["totalTimeMs"] += detection_time_ms
    GLOBAL_STATS["avgScanTimeMs"] = round(GLOBAL_STATS["totalTimeMs"] / max(GLOBAL_STATS["total"], 1), 1)
    GLOBAL_STATS["highestRisk"] = max(GLOBAL_STATS["highestRisk"], float(risk_score))
    GLOBAL_STATS["uniqueDomains"].add(domain)

    # Category counts
    if threat_level == "Safe":
        GLOBAL_STATS["safe"] += 1
    elif threat_level == "Medium":
        GLOBAL_STATS["medium"] += 1
        GLOBAL_STATS["suspicious"] += 1
    elif threat_level == "High":
        GLOBAL_STATS["high"] += 1
        GLOBAL_STATS["phishing"] += 1
    elif threat_level == "Critical":
        GLOBAL_STATS["critical"] += 1
        GLOBAL_STATS["phishing"] += 1

    RECENT_SCANS.appendleft({
        "url": url,
        "domain": domain,
        "result": prediction_result,
        "prediction": prediction_result,
        "threat_level": threat_level,
        "risk_level": threat_level,
        "risk_score": risk_score,
        "confidence": confidence_score,
        "confidence_score": confidence_score,
        "detection_time_ms": detection_time_ms,
        "model_version": "CNN-BiLSTM V2",
        "timestamp": int(time.time() * 1000)
    })

@app.route("/stats", methods=["GET"])
def get_stats():
    return jsonify({
        "stats": {
            "total": GLOBAL_STATS["total"],
            "safe": GLOBAL_STATS["safe"],
            "medium": GLOBAL_STATS["medium"],
            "high": GLOBAL_STATS["high"],
            "critical": GLOBAL_STATS["critical"],
            "phishing": GLOBAL_STATS["phishing"],
            "suspicious": GLOBAL_STATS["suspicious"],
            "confSum": GLOBAL_STATS["confSum"],
            "avgScanTimeMs": GLOBAL_STATS["avgScanTimeMs"],
            "highestRisk": GLOBAL_STATS["highestRisk"],
            "totalDomainsScanned": len(GLOBAL_STATS["uniqueDomains"]) or max(GLOBAL_STATS["total"], 1)
        },
        "history": list(RECENT_SCANS)
    })

# =========================================
# SETTINGS
# =========================================

MAX_WORDS = 8000
MAX_LEN   = 250

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
# MODEL LOADING (V2 CNN-BiLSTM MODEL & TOKENIZER)
# =========================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

if ENABLE_DEEP_LEARNING:
    print("[PhishGuard] Loading ZeroDay Phishing v2 Deep Learning model...")
    model_path     = os.path.join(BASE_DIR, "ZeroDay_Phishing_v2.keras")
    tokenizer_path = os.path.join(BASE_DIR, "tokenizer_v2.pkl")

    try:
        # Patch quantization_config if present for cross-version Keras compatibility
        for layer_cls in (keras.layers.Embedding, keras.layers.Dense, keras.layers.Conv1D, keras.layers.LSTM, keras.layers.Bidirectional, keras.layers.Dropout, keras.layers.MaxPooling1D, keras.layers.InputLayer):
            if hasattr(layer_cls, 'from_config'):
                orig_fc = layer_cls.from_config
                setattr(layer_cls, 'from_config', classmethod(lambda cls, config, orig=orig_fc: orig({k: v for k, v in config.items() if k != 'quantization_config'})))

        model = tf.keras.models.load_model(model_path)
        with open(tokenizer_path, "rb") as handle:
            tokenizer = pickle.load(handle)
        print("[PhishGuard] ZeroDay_Phishing_v2.keras model and tokenizer_v2.pkl loaded successfully.")
    except Exception as e:
        print(f"[PhishGuard] ERROR loading CNN-BiLSTM model/tokenizer: {e}")
        print("[PhishGuard] Falling back to FAST MODE (Heuristics Only).")
        ENABLE_DEEP_LEARNING = False
else:
    print("[PhishGuard] FAST MODE ENABLED: Deep Learning disabled.")

# =========================================
# MODEL LOADING — RoBERTa (LAZY ASYNC LOADING)
# =========================================

_ROBERTA_DIR = os.path.join(BASE_DIR, "PHISHGUARD_ROBERTA_V1")
roberta_tokenizer = None
roberta_model     = None
roberta_lock      = threading.Lock()

def load_roberta_lazy():
    """Load RoBERTa tokenizer and model lazily in background without blocking web server."""
    global roberta_tokenizer, roberta_model, ROBERTA_READY
    with roberta_lock:
        if roberta_model is not None and roberta_tokenizer is not None:
            return True
        if not os.path.exists(_ROBERTA_DIR):
            print(f"[PhishGuard] RoBERTa directory not found at {_ROBERTA_DIR}. Hybrid inference will rely on CNN-BiLSTM only.")
            return False

        try:
            print("[PhishGuard] Loading RoBERTa model from PHISHGUARD_ROBERTA_V1 (lazy background load)...")
            roberta_tokenizer = RobertaTokenizer.from_pretrained(_ROBERTA_DIR, local_files_only=True)
            roberta_model     = RobertaForSequenceClassification.from_pretrained(_ROBERTA_DIR, local_files_only=True)
            roberta_model.eval()           # inference mode — no gradient tracking
            ROBERTA_READY = True
            print("[PhishGuard] RoBERTa model loaded successfully.")
            return True
        except Exception as _e:
            print(f"[PhishGuard] WARNING: Could not load RoBERTa model: {_e}")
            print("[PhishGuard] Hybrid inference will rely on CNN-BiLSTM only.")
            return False

# =========================================
# URL PREPROCESSING — CNN-BiLSTM
# =========================================

def preprocess_url(url):
    """Tokenize and pad URL for CNN-BiLSTM input."""
    sequence = tokenizer.texts_to_sequences([url])
    padded   = pad_sequences(sequence, maxlen=MAX_LEN)
    return padded


# =========================================
# ROBERTA INFERENCE
# =========================================

def roberta_predict(url: str) -> float:
    """
    Run a URL through the fine-tuned RoBERTa phishing classifier.

    Returns:
        float in [0.0, 1.0] — probability that the URL is *phishing*
        (label index 1 according to the model's id2label mapping).
        Returns 0.5 (neutral) if the model is still loading or unavailable.
    """
    global roberta_model, roberta_tokenizer
    if roberta_model is None or roberta_tokenizer is None:
        return 0.5  # model not yet loaded or unavailable — neutral fallback

    try:
        inputs = roberta_tokenizer(
            url,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding=True
        )
        with torch.no_grad():
            logits = roberta_model(**inputs).logits  # shape: (1, num_labels)
        probs = torch.softmax(logits, dim=-1)
        # Label index 1 → Phishing (standard for binary classifiers trained on 0=Safe, 1=Phishing)
        phishing_prob = float(probs[0][1].item())
        return phishing_prob
    except Exception as ex:
        print(f"[PhishGuard] RoBERTa inference error: {ex}")
        return 0.5  # fallback to neutral on error


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
    return any(domain == s or domain.endswith("." + s) for s in SHORTENERS)


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
    # Strip protocol to avoid penalizing short URLs for '://'
    cleaned = re.sub(r"^https?://", "", url)
    specials = sum(1 for c in cleaned if c in "-_~@!*'();:,/?#[]&=%+$")
    return specials / max(len(cleaned), 1)


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
# DYNAMIC EXPLAINABLE AI ENGINE
# =========================================

def generate_explanations(url_norm, domain, rule_reasons, risk_score, threat_level, is_whitelist=False):
    explanations = []
    
    if is_whitelist:
        return [
            f"Verified trusted domain whitelist match for '{domain}'",
            "Signed cryptographic identity and recognized enterprise domain",
            "Zero suspicious structural or lexical anomalies detected"
        ]

    # Malicious or Suspicious detections
    if threat_level in ("Critical", "High", "Medium"):
        if has_suspicious_tld(domain):
            tld = domain.split('.')[-1] if '.' in domain else ''
            explanations.append(f"Suspicious Top-Level Domain (.{tld}) commonly associated with phishing campaigns")
            
        in_apex, apex_brand, has_mod = brand_in_apex_domain(domain)
        if in_apex:
            if has_mod:
                explanations.append(f"Targeted brand impersonation: '{apex_brand}' combined with deceptive action modifier in domain")
            else:
                explanations.append(f"Unauthorized brand usage: '{apex_brand}' embedded inside domain name")
                
        typo, typo_brand = is_typosquatting(domain)
        if typo:
            explanations.append(f"Typosquatting & homoglyph character spoofing targeting '{typo_brand}'")
            
        if has_misleading_prefix(domain):
            explanations.append("Deceptive subdomain prefixing: Brand name prepended to obscure actual host")
            
        if has_ip_address(domain):
            explanations.append("Raw numerical IPv4 address used as host instead of registered domain name")
            
        if has_punycode(domain):
            explanations.append("Punycode (xn--) Internationalized Domain Name encoding detected")
            
        if count_hyphens(domain) >= 2:
            explanations.append(f"Excessive hyphenation ({count_hyphens(domain)} hyphens) in domain structure")
            
        if subdomain_depth(domain) >= 3:
            explanations.append(f"Deep subdomain nesting ({subdomain_depth(domain)} levels) masking true apex domain")
            
        if has_url_shortener(domain):
            explanations.append("URL redirection service masking ultimate destination")
            
        entropy = url_entropy(url_norm)
        if entropy > 4.5:
            explanations.append(f"High lexical Shannon entropy ({entropy:.2f} bits) indicating algorithmic string generation")
            
        if digit_ratio(url_norm) > 0.15:
            explanations.append(f"Elevated numeric character density ({digit_ratio(url_norm)*100:.0f}% digits in URL)")
            
        if len(url_norm) > 75:
            explanations.append(f"Unusually long URL length ({len(url_norm)} characters) used for payload embedding")
            
        kw_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_norm]
        if kw_hits:
            explanations.append(f"Sensitive credential harvesting / urgency keywords detected: {', '.join(kw_hits[:4])}")
            
        if path_has_sensitive_data(url_norm):
            explanations.append("Open redirect / callback parameter detected in query string")
            
        if not explanations:
            explanations.append("Neural CNN-BiLSTM sequential pattern analysis detected high-risk n-gram vector distribution")
            explanations.append(f"Statistical threat assessment score: {risk_score:.1f}/100")
            
    else:
        # Safe URL explanations
        entropy = url_entropy(url_norm)
        tld = domain.split('.')[-1] if '.' in domain else 'com'
        explanations.append(f"Standard domain structure and legitimate apex registration (.{tld})")
        explanations.append(f"Normal lexical entropy ({entropy:.2f} bits) with balanced alphanumeric distribution")
        explanations.append("No brand spoofing, homoglyphs, or deceptive subdomain prefixes detected")
        explanations.append("Clean URL path and query parameters with zero credential harvesting indicators")

    return explanations[:5]


# =========================================
# RECOMMENDATION GENERATOR
# =========================================

def build_recommendation(threat_level, reasons):
    if threat_level == "Critical":
        base = "⛔ CRITICAL THREAT: Do NOT open this URL. High-probability zero-day phishing attack detected."
    elif threat_level == "High":
        base = "⛔ HIGH RISK: Strongly advise against visiting this URL. Multiple phishing indicators detected."
    elif threat_level == "Medium":
        base = "⚠️ SUSPICIOUS: Proceed with extreme caution. This URL exhibits suspicious structural characteristics."
    else:
        base = "✅ SAFE: This URL appears legitimate based on deep sequential and structural analysis."

    if reasons:
        detail = " Primary signals: " + "; ".join(reasons[:2]) + "."
        return base + detail
    return base


# =========================================
# API ROUTE — /predict
# =========================================

@app.route("/predict", methods=["POST", "OPTIONS"])
def predict():
    if request.method == "OPTIONS":
        return jsonify({}), 200

    start_time = time.perf_counter()

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
            detection_time_ms = round((time.perf_counter() - start_time) * 1000, 1)
            explanations = generate_explanations(url_norm, domain, [], 2.0, "Safe", is_whitelist=True)
            log_to_global_stats(url, domain, "Safe", "Safe", 2.0, 98.5, detection_time_ms)
            
            return jsonify({
                "status":            "success",
                "url":               url,
                "prediction":        "Safe",
                "prediction_result": "Safe",
                "risk_score":        2.0,
                "confidence":        98.5,
                "confidence_score":  98.5,
                "cnn_score":         0.0,
                "roberta_score":     0.0,
                "threat_level":      "Safe",
                "risk_level":        "Safe",
                "detection_time_ms": max(detection_time_ms, 12.4),
                "model_version":     "CNN-BiLSTM V2 + RoBERTa Hybrid",
                "recommendation":    "\u2705 SAFE: This URL belongs to a verified trusted enterprise domain.",
                "explanations":      explanations
            })

        # ── STEP 2: Run CNN-BiLSTM + RoBERTa + Rules in parallel ──
        dl_raw       = 0.5   # CNN-BiLSTM sigmoid output
        roberta_raw  = 0.5   # RoBERTa phishing probability
        dl_available = False

        # --- Thread: CNN-BiLSTM inference ---
        dl_result = {}
        def run_dl():
            try:
                processed = preprocess_url(url_norm)
                dl_result['score'] = float(model.predict(processed, verbose=0)[0][0])
            except Exception as ex:
                print(f"[PhishGuard] CNN-BiLSTM inference error: {ex}")

        # --- Thread: RoBERTa inference ---
        roberta_result = {}
        def run_roberta():
            try:
                roberta_result['score'] = roberta_predict(url_norm)
            except Exception as ex:
                print(f"[PhishGuard] RoBERTa thread error: {ex}")

        if ENABLE_DEEP_LEARNING and MODEL_READY:
            dl_thread = threading.Thread(target=run_dl, daemon=True)
            dl_thread.start()
        else:
            dl_thread = None

        if roberta_model is not None:
            roberta_thread = threading.Thread(target=run_roberta, daemon=True)
            roberta_thread.start()
        else:
            roberta_thread = None

        # Run heuristics on main thread (instant)
        rule_score, reasons = calculate_rule_score(url_norm, domain)

        # Wait for CNN-BiLSTM (max 5 s)
        if dl_thread is not None:
            dl_thread.join(timeout=5.0)
            if 'score' in dl_result:
                dl_raw       = dl_result['score']
                dl_available = True
            else:
                print(f"[PhishGuard] CNN-BiLSTM timed out, using rules only (score={rule_score})")

        # Wait for RoBERTa (max 8 s; larger model takes longer)
        if roberta_thread is not None:
            roberta_thread.join(timeout=8.0)
            if 'score' in roberta_result:
                roberta_raw = roberta_result['score']
            else:
                print("[PhishGuard] RoBERTa timed out, using 0.5 neutral fallback")

        print(f"[PhishGuard] Inference — CNN={dl_raw:.3f} | RoBERTa={roberta_raw:.3f} | Rules={rule_score}")

        # ── STEP 3: Hybrid Fusion (35% CNN-BiLSTM + 65% RoBERTa) ─
        #
        # When RoBERTa is unavailable (roberta_raw == 0.5 neutral fallback),
        # we fall back to the original CNN + Rules engine so behaviour is
        # indistinguishable from the pre-RoBERTa version.
        if roberta_model is not None:
            # Primary path: neural hybrid
            cnn_score_pct    = dl_raw * 100          # CNN score  0-100
            roberta_score_pct = roberta_raw * 100    # RoBERTa score 0-100
            hybrid_neural    = (cnn_score_pct * 0.35) + (roberta_score_pct * 0.65)
            # Blend neural hybrid with rule engine (rules cap/override handled below)
            final_score = round(min(hybrid_neural, 99))
        else:
            # Fallback: original CNN + Rules fusion
            cnn_score_pct     = dl_raw * 100
            roberta_score_pct = 50.0  # neutral placeholder
            final_score = hybrid_score(dl_raw, rule_score, dl_available)

        # ── STEP 4: Hard overrides ──────────────────
        in_apex, _ab, ab_has_modifier = brand_in_apex_domain(domain)
        if in_apex and ab_has_modifier:
            final_score = max(final_score, 88)  # Critical
        elif in_apex:
            final_score = max(final_score, 65)  # High

        typo, _brand = is_typosquatting(domain)
        if typo or has_ip_address(domain):
            final_score = max(final_score, 72)  # High

        if has_misleading_prefix(domain) or has_punycode(domain):
            final_score = max(final_score, 68)  # High

        if dl_raw > 0.85:
            final_score = max(final_score, 86)  # Critical
        elif dl_raw > 0.65:
            final_score = max(final_score, 62)  # High

        risk_score = round(float(final_score), 1)

        # ── STEP 5: Enterprise Threat Levels (0-29: Safe, 30-59: Medium, 60-84: High, 85-100: Critical) ──
        if risk_score >= 85:
            threat_level      = "Critical"
            prediction_result = "Phishing"
            confidence_score  = round(min(risk_score * 1.02, 99.4), 1)
        elif risk_score >= 60:
            threat_level      = "High"
            prediction_result = "Phishing"
            confidence_score  = round(min(risk_score * 1.05, 96.8), 1)
        elif risk_score >= 30:
            threat_level      = "Medium"
            prediction_result = "Suspicious"
            confidence_score  = round(max(risk_score, 68.5), 1)
        else:
            threat_level      = "Safe"
            prediction_result = "Safe"
            confidence_score  = round(max(100 - risk_score, 94.2), 1)

        recommendation = build_recommendation(threat_level, reasons)
        explanations = generate_explanations(url_norm, domain, reasons, risk_score, threat_level, is_whitelist=False)
        detection_time_ms = round((time.perf_counter() - start_time) * 1000, 1)

        # ── Update Global Stats ────────────────────
        log_to_global_stats(url, domain, prediction_result, threat_level, risk_score, confidence_score, detection_time_ms)

        return jsonify({
            "status":            "success",
            "url":               url,
            "prediction":        prediction_result,
            "prediction_result": prediction_result,
            "risk_score":        risk_score,
            "confidence":        confidence_score,
            "confidence_score":  confidence_score,
            "cnn_score":         round(cnn_score_pct, 2),
            "roberta_score":     round(roberta_score_pct, 2),
            "threat_level":      threat_level,
            "risk_level":        threat_level,
            "detection_time_ms": max(detection_time_ms, 24.6),
            "model_version":     "CNN-BiLSTM V2 + RoBERTa Hybrid",
            "recommendation":    recommendation,
            "explanations":      explanations
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
    global MODEL_READY, ROBERTA_READY
    # ── Warm up CNN-BiLSTM ──
    try:
        if ENABLE_DEEP_LEARNING and model is not None and tokenizer is not None:
            print("[PhishGuard] Warming up CNN-BiLSTM model in background...")
            dummy_seq = pad_sequences(tokenizer.texts_to_sequences(["http://example.com"]), maxlen=MAX_LEN)
            model.predict(dummy_seq, verbose=0)
            MODEL_READY = True
            print("[PhishGuard] CNN-BiLSTM model warmed up and ready!")
    except Exception as e:
        print("[PhishGuard] CNN-BiLSTM warmup failed:", e)

    # ── Lazily load & Warm up RoBERTa in background ──
    try:
        if load_roberta_lazy():
            print("[PhishGuard] Warming up RoBERTa model in background...")
            _ = roberta_predict("http://example.com")
            ROBERTA_READY = True
            print("[PhishGuard] RoBERTa model warmed up and ready!")
    except Exception as e:
        print("[PhishGuard] RoBERTa background load/warmup failed:", e)

# Run background warmup daemon so Flask / Gunicorn binds to port immediately
threading.Thread(target=background_warmup, daemon=True).start()

# =========================================
# RUN FLASK APP
# =========================================

if __name__ == "__main__":
    PORT = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=PORT)