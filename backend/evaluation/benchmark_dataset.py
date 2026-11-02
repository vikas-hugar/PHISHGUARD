"""
PhishGuard AI V6.1 — Multi-Category Benchmark Evaluation Dataset
================================================================
Comprehensive, domain-separated evaluation dataset covering:
  Set A: Legitimate (whitelisted & standard clean domains)
  Set B: Known Phishing (threat repository matches)
  Set C: Unseen/Zero-Day-like (novel credential harvesters)
  Set D: Typosquatting (omissions, transpositions, phonetic, leetspeak)
  Set E: Homoglyph (character substitutions)
  Set F: Punycode (IDN homograph attacks)
  Set G: Misleading Subdomain (brand in sub-host on attacker apex)
  Set H: Obfuscation & Malicious Host (IP-host, @ masking, double-slash)
  Set I: Adversarial Legitimate (FP Protection: login, crypto, secure keywords on real domains)
  Set J: SSRF Security Guard (Loopback, private RFC1918, cloud metadata)

Total test cases: 32 items with ground truth labels and category metadata.
"""

BENCHMARK_DATASET = [
    # ── Set A: Legitimate (Whitelisted & Clean) ───────────────────────────
    {
        "id": "A1",
        "url": "https://google.com",
        "category": "A. Legitimate",
        "ground_truth": "LEGITIMATE",
        "acceptable_verdicts": ["Legitimate"],
        "notes": "Verified enterprise domain"
    },
    {
        "id": "A2",
        "url": "https://youtube.com",
        "category": "A. Legitimate",
        "ground_truth": "LEGITIMATE",
        "acceptable_verdicts": ["Legitimate"],
        "notes": "Official YouTube domain"
    },
    {
        "id": "A3",
        "url": "https://github.com/explore",
        "category": "A. Legitimate",
        "ground_truth": "LEGITIMATE",
        "acceptable_verdicts": ["Legitimate"],
        "notes": "Official GitHub repository explorer"
    },
    {
        "id": "A4",
        "url": "https://wikipedia.org",
        "category": "A. Legitimate",
        "ground_truth": "LEGITIMATE",
        "acceptable_verdicts": ["Legitimate"],
        "notes": "Standard high-reputation domain"
    },
    {
        "id": "A5",
        "url": "https://stackoverflow.com/questions",
        "category": "A. Legitimate",
        "ground_truth": "LEGITIMATE",
        "acceptable_verdicts": ["Legitimate"],
        "notes": "Developer forum clean domain"
    },

    # ── Set B: Known Phishing (SQLite Threat Repo Matches) ─────────────────
    {
        "id": "B1",
        "url": "http://ledger-com-strts.pages.dev/",
        "category": "B. Known Phishing",
        "ground_truth": "PHISHING",
        "acceptable_verdicts": ["Known Phishing", "Zero-Day Phishing"],
        "notes": "Exact indexed entry in threat repository"
    },
    {
        "id": "B2",
        "url": "http://square-nddax-en-us.square.site/",
        "category": "B. Known Phishing",
        "ground_truth": "PHISHING",
        "acceptable_verdicts": ["Known Phishing", "Zero-Day Phishing"],
        "notes": "Indexed malicious credential harvester in SQLite repository"
    },

    # ── Set C: Unseen / Zero-Day-like Phishing ─────────────────────────────
    {
        "id": "C1",
        "url": "http://my-crypto-security-wallet.xyz/confirm",
        "category": "C. Zero-Day-like / Suspicious",
        "ground_truth": "SUSPICIOUS_OR_PHISHING",
        "acceptable_verdicts": ["Suspicious", "Zero-Day Phishing"],
        "notes": "Generic cryptocurrency keywords on high-risk TLD (.xyz)"
    },
    {
        "id": "C2",
        "url": "http://secure-chase-update-verification.top/auth",
        "category": "C. Zero-Day Phishing",
        "ground_truth": "PHISHING",
        "acceptable_verdicts": ["Zero-Day Phishing"],
        "notes": "Novel banking impersonation targeting Chase Bank"
    },
    {
        "id": "C3",
        "url": "http://apple-id-verify-locked-account.live/login",
        "category": "C. Zero-Day Phishing",
        "ground_truth": "PHISHING",
        "acceptable_verdicts": ["Zero-Day Phishing"],
        "notes": "Apple ID credential harvesting portal on .live TLD"
    },

    # ── Set D: Typosquatting ──────────────────────────────────────────────
    {
        "id": "D1",
        "url": "http://uuttubte.com",
        "category": "D. Typosquatting",
        "ground_truth": "PHISHING",
        "acceptable_verdicts": ["Zero-Day Phishing", "Suspicious"],
        "notes": "Phonetic / repeated character squatting against YouTube"
    },
    {
        "id": "D2",
        "url": "http://paypa1.com",
        "category": "D. Typosquatting",
        "ground_truth": "PHISHING",
        "acceptable_verdicts": ["Zero-Day Phishing"],
        "notes": "Digit substitution (l -> 1) against PayPal"
    },
    {
        "id": "D3",
        "url": "http://micros0ft.com",
        "category": "D. Typosquatting",
        "ground_truth": "PHISHING",
        "acceptable_verdicts": ["Zero-Day Phishing"],
        "notes": "Digit substitution (o -> 0) against Microsoft"
    },
    {
        "id": "D4",
        "url": "http://aaappllle.com",
        "category": "D. Typosquatting",
        "ground_truth": "PHISHING",
        "acceptable_verdicts": ["Zero-Day Phishing"],
        "notes": "Character repetition squatting against Apple"
    },

    # ── Set E: Homoglyph Attacks ──────────────────────────────────────────
    {
        "id": "E1",
        "url": "http://g00gle.com",
        "category": "E. Homoglyph",
        "ground_truth": "PHISHING",
        "acceptable_verdicts": ["Zero-Day Phishing"],
        "notes": "Homoglyph zero substitutions targeting Google"
    },
    {
        "id": "E2",
        "url": "http://goog1e.com",
        "category": "E. Homoglyph",
        "ground_truth": "PHISHING",
        "acceptable_verdicts": ["Zero-Day Phishing"],
        "notes": "Digit 1 for letter l homoglyph targeting Google"
    },

    # ── Set F: Punycode (IDN Spoofing) ───────────────────────────────────
    {
        "id": "F1",
        "url": "http://xn--pple-43d.com",
        "category": "F. Punycode",
        "ground_truth": "PHISHING",
        "acceptable_verdicts": ["Zero-Day Phishing"],
        "notes": "Cyrillic a punycode spoof targeting Apple"
    },
    {
        "id": "F2",
        "url": "http://xn--gogle-pqa.com",
        "category": "F. Punycode",
        "ground_truth": "PHISHING",
        "acceptable_verdicts": ["Zero-Day Phishing"],
        "notes": "IDN punycode spoof targeting Google"
    },

    # ── Set G: Misleading Subdomain ───────────────────────────────────────
    {
        "id": "G1",
        "url": "http://youtube.com.attacker-example.com/watch",
        "category": "G. Misleading Subdomain",
        "ground_truth": "PHISHING",
        "acceptable_verdicts": ["Zero-Day Phishing", "Suspicious"],
        "notes": "Brand in subdomain on attacker-controlled apex domain"
    },
    {
        "id": "G2",
        "url": "http://paypal.com.secure-portal-update.com/signin",
        "category": "G. Misleading Subdomain",
        "ground_truth": "PHISHING",
        "acceptable_verdicts": ["Zero-Day Phishing"],
        "notes": "Brand in subdomain with credential path on deceptive apex"
    },

    # ── Set H: Obfuscation & IP Hosts ────────────────────────────────────
    {
        "id": "H1",
        "url": "http://93.184.216.34/login/verify.php",
        "category": "H. Obfuscation & IP Host",
        "ground_truth": "SUSPICIOUS_OR_PHISHING",
        "acceptable_verdicts": ["Suspicious", "Zero-Day Phishing"],
        "notes": "Direct public IP used as host with credential harvesting path"
    },
    {
        "id": "H2",
        "url": "http://netflix.com@attacker-portal.net/verify",
        "category": "H. Obfuscation & Masking",
        "ground_truth": "SUSPICIOUS_OR_PHISHING",
        "acceptable_verdicts": ["Suspicious", "Zero-Day Phishing"],
        "notes": "@ symbol destination masking attempt"
    },

    # ── Set I: Adversarial Legitimate (False-Positive Protection) ────────
    {
        "id": "I1",
        "url": "https://login.microsoftonline.com",
        "category": "I. Adversarial Legitimate",
        "ground_truth": "LEGITIMATE",
        "acceptable_verdicts": ["Legitimate"],
        "notes": "Real login portal with 'login' in subdomain"
    },
    {
        "id": "I2",
        "url": "https://crypto.com",
        "category": "I. Adversarial Legitimate",
        "ground_truth": "LEGITIMATE",
        "acceptable_verdicts": ["Legitimate"],
        "notes": "Legitimate domain with 'crypto' keyword"
    },
    {
        "id": "I3",
        "url": "https://secure.chase.com",
        "category": "I. Adversarial Legitimate",
        "ground_truth": "LEGITIMATE",
        "acceptable_verdicts": ["Legitimate"],
        "notes": "Legitimate banking domain with 'secure' keyword"
    },
    {
        "id": "I4",
        "url": "https://developer.mozilla.org",
        "category": "I. Adversarial Legitimate",
        "ground_truth": "LEGITIMATE",
        "acceptable_verdicts": ["Legitimate"],
        "notes": "Developer documentation clean apex"
    },
    {
        "id": "I5",
        "url": "https://wallets.polygon.technology",
        "category": "I. Adversarial Legitimate",
        "ground_truth": "LEGITIMATE",
        "acceptable_verdicts": ["Legitimate"],
        "notes": "Legitimate domain with 'wallet' keyword"
    },

    # ── Set J: SSRF Security Guard (Must be Blocked at Boundary) ──────────
    {
        "id": "J1",
        "url": "http://127.0.0.1:5000/internal-admin",
        "category": "J. SSRF Security Guard",
        "ground_truth": "SECURITY_BLOCK",
        "acceptable_verdicts": ["BLOCKED"],
        "notes": "Loopback address SSRF attempt"
    },
    {
        "id": "J2",
        "url": "http://localhost/secret",
        "category": "J. SSRF Security Guard",
        "ground_truth": "SECURITY_BLOCK",
        "acceptable_verdicts": ["BLOCKED"],
        "notes": "Localhost hostname SSRF attempt"
    },
    {
        "id": "J3",
        "url": "http://192.168.1.1/admin",
        "category": "J. SSRF Security Guard",
        "ground_truth": "SECURITY_BLOCK",
        "acceptable_verdicts": ["BLOCKED"],
        "notes": "RFC1918 Private IPv4 address"
    },
    {
        "id": "J4",
        "url": "http://10.0.0.1/aws-keys",
        "category": "J. SSRF Security Guard",
        "ground_truth": "SECURITY_BLOCK",
        "acceptable_verdicts": ["BLOCKED"],
        "notes": "RFC1918 10.x.x.x private address"
    },
    {
        "id": "J5",
        "url": "http://169.254.169.254/latest/meta-data/",
        "category": "J. SSRF Security Guard",
        "ground_truth": "SECURITY_BLOCK",
        "acceptable_verdicts": ["BLOCKED"],
        "notes": "Cloud instance metadata endpoint"
    },
]
