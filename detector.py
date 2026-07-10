"""
Phishing Detection Engine
Uses a weighted heuristic scoring system to classify a URL as:
  - SAFE       (score < 30)
  - SUSPICIOUS (score 30–59)
  - DANGEROUS  (score >= 60)
"""

from features import extract_features

# ── Weight table ──────────────────────────────────────────────────────────────
# Each feature maps to a risk weight (positive = riskier).
# Binary features (0/1) are multiplied directly.
# Count features are multiplied by weight per unit.
WEIGHTS = {
    "uses_https":               -20,   # HTTPS lowers risk
    "long_url":                  15,   # URL > 75 chars
    "has_ip":                    30,   # raw IP instead of domain
    "has_at_symbol":             25,   # @ in URL
    "double_slash_redirect":     20,   # // redirect trick
    "dash_in_domain":            10,   # hyphen in domain name
    "suspicious_tld":            20,   # .tk, .ml, .xyz etc.
    "is_shortened":              35,   # bit.ly, tinyurl etc.
    "has_suspicious_keyword":    20,   # login, verify, paypal…
    "has_hex_encoding":          15,   # %XX encoding in URL
    # per-unit weights
    "subdomain_count":            8,   # each extra subdomain level
    "suspicious_keyword_count":   5,   # each additional suspicious keyword
    "special_char_count":         3,   # each special char beyond normal
    "digits_in_domain":           3,   # each digit in domain name
    "dot_count":                  2,   # each extra dot
}

# Thresholds
THRESHOLD_SAFE       = 30
THRESHOLD_SUSPICIOUS = 60

RISK_LEVELS = {
    "SAFE":       {"label": "SAFE",       "color": "#2ecc71", "emoji": "✅"},
    "SUSPICIOUS": {"label": "SUSPICIOUS", "color": "#f39c12", "emoji": "⚠️"},
    "DANGEROUS":  {"label": "DANGEROUS",  "color": "#e74c3c", "emoji": "🚨"},
}


def analyze_url(url: str) -> dict:
    """
    Analyze a URL and return a full report dict containing:
      - features   : raw extracted features
      - score      : integer risk score (0–100 clamped)
      - risk_level : 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS'
      - breakdown  : list of (reason, points) tuples for UI display
      - color      : hex color for the risk level
      - emoji      : emoji for the risk level
    """
    if not url or not url.strip():
        return _error_result("Please enter a URL.")

    features = extract_features(url.strip())
    if not features:
        return _error_result("Could not parse the URL. Check the format.")

    score = 0
    breakdown = []

    # ── Binary features ───────────────────────────────────────────────────
    binary_features = [
        "uses_https", "long_url", "has_ip", "has_at_symbol",
        "double_slash_redirect", "dash_in_domain", "suspicious_tld",
        "is_shortened", "has_suspicious_keyword", "has_hex_encoding",
    ]
    labels = {
        "uses_https":              "Uses HTTPS",
        "long_url":                "Unusually long URL (>75 chars)",
        "has_ip":                  "IP address used instead of domain",
        "has_at_symbol":           "@ symbol in URL",
        "double_slash_redirect":   "Double-slash redirect detected",
        "dash_in_domain":          "Hyphen (-) in domain name",
        "suspicious_tld":          "Suspicious top-level domain (.tk/.ml etc.)",
        "is_shortened":            "URL shortener service detected",
        "has_suspicious_keyword":  "Phishing keyword in URL",
        "has_hex_encoding":        "Hex/percent encoding in URL",
    }

    for feat in binary_features:
        val = features.get(feat, 0)
        w = WEIGHTS[feat]
        points = val * w
        score += points
        if points != 0:
            breakdown.append((labels[feat], points))

    # ── Count / scaled features ───────────────────────────────────────────
    count_features = {
        "subdomain_count":          ("Subdomain depth",         WEIGHTS["subdomain_count"]),
        "suspicious_keyword_count": ("Suspicious keyword count", WEIGHTS["suspicious_keyword_count"]),
        "special_char_count":       ("Special characters in URL", WEIGHTS["special_char_count"]),
        "digits_in_domain":         ("Digits in domain name",    WEIGHTS["digits_in_domain"]),
        "dot_count":                ("Dot count in URL",         WEIGHTS["dot_count"]),
    }

    for feat, (label, weight) in count_features.items():
        val = features.get(feat, 0)
        # Baseline: subdomain_count=1 and dot_count<=3 are normal, don't penalize those
        if feat == "subdomain_count":
            val = max(0, val - 1)
        if feat == "dot_count":
            val = max(0, val - 2)
        points = val * weight
        score += points
        if points > 0:
            breakdown.append((f"{label} ({features.get(feat, 0)})", points))

    # Clamp score to [0, 100]
    score = max(0, min(100, score))

    # Determine risk level
    if score < THRESHOLD_SAFE:
        risk = "SAFE"
    elif score < THRESHOLD_SUSPICIOUS:
        risk = "SUSPICIOUS"
    else:
        risk = "DANGEROUS"

    # Sort breakdown: biggest contributors first (show positives, skip negatives for clarity)
    positive_breakdown = [(r, p) for r, p in breakdown if p > 0]
    positive_breakdown.sort(key=lambda x: x[1], reverse=True)

    safe_signals = [(r, p) for r, p in breakdown if p < 0]

    return {
        "url":         url.strip(),
        "features":    features,
        "score":       score,
        "risk_level":  risk,
        "breakdown":   positive_breakdown,
        "safe_signals": safe_signals,
        "color":       RISK_LEVELS[risk]["color"],
        "emoji":       RISK_LEVELS[risk]["emoji"],
        "error":       None,
    }


def _error_result(message: str) -> dict:
    return {
        "url":          "",
        "features":     {},
        "score":        0,
        "risk_level":   "UNKNOWN",
        "breakdown":    [],
        "safe_signals": [],
        "color":        "#95a5a6",
        "emoji":        "❓",
        "error":        message,
    }
