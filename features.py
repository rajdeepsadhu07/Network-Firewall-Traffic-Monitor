"""
URL Feature Extractor for Phishing Detection
Extracts ~20 heuristic features from a given URL.
"""

import re
import urllib.parse
import ipaddress
import tldextract


# Known URL shortener services
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
    "buff.ly", "rebrand.ly", "shorturl.at", "is.gd", "cli.gs",
    "yfrog.com", "migre.me", "ff.im", "tiny.cc", "url4.eu",
    "twit.ac", "su.pr", "twurl.nl", "snipurl.com", "short.to",
}

# Suspicious keywords commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "account",
    "banking", "confirm", "password", "credential", "paypal",
    "ebay", "amazon", "apple", "google", "microsoft", "netflix",
    "support", "helpdesk", "alert", "suspended", "locked",
    "unusual", "activity", "validate", "free", "winner", "click",
]

# Common TLDs used in phishing
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work",
    ".click", ".link", ".online", ".site", ".website", ".info",
    ".biz", ".club", ".pw", ".cc",
}


def extract_features(url: str) -> dict:
    """
    Extract heuristic features from a URL.
    Returns a dict with feature names and their values/scores.
    """
    features = {}
    url = url.strip()

    # ── 1. Parse the URL ──────────────────────────────────────────────────
    try:
        parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    except Exception:
        return {}

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full_url = url.lower()

    ext = tldextract.extract(url)
    domain = ext.domain
    suffix = ext.suffix
    subdomain = ext.subdomain

    # ── 2. Individual features ────────────────────────────────────────────

    # Uses HTTPS
    features["uses_https"] = 1 if parsed.scheme == "https" else 0

    # URL length (>75 chars is suspicious)
    features["url_length"] = len(url)
    features["long_url"] = 1 if len(url) > 75 else 0

    # Has IP address as hostname instead of domain name
    features["has_ip"] = _is_ip(hostname)

    # Count of dots in full URL
    features["dot_count"] = url.count(".")

    # Count of hyphens in domain
    features["hyphen_in_domain"] = 1 if "-" in (domain + "." + suffix) else 0

    # Count of subdomains (split by dot)
    features["subdomain_count"] = len(subdomain.split(".")) if subdomain else 0

    # @ symbol in URL (tricks browser into ignoring everything before it)
    features["has_at_symbol"] = 1 if "@" in url else 0

    # Double slash redirect (// after path start)
    features["double_slash_redirect"] = 1 if url.count("//") > 1 else 0

    # Prefix/suffix "-" in domain
    features["dash_in_domain"] = 1 if "-" in domain else 0

    # Suspicious TLD
    tld_str = "." + suffix if suffix else ""
    features["suspicious_tld"] = 1 if tld_str in SUSPICIOUS_TLDS else 0

    # URL shortener
    features["is_shortened"] = 1 if hostname in URL_SHORTENERS else 0

    # Suspicious keywords in URL
    keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url]
    features["suspicious_keyword_count"] = len(keyword_hits)
    features["has_suspicious_keyword"] = 1 if keyword_hits else 0

    # Number of special characters in URL
    special_chars = re.findall(r"[!$%^&*+=\[\]{};'\"\\|<>?]", url)
    features["special_char_count"] = len(special_chars)

    # Number of digits in domain name
    features["digits_in_domain"] = sum(c.isdigit() for c in domain)

    # Query string length
    features["query_length"] = len(query)

    # Path depth (number of "/" in path)
    features["path_depth"] = path.count("/")

    # Domain length
    features["domain_length"] = len(domain)

    # Hex encoding in URL
    features["has_hex_encoding"] = 1 if re.search(r"%[0-9a-fA-F]{2}", url) else 0

    return features


def _is_ip(hostname: str) -> int:
    """Returns 1 if hostname is a raw IP address, else 0."""
    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0
