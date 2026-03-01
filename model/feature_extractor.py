"""
Feature Extraction Module
==========================
Extracts 35+ URL-based, lexical, and domain-based features
for phishing URL classification.

Feature Categories:
  1. Lexical/Length features  (URL structure)
  2. Special character counts (suspicious patterns)
  3. Keyword presence         (phishing bait words)
  4. Domain features          (registration signals)
  5. Path/query features      (URL anatomy)
  6. Entropy features         (randomness detection)
"""

import re
import math
import urllib.parse
from collections import Counter
from typing import Dict, Any, Optional

# ─────────────────────────────────────────────
# REFERENCE LISTS
# ─────────────────────────────────────────────

PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "secure",
    "security", "update", "confirm", "account", "banking", "bank",
    "paypal", "ebay", "amazon", "apple", "google", "microsoft",
    "password", "credential", "authenticate", "auth", "wallet",
    "checkout", "payment", "billing", "invoice", "suspended",
    "alert", "warning", "locked", "unlock", "unusual", "activity",
    "free", "winner", "prize", "claim", "urgent", "immediately",
    "limited", "offer", "expire", "click", "here", "access",
    "support", "helpdesk", "customer-service", "official",
]

TRUSTED_TLDS = {
    ".com", ".org", ".net", ".edu", ".gov", ".co.uk", ".co.ke",
    ".ca", ".au", ".de", ".fr", ".jp", ".it", ".es",
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
    ".link", ".online", ".site", ".website", ".pw", ".cc", ".ws",
    ".biz.pl", ".info.tm", ".stream", ".racing", ".download",
}

SHORTENING_SERVICES = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "clck.ru", "rb.gy", "cutt.ly",
}

POPULAR_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "facebook",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "yahoo",
    "ebay", "wellsfargo", "bankofamerica", "chase", "citibank",
    "outlook", "office365", "onedrive", "icloud", "gmail",
    "mpesa", "safaricom", "equity", "kcb",
]


# ─────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string (measures randomness)."""
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def count_vowels(s: str) -> int:
    return sum(1 for c in s.lower() if c in "aeiou")


def count_consonants(s: str) -> int:
    return sum(1 for c in s.lower() if c.isalpha() and c not in "aeiou")


def longest_word_length(s: str) -> int:
    words = re.split(r"[.\-_/]", s)
    return max((len(w) for w in words if w), default=0)


def digit_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(1 for c in s if c.isdigit()) / len(s)


def char_ratio(s: str, char: str) -> float:
    if not s:
        return 0.0
    return s.count(char) / len(s)


def has_ip_address(url: str) -> int:
    """Detect if URL contains an IP address instead of domain name."""
    ip4 = re.compile(r"(?:https?://)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    # Hex/octal IP
    hex_ip = re.compile(r"0x[0-9a-fA-F]{8}")
    return 1 if (ip4.search(url) or hex_ip.search(url)) else 0


def get_tld(hostname: str) -> str:
    """Extract TLD from hostname."""
    parts = hostname.lower().split(".")
    if len(parts) >= 3 and len(parts[-2]) <= 3:
        return "." + ".".join(parts[-2:])
    return "." + parts[-1] if parts else ""


# ─────────────────────────────────────────────
# MAIN FEATURE EXTRACTOR
# ─────────────────────────────────────────────

def extract_features(url: str) -> Dict[str, Any]:
    """
    Extract all 39 features from a URL.

    Returns a dict with feature names as keys.
    Returns None if URL is invalid/unparseable.
    """
    features = {}

    # ── Parse URL ──────────────────────────────
    try:
        parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path
        query = parsed.query
        fragment = parsed.fragment

        # Strip port from netloc
        hostname = netloc.split(":")[0] if netloc else ""
        subdomains = hostname.split(".")
        domain = ".".join(subdomains[-2:]) if len(subdomains) >= 2 else hostname
        tld = get_tld(hostname)
        subdomain_part = ".".join(subdomains[:-2]) if len(subdomains) > 2 else ""

    except Exception:
        return None

    full_url = url

    # ══════════════════════════════════════════
    # CATEGORY 1: LENGTH FEATURES
    # ══════════════════════════════════════════
    features["url_length"] = len(full_url)
    features["domain_length"] = len(domain)
    features["path_length"] = len(path)
    features["query_length"] = len(query)
    features["subdomain_length"] = len(subdomain_part)
    features["hostname_length"] = len(hostname)

    # ══════════════════════════════════════════
    # CATEGORY 2: SPECIAL CHARACTER COUNTS
    # ══════════════════════════════════════════
    features["num_dots"] = full_url.count(".")
    features["num_hyphens"] = full_url.count("-")
    features["num_underscores"] = full_url.count("_")
    features["num_slashes"] = full_url.count("/")
    features["num_question_marks"] = full_url.count("?")
    features["num_equal_signs"] = full_url.count("=")
    features["num_at_signs"] = full_url.count("@")         # @ tricks browsers
    features["num_ampersands"] = full_url.count("&")
    features["num_percent"] = full_url.count("%")           # URL encoding
    features["num_hash"] = full_url.count("#")
    features["num_digits_url"] = sum(c.isdigit() for c in full_url)
    features["num_digits_domain"] = sum(c.isdigit() for c in domain)

    # ══════════════════════════════════════════
    # CATEGORY 3: BOOLEAN / BINARY FEATURES
    # ══════════════════════════════════════════
    features["is_https"] = 1 if scheme == "https" else 0
    features["has_ip"] = has_ip_address(full_url)
    features["has_at_sign"] = 1 if "@" in netloc else 0     # login@evil.com/paypal
    features["has_double_slash_redirect"] = 1 if "//" in path else 0
    features["has_prefix_suffix"] = 1 if "-" in domain else 0   # paypal-secure.com

    # Subdomain depth (www.sub.domain.com = suspicious)
    features["subdomain_count"] = max(0, len(subdomains) - 2)
    features["is_shortened_url"] = 1 if any(s in hostname for s in SHORTENING_SERVICES) else 0

    # TLD suspiciousness
    features["is_suspicious_tld"] = 1 if tld in SUSPICIOUS_TLDS else 0
    features["is_trusted_tld"] = 1 if tld in TRUSTED_TLDS else 0

    # Brand impersonation: brand name in subdomain but not as actual domain
    brand_in_sub = any(brand in subdomain_part for brand in POPULAR_BRANDS)
    brand_in_domain = any(brand in domain.split(".")[0] for brand in POPULAR_BRANDS)
    # Suspicious if brand appears in subdomain but domain is different
    features["brand_in_subdomain"] = 1 if brand_in_sub and not brand_in_domain else 0

    # ══════════════════════════════════════════
    # CATEGORY 4: KEYWORD FEATURES
    # ══════════════════════════════════════════
    url_lower = full_url.lower()
    features["num_phishing_keywords"] = sum(1 for kw in PHISHING_KEYWORDS if kw in url_lower)
    features["has_login_keyword"] = 1 if any(k in url_lower for k in ["login", "signin", "sign-in"]) else 0
    features["has_secure_keyword"] = 1 if "secure" in url_lower else 0
    features["has_verify_keyword"] = 1 if any(k in url_lower for k in ["verify", "confirm", "validate"]) else 0
    features["has_account_keyword"] = 1 if "account" in url_lower else 0

    # ══════════════════════════════════════════
    # CATEGORY 5: ENTROPY & RATIO FEATURES
    # ══════════════════════════════════════════
    features["url_entropy"] = round(shannon_entropy(full_url), 4)
    features["domain_entropy"] = round(shannon_entropy(domain), 4)
    features["path_entropy"] = round(shannon_entropy(path), 4)
    features["digit_ratio_url"] = round(digit_ratio(full_url), 4)
    features["digit_ratio_domain"] = round(digit_ratio(domain), 4)
    features["longest_word_domain"] = longest_word_length(domain)
    features["vowel_ratio_domain"] = round(
        count_vowels(domain) / len(domain) if domain else 0, 4
    )

    # ══════════════════════════════════════════
    # CATEGORY 6: PATH & QUERY FEATURES
    # ══════════════════════════════════════════
    features["num_query_params"] = len(urllib.parse.parse_qs(query))
    features["path_depth"] = path.count("/") if path else 0
    features["has_port"] = 1 if ":" in netloc and not netloc.endswith(":80") and not netloc.endswith(":443") else 0
    features["has_php_extension"] = 1 if path.endswith(".php") else 0
    features["has_html_extension"] = 1 if path.lower().endswith((".html", ".htm")) else 0
    features["has_exe_extension"] = 1 if any(path.lower().endswith(e) for e in [".exe", ".zip", ".rar", ".dmg"]) else 0

    return features


def get_feature_names() -> list:
    """Return the ordered list of feature names."""
    sample = extract_features("https://example.com/path?q=1")
    return list(sample.keys()) if sample else []


def features_to_vector(features: Dict[str, Any]) -> list:
    """Convert feature dict to ordered list for model input."""
    names = get_feature_names()
    return [features.get(name, 0) for name in names]


# ─────────────────────────────────────────────
# BATCH PROCESSING
# ─────────────────────────────────────────────

def extract_features_batch(urls: list, verbose: bool = False) -> "pd.DataFrame":
    """
    Extract features for a list of URLs.
    Returns a DataFrame with one row per URL.
    """
    import pandas as pd

    results = []
    failed = 0
    for i, url in enumerate(urls):
        if verbose and i % 1000 == 0:
            print(f"  Processing URL {i}/{len(urls)}...")
        feats = extract_features(str(url))
        if feats:
            results.append(feats)
        else:
            failed += 1
            results.append({name: 0 for name in get_feature_names()})

    if verbose and failed:
        print(f"  [!] {failed} URLs failed to parse (filled with zeros)")

    return pd.DataFrame(results)


# ─────────────────────────────────────────────
# CLI DEMO
# ─────────────────────────────────────────────

if __name__ == "__main__":
    test_urls = [
        "https://www.google.com/search?q=phishing",
        "http://paypal-secure-login.tk/verify.php?token=abc123xyz",
        "https://192.168.1.1/banking/login?redirect=paypal.com",
        "http://bit.ly/3xAbc12",
        "https://github.com/user/repo",
        "http://www.paypa1.com/signin/secure?confirm=account",
        "https://secure-apple-id.update-account.tk/login.html",
    ]

    print("=" * 70)
    print("  FEATURE EXTRACTION DEMO")
    print("=" * 70)

    feature_names = get_feature_names()
    print(f"\nTotal features: {len(feature_names)}")
    print(f"Features: {feature_names}\n")

    for url in test_urls:
        feats = extract_features(url)
        print(f"\n URL: {url}")
        print(f"  → Length: {feats['url_length']}, Dots: {feats['num_dots']}, "
              f"HTTPS: {feats['is_https']}, Has IP: {feats['has_ip']}, "
              f"Suspicious TLD: {feats['is_suspicious_tld']}, "
              f"Phishing keywords: {feats['num_phishing_keywords']}, "
              f"Entropy: {feats['url_entropy']}")
