import re
import ipaddress
from urllib.parse import urlparse
import tldextract


SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "update",
    "secure",
    "account",
    "password",
    "confirm",
    "bank",
    "payment",
    "wallet",
    "free",
    "bonus",
    "reward",
    "paypal"
]


SHORTENING_SERVICES = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly"
]


def is_ip_address(hostname):
    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def extract_features(url):

    # Add scheme if user forgot it
    test_url = url

    if not test_url.startswith(("http://", "https://")):
        test_url = "http://" + test_url

    parsed = urlparse(test_url)

    hostname = parsed.hostname or ""

    extracted = tldextract.extract(test_url)

    domain = extracted.domain
    suffix = extracted.suffix
    subdomain = extracted.subdomain

    lower_url = test_url.lower()

    # Suspicious keywords
    found_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in lower_url:
            found_keywords.append(keyword)

    # IP address
    has_ip = is_ip_address(hostname)

    # URL shortening
    is_shortened = False

    for service in SHORTENING_SERVICES:
        if service in hostname.lower():
            is_shortened = True

    # @ symbol
    has_at_symbol = "@" in test_url

    # Double slash inside URL
    double_slash = "//" in parsed.path

    # Hyphen
    hyphen_count = test_url.count("-")

    # Dot
    dot_count = hostname.count(".")

    # Special characters
    special_characters = len(
        re.findall(r"[@?=&_%;]", test_url)
    )

    # Digit count
    digit_count = sum(char.isdigit() for char in test_url)

    features = {
        "url_length": len(test_url),
        "https": parsed.scheme == "https",
        "hostname": hostname,
        "domain": domain,
        "subdomain": subdomain,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "special_character_count": special_characters,
        "digit_count": digit_count,
        "has_ip": has_ip,
        "has_at_symbol": has_at_symbol,
        "double_slash": double_slash,
        "suspicious_keywords": found_keywords,
        "keyword_count": len(found_keywords),
        "is_shortened": is_shortened
    }

    return features