"""Rule-based checks that run next to the AI analysis.

These checks need no API call, so they are fast, free and explainable.
They look at two things:
  1. Every link in the message (look-alike domains, shorteners, odd endings, domain age...)
  2. Wording patterns common in scams (asking for OTP/PIN, fake urgency, fees, threats...)
"""

import difflib
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse

import tldextract

try:
    import whois  # provided by the "python-whois" package
except Exception:  # pragma: no cover - the app still works without it
    whois = None

# Use the public-suffix list bundled with tldextract: no network call needed.
_extract = tldextract.TLDExtract(suffix_list_urls=())

# Names of brands that scammers like to imitate (the part before the dot).
BRANDS = [
    "paypal", "google", "amazon", "microsoft", "apple", "facebook", "instagram",
    "whatsapp", "netflix", "paytm", "phonepe", "gpay", "sbi", "hdfc", "icici",
    "axisbank", "flipkart", "irctc", "fedex", "dhl", "ups", "bluedart",
    "indiapost", "usps", "linkedin", "binance", "coinbase", "dropbox", "adobe",
    "outlook", "gmail", "yahoo", "twitter", "telegram", "airtel", "jio",
    "myntra", "swiggy", "zomato", "uber", "ebay", "walmart", "chase",
    "wellsfargo", "citibank", "barclays", "hsbc",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
    "shorturl.at", "ow.ly", "tiny.cc", "buff.ly", "rebrand.ly", "bit.do", "t.ly",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "link", "icu", "buzz", "club", "vip", "work",
    "support", "live", "online", "site", "shop", "tk", "ml", "ga", "cf", "gq",
    "cc", "rest", "fit", "monster",
}

URL_KEYWORDS = [
    "login", "signin", "verify", "secure", "update", "account", "kyc", "bank",
    "wallet", "free", "bonus", "claim", "confirm", "suspend", "unlock",
    "reward", "gift", "prize", "refund",
]

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+", re.I)
BARE_RE = re.compile(
    r"(?<![@\w./-])((?:[a-z0-9-]+\.)+(?:com|net|org|in|co|io|xyz|top|click|link|info|"
    r"online|site|live|club|vip|shop|buzz|work|support|icu|cc|tk|ml|ga|cf|gq)"
    r"(?:/[^\s<>\"')\]]*)?)(?![\w@-])",
    re.I,
)

# Wording patterns: (regex, weight, plain-language label)
_ACTION = r"(?:share|send|tell|give|provide|enter|confirm|reply with|forward)"
_SECRET = r"(?:otp|cvv|pin|password|passcode|card number)"
TEXT_SIGNALS = [
    (
        re.compile(rf"\b{_ACTION}\b[^.\n]{{0,40}}\b{_SECRET}\b|\b{_SECRET}\b[^.\n]{{0,25}}\b{_ACTION}\b", re.I),
        35,
        "Asks you to hand over an OTP, PIN, password or card details",
    ),
    (
        re.compile(
            r"\b(urgent|immediately|within \d+ ?(hours?|hrs?|minutes?|mins?)|last chance|act now|"
            r"final notice|expires? (today|soon)|account (will be )?(blocked|suspended|closed|deactivated))\b",
            re.I,
        ),
        15,
        "Creates false urgency or threatens to close your account",
    ),
    (
        re.compile(
            r"\b(gift cards?|wire transfer|western union|bitcoin|crypto|processing fee|"
            r"registration fee|customs fee|clearance fee|pay a small fee|advance fee)\b",
            re.I,
        ),
        20,
        "Asks for a fee or an unusual payment method",
    ),
    (
        re.compile(r"\b(you('ve| have)? won|lottery|lucky draw|congratulations|you are selected)\b", re.I),
        15,
        "Promises a prize or a too-good-to-be-true offer",
    ),
    (
        re.compile(r"\b(arrest|police|cbi|customs (officer|department|case)|court|legal action|warrant|digital arrest)\b", re.I),
        15,
        "Threatens legal trouble or impersonates an authority",
    ),
    (
        re.compile(r"\b(do not tell|don't tell|dont tell|keep this (a )?(secret|confidential))\b", re.I),
        15,
        "Pushes you to keep it secret",
    ),
    (
        re.compile(r"\bkyc\b[^.\n]{0,60}\b(update|expire[sd]?|pending|verify|blocked)\b", re.I),
        20,
        "Uses the 'KYC update' pressure tactic",
    ),
]

# Genuine messages often say "never share your OTP". Remove those sentences first
# so a safe warning is not mistaken for a request.
_NEGATED = re.compile(
    r"(do not|don't|dont|never|not to)\s+(share|disclose|give|tell|reveal|forward)[^.\n]*",
    re.I,
)


# --------------------------------------------------------------------------- #
# Link checks
# --------------------------------------------------------------------------- #
def extract_urls(text: str) -> list[str]:
    """Return unique links found in the text (with or without http://)."""
    found = []
    for m in URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:!?)")
        if url not in found:
            found.append(url)
    for m in BARE_RE.finditer(text):
        url = m.group(1).rstrip(".,;:!?)")
        if not any(url in f for f in found) and url not in found:
            found.append(url)
    return found


def _variants(label: str) -> set[str]:
    """Undo look-alike characters, e.g. 'paypa1' -> 'paypal', 'g00gle' -> 'google'."""
    base = label.replace("rn", "m").replace("vv", "w")
    table_l = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a"})
    table_i = str.maketrans({"0": "o", "1": "i", "3": "e", "5": "s", "4": "a"})
    return {base.translate(table_l), base.translate(table_i)}


def _to_utc(dt):
    if not isinstance(dt, datetime):
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


_pool = ThreadPoolExecutor(max_workers=4)
_AGE_CACHE: dict[str, int | None] = {}


def _whois_age(domain: str):
    record = whois.whois(domain)
    created = record.creation_date
    if not isinstance(created, list):
        created = [created]
    dates = [d for d in (_to_utc(c) for c in created) if d]
    if not dates:
        return None
    return max(0, (datetime.now(timezone.utc) - min(dates)).days)


def get_domain_age_days(domain: str, timeout: int = 8):
    """Domain age in days, or None if it cannot be found quickly."""
    if whois is None:
        return None
    if domain in _AGE_CACHE:
        return _AGE_CACHE[domain]
    try:
        age = _pool.submit(_whois_age, domain).result(timeout=timeout)
    except Exception:
        age = None
    _AGE_CACHE[domain] = age
    return age


def analyze_url(raw: str, check_age: bool = True) -> dict:
    """Inspect one link. Returns its findings and a 0-100 risk score."""
    url = raw.rstrip(".,;:!?)")
    explicit_scheme = bool(re.match(r"https?://", url, re.I))
    parsed = urlparse(url if explicit_scheme else "http://" + url)
    host = (parsed.hostname or "").lower()

    findings: list[tuple[str, int]] = []
    result = {"url": url, "host": host, "domain": host, "age_days": None, "findings": [], "score": 0}

    if not host:
        return result

    if "@" in parsed.netloc:
        findings.append(("Contains '@', a trick that hides the real destination", 30))

    # Raw IP address instead of a domain name
    try:
        ipaddress.ip_address(host)
        findings.append(("Uses a raw IP address instead of a website name", 35))
        return _finish(result, findings)
    except ValueError:
        pass

    ext = _extract(host)
    if not ext.suffix:
        return _finish(result, findings)

    label = ext.domain.lower()
    registered = ext.registered_domain.lower()
    tld = ext.suffix.split(".")[-1]
    result["domain"] = registered

    if registered in SHORTENERS:
        findings.append(("Shortened link: you can't see where it really goes", 15))

    # A brand's real site: the brand name with a normal ending (not a suspicious one)
    official = label in BRANDS and tld not in SUSPICIOUS_TLDS and not ext.subdomain.endswith(tuple(BRANDS))

    if tld in SUSPICIOUS_TLDS:
        findings.append((f"Unusual domain ending '.{tld}' often used in scams", 20))
    if "xn--" in host:
        findings.append(("Uses disguised (punycode) characters", 30))
    if explicit_scheme and parsed.scheme == "http":
        findings.append(("Not using secure HTTPS", 10))
    if ext.subdomain and len(ext.subdomain.split(".")) >= 3:
        findings.append(("Has many sub-domains, a common disguise", 10))
    if label.count("-") >= 2:
        findings.append(("Domain name is stuffed with hyphens", 10))
    if len(url) > 100:
        findings.append(("Unusually long link", 5))

    if not official:
        hits = [k for k in URL_KEYWORDS if k in (host + parsed.path).lower()]
        if hits:
            findings.append((f"Link contains pressure words ({', '.join(hits[:3])})", min(10 * len(hits), 20)))

        tokens = re.split(r"[-_]", label)
        for brand in BRANDS:
            if label == brand:
                findings.append((f"Uses the brand name '{brand}' on an unusual domain ending", 25))
                break
            if brand in _variants(label) and label != brand:
                findings.append((f"Uses look-alike characters to imitate '{brand}'", 40))
                break
            if len(brand) >= 5 and difflib.SequenceMatcher(None, label, brand).ratio() >= 0.8:
                findings.append((f"Domain looks like a misspelling of '{brand}'", 30))
                break
            if brand in tokens or (len(brand) >= 5 and brand in label):
                findings.append((f"Contains the brand name '{brand}' but is not its official site", 30))
                break
            if brand in ext.subdomain.lower():
                findings.append((f"Brand name '{brand}' appears in the sub-domain; the real domain is {registered}", 35))
                break

        if check_age:
            age = get_domain_age_days(registered)
            result["age_days"] = age
            if age is not None:
                if age < 30:
                    findings.append((f"Website was registered only {age} days ago", 35))
                elif age < 90:
                    findings.append((f"Website is very new ({age} days old)", 25))
                elif age < 365:
                    findings.append((f"Website is less than a year old ({age} days)", 10))

    return _finish(result, findings)


def _finish(result: dict, findings: list[tuple[str, int]]) -> dict:
    result["findings"] = [text for text, _ in findings]
    result["score"] = min(100, sum(w for _, w in findings))
    return result


# --------------------------------------------------------------------------- #
# Wording checks
# --------------------------------------------------------------------------- #
def analyze_text(text: str) -> list[tuple[str, int]]:
    cleaned = _NEGATED.sub("", text)
    return [(label, weight) for pattern, weight, label in TEXT_SIGNALS if pattern.search(cleaned)]


# --------------------------------------------------------------------------- #
# Entry point used by the app
# --------------------------------------------------------------------------- #
def run_checks(text: str, check_age: bool = True, max_urls: int = 5) -> dict:
    urls = extract_urls(text)[:max_urls]
    url_results = [analyze_url(u, check_age) for u in urls]
    text_hits = analyze_text(text)

    url_score = max((r["score"] for r in url_results), default=0)
    text_score = min(100, sum(w for _, w in text_hits))
    return {
        "score": min(100, url_score + text_score),
        "urls": url_results,
        "text_hits": [label for label, _ in text_hits],
        "has_findings": bool(text_hits) or any(r["findings"] for r in url_results),
    }
