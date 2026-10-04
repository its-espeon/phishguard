import re
import tldextract
import datetime

# Known URL shortening services
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "clck.ru", "cutt.ly", "rebrand.ly",
    "shorturl.at", "rb.gy", "tiny.cc", "bl.ink", "hyperurl.co", "s.id",
    "lnkd.in", "urlzs.com", "urlcut.com", "x.co", "bc.vc", "v.gd",
    "dub.sh", "bit.do", "mcaf.ee", "su.pr", "twtr.to", "po.st"
}

# High-risk TLDs often associated with phishing
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".win",
    ".click", ".download", ".stream", ".gdn", ".racing", ".review",
    ".accountant", ".date", ".faith", ".loan", ".men", ".party",
    ".science", ".trade", ".webcam", ".work", ".zip", ".mov"
}

# Brands commonly impersonated in phishing
IMPERSONATED_BRANDS = [
    "paypal", "apple", "microsoft", "amazon", "google", "facebook",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "adobe",
    "wells-fargo", "bankofamerica", "chase", "citibank", "hsbc",
    "ebay", "steam", "discord", "whatsapp", "telegram", "coinbase",
    "binance", "blockchain", "wallet", "crypto", "signin", "verify"
]


def analyze_url(url: str) -> dict:
    """
    Performs heuristic analysis on a URL and returns a findings dict.
    """
    findings = {
        "has_ip_address": False,
        "is_url_shortener": False,
        "suspicious_tld": False,
        "excessive_subdomains": False,
        "suspicious_keywords": [],
        "has_at_symbol": False,
        "has_double_slash": False,
        "url_length": len(url),
        "long_url": False,
        "hyphen_in_domain": False,
        "brand_impersonation": [],
        "uses_https": False,
        "special_char_count": 0,
    }

    # Check HTTPS
    findings["uses_https"] = url.lower().startswith("https://")

    # Check for IP address in hostname
    ip_pattern = re.compile(
        r"(https?://)?(\d{1,3}\.){3}\d{1,3}"
    )
    if ip_pattern.match(url):
        findings["has_ip_address"] = True

    # Parse domain with tldextract
    extracted = tldextract.extract(url)
    domain = extracted.domain
    suffix = "." + extracted.suffix if extracted.suffix else ""
    subdomain = extracted.subdomain
    full_domain = extracted.registered_domain

    # URL shortener check
    if full_domain in URL_SHORTENERS:
        findings["is_url_shortener"] = True

    # Suspicious TLD
    if suffix.lower() in SUSPICIOUS_TLDS:
        findings["suspicious_tld"] = True

    # Excessive subdomains (more than 3 levels)
    if subdomain and subdomain.count(".") >= 2:
        findings["excessive_subdomains"] = True

    # Long URL
    if len(url) > 75:
        findings["long_url"] = True

    # @ symbol in URL
    if "@" in url:
        findings["has_at_symbol"] = True

    # Double slash redirect
    path_part = url.split("//", 1)[-1]
    if "//" in path_part:
        findings["has_double_slash"] = True

    # Hyphen in domain name
    if "-" in domain:
        findings["hyphen_in_domain"] = True

    # Brand impersonation check
    url_lower = url.lower()
    for brand in IMPERSONATED_BRANDS:
        if brand in url_lower and brand not in full_domain:
            findings["brand_impersonation"].append(brand)

    # Special character count (excluding normal URL chars)
    special_chars = re.findall(r"[!$&'()*+,;=%~`^|{}]", url)
    findings["special_char_count"] = len(special_chars)

    return findings


def get_domain_age(domain: str) -> dict:
    """
    Tries to fetch domain WHOIS info and return creation date and age in days.
    Returns a dict with 'age_days', 'creation_date', 'error'.
    """
    try:
        import whois
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return {"age_days": None, "creation_date": None, "error": "No creation date found"}

        # Ensure it's a datetime object
        if isinstance(creation_date, datetime.datetime):
            age = (datetime.datetime.utcnow() - creation_date).days
        else:
            return {"age_days": None, "creation_date": None, "error": "Unexpected date format"}

        return {
            "age_days": age,
            "creation_date": creation_date.strftime("%Y-%m-%d"),
            "error": None
        }
    except Exception as e:
        return {"age_days": None, "creation_date": None, "error": str(e)}


def calculate_heuristic_score(findings: dict, domain_age: dict) -> tuple[int, list]:
    """
    Calculates a risk score (0–100) and a list of risk flags.
    Higher score = more suspicious.
    """
    score = 0
    flags = []

    if findings["has_ip_address"]:
        score += 25
        flags.append({"label": "IP Address Used as Domain", "severity": "high"})

    if findings["is_url_shortener"]:
        score += 15
        flags.append({"label": "URL Shortening Service Detected", "severity": "medium"})

    if findings["suspicious_tld"]:
        score += 15
        flags.append({"label": "High-Risk TLD Detected", "severity": "medium"})

    if findings["excessive_subdomains"]:
        score += 10
        flags.append({"label": "Excessive Subdomains", "severity": "medium"})

    if findings["long_url"]:
        score += 5
        flags.append({"label": "Unusually Long URL", "severity": "low"})

    if findings["has_at_symbol"]:
        score += 20
        flags.append({"label": "@ Symbol in URL (Redirect Trick)", "severity": "high"})

    if findings["has_double_slash"]:
        score += 10
        flags.append({"label": "Double Slash Redirect in Path", "severity": "medium"})

    if findings["hyphen_in_domain"]:
        score += 5
        flags.append({"label": "Hyphen in Domain Name", "severity": "low"})

    if findings["brand_impersonation"]:
        score += 20
        brands = ", ".join(findings["brand_impersonation"])
        flags.append({"label": f"Brand Impersonation: {brands}", "severity": "high"})

    if findings["special_char_count"] > 4:
        score += 10
        flags.append({"label": f"Excessive Special Characters ({findings['special_char_count']})", "severity": "medium"})

    if not findings["uses_https"]:
        score += 10
        flags.append({"label": "Not Using HTTPS", "severity": "medium"})

    # Domain age penalties
    if domain_age.get("age_days") is not None:
        if domain_age["age_days"] < 30:
            score += 20
            flags.append({"label": f"Very New Domain ({domain_age['age_days']} days old)", "severity": "high"})
        elif domain_age["age_days"] < 180:
            score += 10
            flags.append({"label": f"Recently Registered Domain ({domain_age['age_days']} days old)", "severity": "medium"})
    elif domain_age.get("error"):
        score += 5
        flags.append({"label": "Could Not Verify Domain Age", "severity": "low"})

    score = min(score, 100)
    return score, flags
