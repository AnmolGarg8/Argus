
"""
Infrastructure Analysis Module
Detects lookalike/homoglyph domains, performs WHOIS domain age checks,
and traces redirect chains for credential-harvesting indicators.
"""

import re
import datetime
import urllib.parse
from difflib import SequenceMatcher
import requests

try:
    import whois
except ImportError:
    whois = None


# Known municipal and prominent target brand domains
BRAND_ALLOWLIST = [
    "paypal.com",
    "microsoft.com",
    "office365.com",
    "login.microsoftonline.com",
    "google.com",
    "accounts.google.com",
    "apple.com",
    "amazon.com",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "irs.gov",
    "civicgov.org",
    "cityhall.gov",
    "municipal-portal.gov",
]

# Common homoglyph / visual substitution mapping
HOMOGLYPH_MAP = {
    "1": "l",
    "!": "i",
    "|": "l",
    "0": "o",
    "3": "e",
    "4": "a",
    "5": "s",
    "8": "b",
    "@": "a",
    "vv": "w",
    "rn": "m",
    "cl": "d",
}


def normalize_homoglyphs(text: str) -> str:
    """Normalize potential homoglyph characters into standard Latin equivalents."""
    cleaned = text.lower()
    for pseudo, real in HOMOGLYPH_MAP.items():
        cleaned = cleaned.replace(pseudo, real)
    return cleaned


def extract_domain(url_or_domain: str) -> str:
    """Extract registered domain or hostname from URL or string."""
    s = url_or_domain.strip().lower()
    if not s.startswith(("http://", "https://")):
        s = "http://" + s
    parsed = urllib.parse.urlparse(s)
    domain = parsed.netloc or parsed.path
    if ":" in domain:
        domain = domain.split(":")[0]
    return domain.lower()


def detect_lookalike_domain(domain: str, threshold: float = 0.75) -> dict:
    """
    Compare given domain against brand allowlist using normalized homoglyphs and edit distance.
    Returns details on any spoof match found.
    """
    domain = extract_domain(domain)
    normalized_domain = normalize_homoglyphs(domain)

    best_match = None
    max_sim = 0.0

    for brand in BRAND_ALLOWLIST:
        # Exact match is legitimate
        if domain == brand:
            return {
                "is_lookalike": False,
                "similarity": 1.0,
                "matched_brand": brand,
                "explanation": f"Domain '{domain}' is an exact match for verified brand '{brand}'.",
            }

        # Calculate string similarity between normalized test domain and brand
        sim = SequenceMatcher(None, normalized_domain, brand).ratio()
        
        # Subdomain / infix spoofing check (e.g. login-microsoft.com or paypal.verify-security.com)
        brand_base = brand.split(".")[0]
        # Check normalized domain for brand base presence (e.g. paypa1 -> paypal in paypal-security.xyz)
        if brand_base in normalized_domain and domain != brand:
            sim = max(sim, 0.88)

        # Also check tokenized parts (split by hyphen, dot, underscore)
        tokens = re.split(r"[\.\-_]+", normalized_domain)
        for tok in tokens:
            tok_sim = SequenceMatcher(None, tok, brand_base).ratio()
            if tok_sim >= 0.80 and tok != brand_base:
                sim = max(sim, tok_sim)
            elif tok == brand_base and domain != brand:
                sim = max(sim, 0.88)

        if sim > max_sim:
            max_sim = sim
            best_match = brand

    is_lookalike = max_sim >= threshold
    explanation = ""
    if is_lookalike:
        explanation = (
            f"Domain '{domain}' exhibits high similarity ({max_sim*100:.1f}%) to verified brand '{best_match}'. "
            f"Possible homoglyph or lookalike impersonation attack."
        )

    return {
        "is_lookalike": is_lookalike,
        "similarity": round(max_sim, 3),
        "matched_brand": best_match,
        "explanation": explanation,
    }


def check_domain_age(domain: str, max_age_days: int = 30) -> dict:
    """
    Check domain creation age via WHOIS.
    Flags domains registered within the last `max_age_days`.
    """
    domain = extract_domain(domain)
    if not whois:
        return {
            "flagged": False,
            "age_days": None,
            "creation_date": None,
            "explanation": "WHOIS module not available.",
        }

    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        if not creation or not isinstance(creation, datetime.datetime):
            # Many suspicious / disposable TLDs fail WHOIS lookup
            return {
                "flagged": False,
                "age_days": None,
                "creation_date": None,
                "explanation": f"WHOIS record for '{domain}' returned ambiguous registration date.",
            }

        # Convert to naive datetime if tz-aware
        if creation.tzinfo is not None:
            creation = creation.replace(tzinfo=None)

        age = (datetime.datetime.now() - creation).days
        is_young = age < max_age_days

        explanation = ""
        if is_young:
            explanation = f"Domain was registered only {age} day(s) ago (threshold: < {max_age_days} days). High probability of newly provisioned threat infrastructure."
        else:
            explanation = f"Domain is {age} days old (established infrastructure)."

        return {
            "flagged": is_young,
            "age_days": age,
            "creation_date": creation.strftime("%Y-%m-%d"),
            "explanation": explanation,
        }
    except Exception as e:
        return {
            "flagged": False,
            "age_days": None,
            "creation_date": None,
            "explanation": f"WHOIS query for '{domain}' did not resolve: {str(e)[:60]}",
        }


def trace_redirect_chain(url: str, max_hops: int = 10, timeout: int = 5) -> dict:
    """
    Trace HTTP/HTTPS redirect hops and inspect destination page for credential harvesting patterns.
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    chain = []
    has_credential_form = False
    status_code = None
    final_url = url
    explanation_parts = []

    try:
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Argus-Security-Crawler/1.0"
        })

        resp = session.get(url, allow_redirects=True, timeout=timeout)
        status_code = resp.status_code
        final_url = resp.url

        # Build redirect history
        for r in resp.history:
            chain.append(r.url)
        chain.append(final_url)

        # Inspect final page content for credential form patterns
        html_content = resp.text.lower()
        password_input_patterns = [
            r'type=["\']password["\']',
            r'name=["\'](?:passwd|password|pass|pwd)["\']',
            r'id=["\'](?:passwd|password|pass|pwd)["\']',
        ]
        
        credential_hints = [
            "enter your password",
            "sign in to your account",
            "verify your login",
            "confirm credentials",
            "session expired",
        ]

        found_pw_input = any(re.search(p, html_content) for p in password_input_patterns)
        found_cred_text = any(hint in html_content for hint in credential_hints)

        if found_pw_input or found_cred_text:
            has_credential_form = True

        if len(chain) > 1:
            explanation_parts.append(f"Redirect chain traversed {len(chain) - 1} hop(s) to '{final_url}'.")
        if has_credential_form:
            explanation_parts.append("Terminating page matches credential-form signature (contains password input or auth harvest prompts).")

    except requests.exceptions.RequestException as e:
        chain.append(url)
        explanation_parts.append(f"Redirect inspection encountered network exception: {str(e)[:60]}")

    is_flagged = has_credential_form or (len(chain) > 3)
    explanation = " ".join(explanation_parts) if explanation_parts else "Redirect chain normal, no credential harvest indicators detected."

    return {
        "flagged": is_flagged,
        "hops": len(chain) - 1 if len(chain) > 0 else 0,
        "chain": chain,
        "final_url": final_url,
        "has_credential_form": has_credential_form,
        "status_code": status_code,
        "explanation": explanation,
    }


SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".biz", ".cc", ".top", ".buzz", ".monster"}
SUSPICIOUS_KEYWORDS = ["secure-login", "account-secure", "verify-now", "password-update", "free-rewards", "irs-refund", "vpn-setup", "auth-portal", "finance-docs", "internal-portal"]


def analyze_infrastructure(url: str, max_domain_age_days: int = 30, fast_scan: bool = False) -> dict:
    """
    Comprehensive infrastructure analysis.
    Combines:
      - Lookalike/homoglyph domain spoof check
      - WHOIS domain age inspection (bypassed in fast_scan mode)
      - Redirect-chain tracing & credential harvesting check (bypassed in fast_scan mode)
      - Suspicious TLD & keyword heuristic analysis

    Returns:
      {
        "flagged": bool,
        "signals": list[str],
        "confidence": float,
        "explanation": str,
        "details": dict
      }
    """
    domain = extract_domain(url)
    signals = []
    confidence = 0.0
    explanation_points = []

    # 1. Homoglyph check
    lookalike_res = detect_lookalike_domain(domain)
    if lookalike_res["is_lookalike"]:
        signals.append("HOMOGLYPH_LOOKALIKE_DOMAIN")
        confidence = max(confidence, 88.0)
        explanation_points.append(lookalike_res["explanation"])

    # 2. Heuristic TLD & Keyword check (Always runs, fast)
    has_suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
    has_suspicious_kw = any(kw in domain or kw in url.lower() for kw in SUSPICIOUS_KEYWORDS)

    if has_suspicious_tld:
        signals.append("DISPOSABLE_RISKY_TLD")
        confidence = max(confidence, 72.0)
        explanation_points.append(f"Domain '{domain}' uses a disposable or high-abuse TLD.")

    if has_suspicious_kw:
        signals.append("CREDENTIAL_PHISH_KEYWORD_DOMAIN")
        confidence = max(confidence, 78.0)
        explanation_points.append(f"URL contains high-risk credential-phishing nomenclature.")

    age_res = {"flagged": False, "age_days": None, "explanation": "Skipped in fast scan"}
    redirect_res = {"flagged": False, "explanation": "Skipped in fast scan"}

    if not fast_scan:
        # 3. WHOIS age check
        age_res = check_domain_age(domain, max_age_days=max_domain_age_days)
        if age_res["flagged"]:
            signals.append("NEWLY_REGISTERED_DOMAIN")
            confidence = max(confidence, 78.0)
            explanation_points.append(age_res["explanation"])

        # 4. Redirect chain inspection
        redirect_res = trace_redirect_chain(url, timeout=3)
        if redirect_res["flagged"]:
            if redirect_res.get("has_credential_form"):
                signals.append("CREDENTIAL_HARVEST_LANDING_PAGE")
                confidence = max(confidence, 85.0)
            else:
                signals.append("EXCESSIVE_REDIRECT_CHAIN")
                confidence = max(confidence, 60.0)
            explanation_points.append(redirect_res["explanation"])

    flagged = len(signals) > 0
    if not flagged:
        confidence = 10.0
        overall_explanation = f"Infrastructure analysis for '{domain}' found no suspicious homoglyphs, mature registration, and clean landing behavior."
    else:
        # If multiple signals fire simultaneously, boost confidence
        if len(signals) >= 2:
            confidence = min(98.0, confidence + 10.0)
        overall_explanation = " | ".join(explanation_points)

    return {
        "flagged": flagged,
        "signals": signals,
        "confidence": round(confidence, 1),
        "explanation": overall_explanation,
        "details": {
            "domain": domain,
            "lookalike": lookalike_res,
            "whois": age_res,
            "redirects": redirect_res,
        },
    }
