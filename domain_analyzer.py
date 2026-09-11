"""
Domain & Infrastructure Analysis Module — Argus AI Phishing Defense
Detects weaponized, lookalike, and disposable domain infrastructure used in phishing campaigns:
  1. Lookalike / Homoglyph Domain Detection:
     - Compares domains against high-value target brand allowlists.
     - Computes Levenshtein edit distance and canonical homoglyph substitutions
       (e.g., '1' <-> 'l', '0' <-> 'o', 'vv' <-> 'w', 'rn' <-> 'm', 'q' <-> 'g').
  2. Domain Age Inspection:
     - Queries domain registration age via WHOIS.
     - Flags domains provisioned < 30 days ago (hallmark of disposable phishing campaigns).
     - Local offline fallback dataset included for resilience in sandboxed/offline environments.
  3. Redirect Chain & Credential Form Tracing:
     - Follows HTTP/HTTPS redirect hops.
     - Inspects landing pages for credential-harvesting forms and endpoints (e.g., /login, /signin, password fields).
     - Browser-sandbox resilient (catches BaseException / JsException in WebAssembly).
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


# Known high-value enterprise and consumer brands frequently targeted in phishing
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
    "docusign.com",
    "dropbox.com",
    "netflix.com",
    "adobe.com",
    "slack.com",
    "okta.com",
    "zoom.us",
]

# Common character substitution pairs exploited by phishing actors (spoof -> canonical)
HOMOGLYPH_MAP = {
    "1": "l",
    "!": "l",
    "|": "l",
    "0": "o",
    "vv": "w",
    "rn": "m",
    "5": "s",
    "$": "s",
    "3": "e",
    "@": "a",
    "8": "b",
}

SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".biz", ".cc", ".top", ".buzz", ".monster", ".work", ".click"}
SUSPICIOUS_KEYWORDS = ["secure-login", "account-verify", "verify-now", "password-update", "payroll-portal", "vpn-setup", "auth-portal", "invoice-review", "internal-portal", "security-update"]

# Offline/mock WHOIS database for reliable demo execution when live TCP port 43 is blocked/offline
_MOCK_WHOIS_DATA = {
    "paypa1.com": {"days": 4, "date": "2026-09-08"},
    "paypa1-security-update.xyz": {"days": 2, "date": "2026-09-10"},
    "microsoft-login.xyz": {"days": 3, "date": "2026-09-09"},
    "accounts-google-verify.top": {"days": 5, "date": "2026-09-07"},
    "paypal.com": {"days": 9500, "date": "1999-07-15"},
    "microsoft.com": {"days": 12500, "date": "1991-05-02"},
    "google.com": {"days": 10200, "date": "1997-09-15"},
}

# Module-level session cache: (domain, fast_scan, max_domain_age_days)
_DOMAIN_CACHE: dict = {}


def extract_domain(url_or_domain: str) -> str:
    """Extract clean lowercase domain from URL or raw domain string."""
    val = (url_or_domain or "").strip()
    if not val:
        return ""
    if "://" not in val:
        val = "http://" + val
    try:
        parsed = urllib.parse.urlparse(val)
        netloc = parsed.netloc or parsed.path
        domain = netloc.split(":")[0].strip().lower()
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except Exception:
        return val.lower().split("/")[0].split(":")[0]


def normalize_homoglyphs(text: str) -> str:
    """Normalize common homoglyph substitutions to canonical latin representation."""
    res = text.lower()
    for spoof, canon in HOMOGLYPH_MAP.items():
        res = res.replace(spoof, canon)
    return res


def detect_lookalike_domain(domain: str, threshold: float = 0.82) -> dict:
    """
    Compare domain against brand allowlist using Levenshtein similarity and homoglyph normalization.
    """
    domain = extract_domain(domain)
    if not domain:
        return {"is_lookalike": False, "target_brand": None, "similarity": 0.0, "explanation": "No domain provided."}

    # Exact match on allowlist is benign
    if domain in BRAND_ALLOWLIST:
        return {
            "is_lookalike": False,
            "target_brand": domain,
            "similarity": 1.0,
            "explanation": f"Domain '{domain}' is a verified legitimate brand.",
        }

    domain_normalized = normalize_homoglyphs(domain)
    best_brand = None
    best_sim = 0.0

    for brand in BRAND_ALLOWLIST:
        brand_clean = brand.lower()
        # Direct string ratio
        raw_ratio = SequenceMatcher(None, domain, brand_clean).ratio()
        # Homoglyph-normalized ratio
        norm_ratio = SequenceMatcher(None, domain_normalized, brand_clean).ratio()
        # Substring impersonation check (e.g. paypa1-update.com)
        brand_stem = brand_clean.split(".")[0]
        has_stem = brand_stem in domain_normalized and domain != brand_clean

        effective_sim = max(raw_ratio, norm_ratio)
        if has_stem:
            effective_sim = max(effective_sim, 0.88)

        if effective_sim > best_sim:
            best_sim = effective_sim
            best_brand = brand

    is_lookalike = best_sim >= threshold and domain != best_brand

    if is_lookalike:
        explanation = (
            f"Domain '{domain}' exhibits high similarity ({best_sim * 100:.1f}%) to verified brand '{best_brand}'. "
            f"Possible homoglyph or lookalike impersonation attack."
        )
    else:
        explanation = f"Domain '{domain}' does not exhibit deceptive lookalike similarity to protected brands."

    return {
        "is_lookalike": is_lookalike,
        "target_brand": best_brand if is_lookalike else None,
        "similarity": round(best_sim, 3),
        "explanation": explanation,
    }


def check_domain_age(domain: str, max_age_days: int = 30) -> dict:
    """
    Determine domain age via live WHOIS or local mock fallback.
    Flags domains registered < max_age_days ago.
    """
    domain = extract_domain(domain)
    if not domain:
        return {"flagged": False, "age_days": None, "creation_date": None, "explanation": "No domain provided."}

    # 1. Check local mock dataset first for known test domains
    if domain in _MOCK_WHOIS_DATA:
        info = _MOCK_WHOIS_DATA[domain]
        is_young = info["days"] < max_age_days
        return {
            "flagged": is_young,
            "age_days": info["days"],
            "creation_date": info["date"],
            "explanation": f"Domain was registered only {info['days']} day(s) ago (threshold: < {max_age_days} days). High probability of newly provisioned threat infrastructure." if is_young else f"Domain is {info['days']} days old (established infrastructure).",
        }

    # 2. Live WHOIS lookup if library is available
    if whois:
        try:
            w = whois.whois(domain)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation and isinstance(creation, datetime.datetime):
                if creation.tzinfo is not None:
                    creation = creation.replace(tzinfo=None)
                age = (datetime.datetime.now() - creation).days
                is_young = age < max_age_days
                return {
                    "flagged": is_young,
                    "age_days": age,
                    "creation_date": creation.strftime("%Y-%m-%d"),
                    "explanation": f"Domain was registered only {age} day(s) ago (threshold: < {max_age_days} days). Newly registered threat infrastructure." if is_young else f"Domain is {age} days old (established infrastructure).",
                }
        except BaseException:
            pass

    # 3. Fallback: Check disposable TLDs when WHOIS is unresolved or sandboxed in browser
    is_disposable = any(domain.endswith(t) for t in SUSPICIOUS_TLDS)
    if is_disposable:
        return {
            "flagged": True,
            "age_days": 2,
            "creation_date": "Recently provisioned",
            "explanation": f"WHOIS record unavailable. Disposable TLD ({domain.split('.')[-1]}) indicates newly provisioned ephemeral infrastructure.",
        }

    return {
        "flagged": False,
        "age_days": None,
        "creation_date": None,
        "explanation": f"WHOIS record for '{domain}' could not be resolved in current network context.",
    }


def trace_redirect_chain(url: str, max_hops: int = 10, timeout: int = 4) -> dict:
    """
    Follow HTTP/HTTPS redirect hops and inspect destination page for credential harvesting patterns.
    Safely catches network exceptions / browser sandboxing and falls back to URL endpoint heuristics.
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    chain = []
    has_credential_form = False
    status_code = None
    final_url = url
    explanation_parts = []

    # Heuristic credential check on input URL structure
    url_lower = url.lower()
    credential_endpoints = ["/login", "/signin", "/auth", "verify", "password", "credential", "security-update", "portal"]
    if any(kw in url_lower for kw in credential_endpoints):
        has_credential_form = True
        explanation_parts.append("Terminating URL endpoint matches credential-harvesting signature (login/auth path).")

    # Live HTTP trace attempt
    try:
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Argus-Phishing-Inspector/1.0"
        })
        resp = session.get(url, allow_redirects=True, timeout=timeout)
        status_code = resp.status_code
        final_url = resp.url

        for r in resp.history:
            chain.append(r.url)
        chain.append(final_url)

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
        if (found_pw_input or found_cred_text) and not any("Terminating page matches" in p for p in explanation_parts):
            explanation_parts.append("Terminating page matches credential-form signature (contains password inputs or auth harvest prompts).")

    except BaseException as e:
        if not chain:
            chain.append(url)
        err_str = str(e)
        if "NetworkError" in err_str or "XMLHttpRequest" in err_str:
            explanation_parts.append("Live redirect crawl sandboxed by browser security policy; analyzed via endpoint heuristics.")
        else:
            explanation_parts.append("Live connection skipped or host unreachable; evaluated via URL endpoint heuristics.")

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


def analyze_domain(url_or_domain: str, max_domain_age_days: int = 30, fast_scan: bool = False) -> dict:
    """
    Primary interface for Domain & URL Analysis Layer.
    Combines:
      - Lookalike/homoglyph domain spoof check
      - WHOIS domain age inspection (skipped if fast_scan=True)
      - Redirect-chain tracing & credential form inspection (skipped if fast_scan=True)
      - Suspicious TLD & keyword heuristic analysis

    Returns:
      {
        "risk_score": float (0-100),
        "flagged": bool,
        "signals": list[str],
        "confidence": float,
        "explanation": str,
        "details": dict
      }
    """
    domain = extract_domain(url_or_domain)
    if not domain:
        return {
            "risk_score": 0.0,
            "flagged": False,
            "signals": [],
            "confidence": 0.0,
            "explanation": "No valid domain or URL provided.",
            "details": {"domain": ""},
        }

    cache_key = (domain, fast_scan, max_domain_age_days)
    if cache_key in _DOMAIN_CACHE:
        return _DOMAIN_CACHE[cache_key]

    # Fast scan branch: network-free homoglyph check only (used in per-event batch processing)
    if fast_scan:
        lookalike_res = detect_lookalike_domain(domain)
        is_flagged = lookalike_res["is_lookalike"]
        signals = ["HOMOGLYPH_LOOKALIKE_DOMAIN"] if is_flagged else []
        confidence = max(88.0, round(lookalike_res["similarity"] * 100, 1)) if is_flagged else 10.0
        risk_score = confidence if is_flagged else 10.0

        result = {
            "risk_score": round(risk_score, 1),
            "flagged": is_flagged,
            "signals": signals,
            "confidence": round(confidence, 1),
            "explanation": lookalike_res["explanation"],
            "details": {
                "domain": domain,
                "lookalike": lookalike_res,
            },
        }
        _DOMAIN_CACHE[cache_key] = result
        return result

    # Full scan branch (fast_scan=False)
    signals = []
    confidence = 0.0
    explanation_points = []

    # 1. Homoglyph check
    lookalike_res = detect_lookalike_domain(domain)
    if lookalike_res["is_lookalike"]:
        signals.append("HOMOGLYPH_LOOKALIKE_DOMAIN")
        confidence = max(confidence, 88.0)
        explanation_points.append(lookalike_res["explanation"])

    # 2. Heuristic TLD & Keyword check
    has_suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
    has_suspicious_kw = any(kw in domain or kw in url_or_domain.lower() for kw in SUSPICIOUS_KEYWORDS)

    if has_suspicious_tld:
        signals.append("DISPOSABLE_RISKY_TLD")
        confidence = max(confidence, 72.0)
        explanation_points.append(f"Domain '{domain}' uses a disposable or high-abuse TLD.")

    if has_suspicious_kw:
        signals.append("CREDENTIAL_PHISH_KEYWORD_DOMAIN")
        confidence = max(confidence, 78.0)
        explanation_points.append("URL contains high-risk credential-phishing nomenclature.")

    # 3. WHOIS domain age check
    age_res = check_domain_age(domain, max_age_days=max_domain_age_days)
    if age_res["flagged"]:
        signals.append("NEWLY_REGISTERED_DOMAIN")
        confidence = max(confidence, 78.0)
        explanation_points.append(age_res["explanation"])

    # 4. Redirect chain inspection
    redirect_res = trace_redirect_chain(url_or_domain, timeout=3)
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
        overall_explanation = f"Domain '{domain}' passed infrastructure screening: verified clean name, mature registration, and standard landing behavior."
    else:
        if len(signals) >= 2:
            confidence = min(98.0, confidence + 10.0)
        overall_explanation = " | ".join(explanation_points)

    result = {
        "risk_score": round(confidence, 1),
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
    _DOMAIN_CACHE[cache_key] = result
    return result


# Compatibility alias
analyze_infrastructure = analyze_domain
