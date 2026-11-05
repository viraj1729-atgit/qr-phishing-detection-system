'''URL analysis and heuristic risk scoring.

The module extracts lexical and structural features from a URL and produces a
risk score (0‑100) together with a categorical risk level. It is deliberately
light‑weight – the heavy‑lifting (e.g. VirusTotal lookup) can be added later
by extending ``analyze_url``.
''' 

import re
import urllib.parse
from enum import Enum
from dataclasses import dataclass
from typing import Dict, List

import tldextract

# ---------------------------------------------------------------------------
# Helper data structures
# ---------------------------------------------------------------------------

class RiskLevel(Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"

@dataclass
class AnalysisResult:
    score: int                # 0‑100
    level: RiskLevel
    features: Dict[str, bool] # Individual flags used in scoring

# ---------------------------------------------------------------------------
# Heuristic helpers
# ---------------------------------------------------------------------------

_SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "buff.ly",
    "adf.ly",
    "is.gd",
    "su.pr",
    "bit.do",
}

_IP_REGEX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

def _has_ip_address(netloc: str) -> bool:
    # Strip possible port.
    host = netloc.split(":")[0]
    return bool(_IP_REGEX.match(host))

def _has_excessive_length(url: str, threshold: int = 75) -> bool:
    return len(url) > threshold

def _count_subdomains(subdomains: List[str]) -> int:
    return len([s for s in subdomains if s])

def _contains_at_symbol(url: str) -> bool:
    return "@" in url

def _hyphen_count(domain: str) -> int:
    return domain.count("-")

def _is_known_shortener(domain: str) -> bool:
    return domain.lower() in _SHORTENER_DOMAINS

def _extract_domain_parts(url: str):
    parsed = urllib.parse.urlparse(url)
    ext = tldextract.extract(url)
    return {
        "netloc": parsed.netloc,
        "domain": ext.domain,
        "suffix": ext.suffix,
        "subdomains": ext.subdomain.split(".") if ext.subdomain else [],
    }

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_url(url: str) -> AnalysisResult:
    """Analyse *url* and return a risk score.

    The algorithm is intentionally simple and fully deterministic – each flag
    contributes a fixed weight. The final score is capped at 100 and mapped to a
    ``RiskLevel``.
    """
    # Normalise
    url = url.strip()
    # Basic safety – if the URL cannot be parsed we treat it as suspicious.
    try:
        parts = _extract_domain_parts(url)
    except Exception:
        parts = {"netloc": "", "domain": "", "suffix": "", "subdomains": []}
        # Conservatively mark as suspicious.
        flags = {
            "parse_error": True,
        }
        score = 30
        level = RiskLevel.SUSPICIOUS if score < 70 else RiskLevel.MALICIOUS
        return AnalysisResult(score=score, level=level, features=flags)

    flags: Dict[str, bool] = {}
    # 1. IP address in host
    flags["ip_in_host"] = _has_ip_address(parts["netloc"])
    # 2. Excessive length
    flags["excessive_length"] = _has_excessive_length(url)
    # 3. Multiple sub‑domains (>2)
    flags["many_subdomains"] = _count_subdomains(parts["subdomains"]) > 2
    # 4. @ symbol – browsers treat everything before it as user‑info.
    flags["contains_at"] = _contains_at_symbol(url)
    # 5. Hyphens in domain (>2)
    flags["many_hyphens"] = _hyphen_count(parts["domain"]) > 2
    # 6. Known URL shortener
    flags["shortener"] = _is_known_shortener(f"{parts['domain']}.{parts['suffix']}")
    # 7. Suspicious TLDs (e.g. .xyz, .top, .club) – we keep a small list.
    suspicious_tlds = {"xyz", "top", "club", "gq", "tk", "ml"}
    flags["suspicious_tld"] = parts["suffix"].lower() in suspicious_tlds

    # -------------------------------------------------------------------
    # Scoring – each flag contributes a weight.
    # -------------------------------------------------------------------
    weights = {
        "ip_in_host": 25,
        "excessive_length": 10,
        "many_subdomains": 15,
        "contains_at": 10,
        "many_hyphens": 5,
        "shortener": 15,
        "suspicious_tld": 10,
    }
    score = sum(w for f, w in weights.items() if flags.get(f, False))
    # Cap to 100.
    if score > 100:
        score = 100
    # Determine level.
    if score < 30:
        level = RiskLevel.SAFE
    elif score < 70:
        level = RiskLevel.SUSPICIOUS
    else:
        level = RiskLevel.MALICIOUS
    return AnalysisResult(score=score, level=level, features=flags)
