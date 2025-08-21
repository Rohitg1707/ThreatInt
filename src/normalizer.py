import re
from datetime import datetime

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b([a-z0-9-]{1,63}\.)+[a-z]{2,63}\b", re.IGNORECASE)
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
URL_RE = re.compile(r"https?://[^\s,]+", re.IGNORECASE)

def detect_ioc_types(indicator_str):
    s = indicator_str.strip()
    types = []
    if IPV4_RE.search(s):
        types.append("ip")
    if URL_RE.search(s):
        types.append("url")
    if MD5_RE.fullmatch(s) or SHA1_RE.fullmatch(s) or SHA256_RE.fullmatch(s):
        types.append("hash")
    if DOMAIN_RE.fullmatch(s):
        types.append("domain")
    if not types:
        types.append("unknown")
    return types

def normalize_indicator(indicator_obj):
    """
    indicator_obj: dictionary from a feed (OTX pulse indicator)
    Return normalized dict with keys: id, raw, type(s), first_seen, source, tags, metadata
    """
    raw = indicator_obj.get("indicator") or indicator_obj.get("address") or str(indicator_obj)
    types = detect_ioc_types(raw)
    normalized = {
        "raw": raw,
        "types": types,
        "source": indicator_obj.get("source") or indicator_obj.get("status") or "otx",
        "confidence": indicator_obj.get("confidence", None),
        "description": indicator_obj.get("description") or indicator_obj.get("comment") or "",
        "first_seen": indicator_obj.get("created_at") or datetime.utcnow().isoformat(),
        "meta": indicator_obj
    }
    # simple severity heuristic
    score = 0
    if "ip" in types:
        score += 2
    if "hash" in types:
        score += 3
    if "url" in types:
        score += 2
    if indicator_obj.get("malicious", False):
        score += 5
    normalized["severity_score"] = score
    return normalized
