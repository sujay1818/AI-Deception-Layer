# detection/scoring.py
from __future__ import annotations
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple

# --- Endpoint weights (simple + effective) ---
ENDPOINT_WEIGHTS = [
    (re.compile(r"^/admin/?$"), 25, "admin-probe"),
    (re.compile(r"^/config/?$"), 30, "config-probe"),
    (re.compile(r"^/backup/?$"), 30, "backup-probe"),
    (re.compile(r"^/login/?$"), 10, "login-probe"),
    (re.compile(r"^/api/.*"), 8, "api-probe"),
    (re.compile(r"^/health/?$"), 0, "health"),
    (re.compile(r"^/$"), 0, "root"),
]

# --- Keyword indicators ---
INDICATORS = [
    # scanners / tooling
    (re.compile(r"\b(sqlmap|nikto|acunetix|nmap|masscan|zgrab|burp)\b", re.I), 20, "scanner-tool"),
    # SQLi
    (re.compile(r"(union\s+select|or\s+1\s*=\s*1|--\s|'\s*--|sleep\(|benchmark\()", re.I), 25, "sqli"),
    # LFI / traversal
    (re.compile(r"(\.\./|\.\.\\|/etc/passwd|win\.ini|boot\.ini)", re.I), 25, "lfi-traversal"),
    # RCE-ish
    (re.compile(r"\b(cmd=|powershell|bash\s+-c|sh\s+-c|wget\b|curl\b)\b", re.I), 35, "rce-attempt"),
    # SSRF-ish
    (re.compile(r"(169\.254\.169\.254|metadata\.google\.internal)", re.I), 25, "ssrf"),
]

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def score_event(event: Dict, ip_state) -> Tuple[int, List[str], str, Dict]:
    """
    Returns: (score_delta, tags, attack_type_guess, debug_reasons)
    ip_state is your DetectionState's IPState (from state.py).
    """
    path = (event.get("path") or "").strip()
    method = (event.get("method") or "").upper()
    ua = (event.get("user_agent") or "") or (event.get("headers", {}).get("User-Agent") if isinstance(event.get("headers"), dict) else "") or ""
    body = event.get("body")
    query = event.get("query_params") or {}

    # Combine content into one string to scan
    parts = [path, method, ua]
    if isinstance(query, dict) and query:
        parts.append(str(query))
    if body is not None:
        parts.append(str(body))
    haystack = " | ".join(parts)

    score = 0
    tags: List[str] = []
    reasons = {"endpoint": None, "indicators": [], "rate": None, "burst": None}

    # 1) endpoint weight
    for pattern, weight, tag in ENDPOINT_WEIGHTS:
        if pattern.match(path):
            score += weight
            tags.append(tag)
            reasons["endpoint"] = {"path": path, "weight": weight, "tag": tag}
            break

    # 2) indicators in payload / UA / query
    for pattern, weight, tag in INDICATORS:
        if pattern.search(haystack):
            score += weight
            tags.append(tag)
            reasons["indicators"].append({"tag": tag, "weight": weight, "match": pattern.pattern})

    # 3) rate / burst behavior (based on ip_state rolling windows)
    now = _utcnow()
    ip_state.req_times.append(now)
    ip_state.recent_paths.append((now, path))

    # Rate: requests in last 60s
    one_min_ago = now - timedelta(seconds=60)
    req_last_min = [t for t in ip_state.req_times if t >= one_min_ago]
    rpm = len(req_last_min)

    if rpm > 30:
        score += 20
        tags.append("rate-spike")
        reasons["rate"] = {"rpm": rpm, "added": 20}
    elif rpm > 15:
        score += 10
        tags.append("rate-elevated")
        reasons["rate"] = {"rpm": rpm, "added": 10}

    # Burst: distinct paths in last 30s
    thirty_sec_ago = now - timedelta(seconds=30)
    recent = [p for (t, p) in ip_state.recent_paths if t >= thirty_sec_ago]
    distinct = len(set(recent))
    if distinct >= 10:
        score += 15
        tags.append("path-sweep")
        reasons["burst"] = {"distinct_paths_30s": distinct, "added": 15}

    # 4) attack type guess (simple dominance)
    attack_type_guess = guess_attack_type(tags)

    return score, dedupe(tags), attack_type_guess, reasons

def dedupe(tags: List[str]) -> List[str]:
    out = []
    seen = set()
    for t in tags:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out

def guess_attack_type(tags: List[str]) -> str:
    # Priority based on “most meaningful” indicators
    if "rce-attempt" in tags:
        return "rce"
    if "ssrf" in tags:
        return "ssrf"
    if "lfi-traversal" in tags:
        return "lfi"
    if "sqli" in tags:
        return "sqli"
    if "login-probe" in tags and ("rate-spike" in tags or "rate-elevated" in tags):
        return "credential-stuffing"
    if "path-sweep" in tags or "scanner-tool" in tags:
        return "automated-scan"
    if any(t in tags for t in ["admin-probe", "config-probe", "backup-probe"]):
        return "recon"
    return "unknown"
