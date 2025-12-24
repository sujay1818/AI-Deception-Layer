# detection/analytics.py
from __future__ import annotations
from typing import Dict, List
from collections import Counter

def leaderboard(state, limit: int = 20) -> List[Dict]:
    rows = []
    for ip, st in state.by_ip.items():
        rows.append({
            "ip": ip,
            "score": st.score,
            "severity": severity(st.score),
            "last_seen": st.last_seen.isoformat() if st.last_seen else None,
            "attack_type_guess": st.attack_type_guess,
            "top_tags": [t for t, _ in st.tags.most_common(5)],
        })
    rows.sort(key=lambda r: r["score"], reverse=True)
    return rows[:limit]

def ip_summary(state, ip: str) -> Dict:
    st = state.by_ip.get(ip)
    if not st:
        return {"ip": ip, "score": 0, "severity": "info", "timeline": [], "top_tags": [], "attack_type_guess": "unknown"}
    return {
        "ip": ip,
        "score": st.score,
        "severity": severity(st.score),
        "last_seen": st.last_seen.isoformat() if st.last_seen else None,
        "attack_type_guess": st.attack_type_guess,
        "top_tags": [t for t, _ in st.tags.most_common(10)],
        "timeline": list(st.timeline),
    }

def severity(score: int) -> str:
    if score >= 100:
        return "critical"
    if score >= 60:
        return "warn"
    return "info"
