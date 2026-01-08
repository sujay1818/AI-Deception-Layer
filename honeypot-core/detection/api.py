# detection/api.py
"""
API endpoints for Person 4's dashboard.
Register this blueprint in app.py.
"""
from __future__ import annotations
from flask import Blueprint, jsonify, request
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .pipeline import DetectionPipeline

bp = Blueprint("detection_api", __name__, url_prefix="/api/detection")

# Will be set by app.py
_pipeline: "DetectionPipeline" = None


def init_api(pipeline: "DetectionPipeline"):
    global _pipeline
    _pipeline = pipeline


@bp.route("/leaderboard")
def leaderboard():
    """Top attackers by score."""
    from .analytics import leaderboard as get_leaderboard
    limit = request.args.get("limit", 20, type=int)
    data = get_leaderboard(_pipeline.state, limit=limit)
    return jsonify({"attackers": data, "total": len(_pipeline.state.by_ip)})


@bp.route("/ip/<ip>")
def ip_detail(ip: str):
    """Detailed view for a single IP."""
    from .analytics import ip_summary
    data = ip_summary(_pipeline.state, ip)
    return jsonify(data)


@bp.route("/timeline/<ip>")
def ip_timeline(ip: str):
    """Full event timeline for an IP (for dashboard drill-down)."""
    st = _pipeline.state.by_ip.get(ip)
    if not st:
        return jsonify({"ip": ip, "events": [], "error": "IP not found"}), 404
    
    # Convert deque to list, limit to last N events
    limit = request.args.get("limit", 100, type=int)
    events = list(st.timeline)[-limit:]
    
    return jsonify({
        "ip": ip,
        "score": st.score,
        "attack_type_guess": st.attack_type_guess,
        "events": events
    })


@bp.route("/stats")
def global_stats():
    """Global honeypot statistics."""
    from .analytics import severity
    
    state = _pipeline.state
    total_ips = len(state.by_ip)
    
    severity_counts = {"info": 0, "warn": 0, "critical": 0}
    attack_types = {}
    total_events = 0
    
    for ip, st in state.by_ip.items():
        sev = severity(st.score)
        severity_counts[sev] += 1
        
        guess = st.attack_type_guess
        attack_types[guess] = attack_types.get(guess, 0) + 1
        total_events += len(st.timeline)
    
    return jsonify({
        "total_ips": total_ips,
        "total_events": total_events,
        "by_severity": severity_counts,
        "by_attack_type": attack_types
    })


@bp.route("/alerts")
def recent_alerts():
    """Read recent alerts from sentinel file."""
    import json
    from pathlib import Path
    
    sentinel_file = Path("sentinel_events.jsonl")
    alerts = []
    
    if sentinel_file.exists():
        lines = sentinel_file.read_text().strip().split("\n")
        # Last N alerts, newest first
        limit = request.args.get("limit", 50, type=int)
        for line in reversed(lines[-limit:]):
            if line.strip():
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    
    return jsonify({"alerts": alerts})