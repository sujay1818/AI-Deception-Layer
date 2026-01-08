# detection/pipeline.py
from __future__ import annotations
from datetime import datetime, timezone
from typing import Dict, Optional

from .state import DetectionState
from .scoring import score_event
from .analytics import severity
from .sentinel import send_alert

WARN_THRESHOLD = 60
CRIT_THRESHOLD = 100

class DetectionPipeline:
    def __init__(self):
        self.state = DetectionState()
        # Track last severity per IP to avoid spamming alerts
        self._last_severity = {}

    def process_event(self, event: Dict, ai_risk_score: Optional[float] = None) -> Dict:
        """
        Takes the event produced by logger.log_event() and returns an enriched event.
        """
        ip = event.get("ip") or "unknown"
        st = self.state.get_ip(ip)

        # Parse timestamp
        ts = event.get("timestamp")
        try:
            # logger.py uses datetime.utcnow().isoformat() (no tz)
            event_time = datetime.fromisoformat(ts)
            if event_time.tzinfo is None:
                event_time = event_time.replace(tzinfo=timezone.utc)
        except Exception:
            event_time = datetime.now(timezone.utc)

        st.last_seen = event_time

        # Main scoring
        delta, tags, attack_guess, reasons = score_event(event, st)

        # Optional AI hint boost (cap at +20)
        boost = 0
        if ai_risk_score is not None:
            # allow 0-1 or 0-100
            if 0 <= ai_risk_score <= 1:
                boost = round(ai_risk_score * 20)
            elif 0 <= ai_risk_score <= 100:
                boost = round(ai_risk_score * 0.2)
            boost = max(0, min(20, boost))

        total_delta = delta + boost
        st.score += total_delta

        # Update tags + guess
        for t in tags:
            st.tags[t] += 1
        st.attack_type_guess = attack_guess

        sev = severity(st.score)

        enriched = {
            **event,
            "score_delta": total_delta,
            "score_total": st.score,
            "tags": tags,
            "attack_type_guess": attack_guess,
            "severity": sev,
            "reasons": reasons,
            "ai_boost": boost,
        }

        st.timeline.append(enriched)

        # Alerting (only when crossing or severity changes)
        prev = self._last_severity.get(ip, "info")
        crossed_warn = (prev == "info" and sev in ("warn", "critical"))
        crossed_crit = (prev != "critical" and sev == "critical")

        if crossed_warn or crossed_crit:
            alert = {
                "provider": "honeypot",
                "ip": ip,
                "severity": sev,
                "score": st.score,
                "attack_type_guess": attack_guess,
                "top_tags": [t for t, _ in st.tags.most_common(5)],
                "evidence": {
                    "last_path": event.get("path"),
                    "last_method": event.get("method"),
                    "last_user_agent": event.get("user_agent"),
                    "last_reasons": reasons,
                },
                "time": event_time.isoformat(),
            }
            send_alert(alert)

        self._last_severity[ip] = sev
        return enriched
