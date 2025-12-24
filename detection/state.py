# detection/state.py
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from collections import deque, Counter
from typing import Deque, Dict, List, Optional, Tuple

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

@dataclass
class IPState:
    ip: str
    score: int = 0
    last_seen: Optional[datetime] = None
    tags: Counter = field(default_factory=Counter)
    attack_type_guess: str = "unknown"

    # Rolling request timestamps (for rate/burst checks)
    req_times: Deque[datetime] = field(default_factory=lambda: deque(maxlen=500))

    # Rolling path history (for distinct path burst checks)
    recent_paths: Deque[Tuple[datetime, str]] = field(default_factory=lambda: deque(maxlen=500))

    # Timeline of enriched events (keep small for hackathon)
    timeline: Deque[dict] = field(default_factory=lambda: deque(maxlen=300))

class DetectionState:
    """
    In-memory state store.
    For hackathon MVP: keyed by IP. You can expand to session_id later.
    """
    def __init__(self):
        self.by_ip: Dict[str, IPState] = {}

    def get_ip(self, ip: str) -> IPState:
        if ip not in self.by_ip:
            self.by_ip[ip] = IPState(ip=ip)
        return self.by_ip[ip]

    def prune_old(self, max_idle_minutes: int = 60) -> None:
        """Optional cleanup to avoid infinite growth."""
        now = _utcnow()
        cutoff = now - timedelta(minutes=max_idle_minutes)
        to_delete = [ip for ip, st in self.by_ip.items() if (st.last_seen and st.last_seen < cutoff)]
        for ip in to_delete:
            del self.by_ip[ip]
