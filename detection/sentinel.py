# detection/sentinel.py
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

SENTINEL_FILE = Path("sentinel_events.jsonl")

def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def send_alert(alert: Dict) -> None:
    """
    Hackathon stub: write newline-delimited JSON and print.
    Replace with HTTP collector later if needed.
    """
    alert = {**alert, "emitted_at": _utcnow_iso()}
    line = json.dumps(alert, ensure_ascii=False)
    print("[SENTINEL]", line)
    SENTINEL_FILE.parent.mkdir(parents=True, exist_ok=True)
    with SENTINEL_FILE.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
