# logger.py
from datetime import datetime
import uuid

EVENT_LOGS = []

def log_event(event_dict):
    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat(),
        **event_dict
    }
    EVENT_LOGS.append(event)
    print(event)
    return event
