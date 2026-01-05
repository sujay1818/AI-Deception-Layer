# deception_stub.py
from typing import Any, Dict
from deception_engine import generate_deception as brain_generate_deception

def generate_deception(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wrapper used by the Flask app.
    Converts Flask-style context -> Person 2 input, then converts Person 2 output
    into the response shape your app currently expects.
    """

    path = context.get("path", "/")
    current_request = {
        "path": path,
        "method": context.get("method"),
        "ip": context.get("ip"),
        "user_agent": context.get("user_agent"),
        "body": context.get("body"),
        "session_id": context.get("session_id"),
    }

    # Person 1 can wire real recent_events later; keep empty for now.
    result = brain_generate_deception(recent_events=[], current_request=current_request)

    # Only send fake_response.body to attacker
    fake_response = result["fake_response"]
    content_type = fake_response.get("content_type", "application/json")

    response_type = "json" if content_type == "application/json" else "text"

    return {
        "response_type": response_type,
        "content": fake_response["body"],
        "status_code": int(fake_response["status_code"]),
        "deception_id": "dec-login-001" if path == "/login" else "dec-generic-001",

        # internal fields (dashboard/alerts). app.py can ignore these if it wants.
        "risk_score": result["risk_score"],
        "fake_logs": result["fake_logs"],
        "suggested_endpoints": result["suggested_endpoints"],
        "fake_creds": result["fake_creds"],
    }
