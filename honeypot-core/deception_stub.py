# deception_stub.py
from typing import Any, Dict
from deception_engine import generate_deception as brain_generate_deception

def generate_deception(context: Dict[str, Any]) -> Dict[str, Any]:
    path = context.get("path", "/")

    current_request = {
        "path": path,
        "method": context.get("method"),
        "ip": context.get("ip"),
        "user_agent": context.get("user_agent"),
        "body": context.get("body"),
        "session_id": context.get("session_id"),
    }

    result = brain_generate_deception(recent_events=[], current_request=current_request)

    fake_response = result["fake_response"]
    content_type = fake_response.get("content_type", "application/json")

    if content_type == "application/json":
        response_type = "json"
    elif content_type == "text/html":
        response_type = "html"
    else:
        response_type = "text"

    if path == "/login":
        deception_id = "dec-login-001"
    elif path == "/admin":
        deception_id = "dec-admin-001"
    else:
        deception_id = "dec-generic-001"

    return {
        "response_type": response_type,
        "content": fake_response["body"],
        "status_code": int(fake_response["status_code"]),
        "deception_id": deception_id,

        # internal fields for dashboard/alerts
        "risk_score": result["risk_score"],
        "fake_logs": result["fake_logs"],
        "suggested_endpoints": result["suggested_endpoints"],
        "fake_creds": result["fake_creds"],
    }
