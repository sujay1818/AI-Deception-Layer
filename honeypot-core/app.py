from flask import Flask, request, jsonify, make_response, g
from logger import (
    log_event, log_deception, upsert_session,
    check_credentials, user_exists, get_user_role,
    record_session_activity, create_alert,
    get_overview, list_sessions, get_session, list_alerts, list_events, list_deceptions
)

from logger import update_session_max_risk

from deception_engine import generate_deception  # <-- use updated engine module


# Person 3 pipeline
from detection import DetectionPipeline, detection_bp, init_api

app = Flask(__name__)

PIPELINE = DetectionPipeline()
init_api(PIPELINE)
app.register_blueprint(detection_bp)

def _session_id() -> str:
    return f"{request.remote_addr}|{request.headers.get('User-Agent','')}"


@app.before_request
def capture_request():
    event_data = {
        "ip": request.remote_addr,
        "method": request.method,
        "path": request.path,
        "headers": dict(request.headers),
        "query_params": request.args.to_dict(),
        "body": request.get_json(silent=True),
        "user_agent": request.headers.get("User-Agent"),
        "session_id": _session_id(),
    }

    event = log_event(event_data)

    upsert_session(event_data["session_id"], {
        "ip": event_data["ip"],
        "user_agent": event_data["user_agent"],
    })

    g.current_event = event
    g.ai_risk_score = None


@app.after_request
def score_request(response):
    try:
        event = getattr(g, "current_event", None)
        if event is not None:
            PIPELINE.process_event(event, ai_risk_score=getattr(g, "ai_risk_score", None))
    except Exception as e:
        print(f"[DETECTION_PIPELINE_ERROR] {e}")

    return response


@app.route("/")
def index():
    return "<h1>Welcome</h1><p>Service running.</p>"


def _build_current_request(path_override: str | None = None) -> dict:
    return {
        "path": path_override or request.path,
        "method": request.method,
        "ip": request.remote_addr,
        "user_agent": request.headers.get("User-Agent"),
        "headers": dict(request.headers),
        "body": request.get_json(silent=True),
        "session_id": _session_id(),
    }


def _serve_deception(deception: dict):
    fr = deception["fake_response"]
    status_code = int(fr["status_code"])
    content_type = fr["content_type"]
    body = fr["body"]

    # JSON body
    if content_type == "application/json":
        return jsonify(body), status_code

    # HTML body
    resp = make_response(body, status_code)
    resp.headers["Content-Type"] = f"{content_type}; charset=utf-8"
    return resp


@app.route("/login", methods=["GET", "POST"])
def login():
    current_req = _build_current_request("/login")
    recent_events = []
    deception = generate_deception(recent_events, current_req)

    body = request.get_json(silent=True) or {}
    username = str(body.get("username") or body.get("email") or "")
    password = str(body.get("password") or "")

    exists = user_exists(username) if username else False
    valid = check_credentials(username, password) if username else False
    role = get_user_role(username) if exists else None

    risk = int(deception.get("risk_score") or 0)
    flags = ["login_attempt"]
    counters = {"login_attempts": 1}

    if username and not exists:
        risk = max(risk, 50)
        flags += ["unknown_user"]
        counters["unknown_user_attempts"] = 1

    if exists and not valid:
        risk = max(risk, 70)
        flags += ["known_user", "bad_password"]
        counters["known_user_attempts"] = 1

    if valid:
        risk = max(risk, 95)
        flags += ["valid_creds"]
        counters["valid_cred_attempts"] = 1

    if role == "admin":
        risk = min(100, risk + 10)
        flags += ["admin_user_targeted"]

    g.ai_risk_score = risk

    # Update sessions for dashboard
    record_session_activity(
        current_req["session_id"],
        ip=current_req["ip"],
        user_agent=current_req["user_agent"],
        path="/login",
        method=request.method,
        status_code=int(deception["fake_response"]["status_code"]),
        risk=risk,
        flags=flags,
        counters_inc=counters,
    )

    # Create alerts
    if "valid_creds" in flags:
        create_alert(
            current_req["session_id"], current_req["ip"], current_req["user_agent"],
            severity="CRITICAL",
            alert_type="valid_creds",
            reason=f"Valid credentials used for username={username} role={role}",
            risk=risk,
        )
    elif "admin_user_targeted" in flags:
        create_alert(
            current_req["session_id"], current_req["ip"], current_req["user_agent"],
            severity="HIGH",
            alert_type="admin_target",
            reason=f"Admin user targeted: username={username}",
            risk=risk,
        )

    log_deception({
        "session_id": current_req["session_id"],
        "path": "/login",
        "method": request.method,
        "ip": current_req["ip"],
        "user_agent": current_req["user_agent"],
        "risk_score": risk,
        "flags": flags,
        "credential_intel": {"username": username, "exists": exists, "valid": valid, "role": role},
        "served_response": {
            "status_code": int(deception["fake_response"]["status_code"]),
            "content_type": deception["fake_response"]["content_type"],
        },
        "fake_logs": deception.get("fake_logs"),
        "fake_creds": deception.get("fake_creds"),
        "suggested_endpoints": deception.get("suggested_endpoints"),
    })

    return _serve_deception(deception)




@app.route("/admin", methods=["GET"])
def admin():
    current_req = _build_current_request("/admin")
    recent_events = []
    deception = generate_deception(recent_events, current_req)

    as_user = request.args.get("as_user", "")  # test hook
    exists = user_exists(as_user) if as_user else False
    role = get_user_role(as_user) if exists else None

    risk = int(deception.get("risk_score") or 0)
    risk = max(risk, 60)

    flags = ["admin_probe"]
    counters = {"admin_hits": 1, "sensitive_hits": 1}

    if exists:
        risk = max(risk, 80)
        flags += ["known_user_admin_probe"]
        if role == "admin":
            risk = min(100, risk + 10)
            flags += ["admin_role_probe"]

    g.ai_risk_score = risk

    record_session_activity(
        current_req["session_id"],
        ip=current_req["ip"],
        user_agent=current_req["user_agent"],
        path="/admin",
        method=request.method,
        status_code=int(deception["fake_response"]["status_code"]),
        risk=risk,
        flags=flags,
        counters_inc=counters,
    )

    # Alerts
    if "admin_role_probe" in flags:
        create_alert(
            current_req["session_id"], current_req["ip"], current_req["user_agent"],
            severity="CRITICAL",
            alert_type="admin_probe",
            reason=f"Admin panel probing as admin user={as_user}",
            risk=risk,
        )
    else:
        create_alert(
            current_req["session_id"], current_req["ip"], current_req["user_agent"],
            severity="HIGH",
            alert_type="admin_probe",
            reason="Admin panel probing detected",
            risk=risk,
        )

    log_deception({
        "session_id": current_req["session_id"],
        "path": "/admin",
        "method": request.method,
        "ip": current_req["ip"],
        "user_agent": current_req["user_agent"],
        "risk_score": risk,
        "flags": flags,
        "admin_intel": {"as_user": as_user, "exists": exists, "role": role},
        "served_response": {
            "status_code": int(deception["fake_response"]["status_code"]),
            "content_type": deception["fake_response"]["content_type"],
        },
    })

    return _serve_deception(deception)

@app.route("/dashboard/api/overview")
def api_overview():
    return jsonify(get_overview())


@app.route("/dashboard/api/sessions")
def api_sessions():
    limit = int(request.args.get("limit", 200))
    return jsonify({"sessions": list_sessions(limit=limit)})


@app.route("/dashboard/api/session")
def api_session_detail():
    session_id = request.args.get("session_id", "")
    if not session_id:
        return jsonify({"error": "session_id required"}), 400

    sess = get_session(session_id)
    ev = list_events(session_id, limit=int(request.args.get("events", 50)))
    dec = list_deceptions(session_id, limit=int(request.args.get("deceptions", 50)))

    return jsonify({
        "session": sess,
        "events": ev,
        "deceptions": dec,
    })


@app.route("/dashboard/api/alerts")
def api_alerts():
    status = request.args.get("status", "OPEN")  # OPEN/ACK/CLOSED or empty for all
    limit = int(request.args.get("limit", 200))
    return jsonify({"alerts": list_alerts(status=status if status else "", limit=limit)})





# ---- Optional demo endpoints ----

@app.route("/api/<path:subpath>", methods=["GET", "POST"])
def api(subpath):
    return jsonify({"status": "api endpoint reached", "path": subpath})


@app.route("/backup")
def backup():
    fake_backup = "FAKE_DB_BACKUP\nuser: admin\npassword: fake123"
    response = make_response(fake_backup)
    response.headers["Content-Disposition"] = "attachment; filename=backup.sql"
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    return response


@app.route("/config")
def config():
    return jsonify({
        "DB_HOST": "localhost",
        "DB_USER": "admin",
        "DB_PASSWORD": "fake_password"
    })




if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)



