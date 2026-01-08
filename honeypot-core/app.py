# app.py
from flask import Flask, request, jsonify, make_response, g

from logger import log_event, log_deception, upsert_session
from deception_stub import generate_deception

# Person 3 pipeline
from detection import DetectionPipeline

app = Flask(__name__)

# Global in-memory detection pipeline (Person 3)
PIPELINE = DetectionPipeline()


def _session_id() -> str:
    return f"{request.remote_addr}|{request.headers.get('User-Agent','')}"


@app.before_request
def capture_request():
    """
    Log raw request telemetry exactly ONCE per request.
    Store the created event in flask.g so we can score it later in after_request
    (after login/admin has generated an AI risk_score).
    """
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

    # 1) Log raw request telemetry
    event = log_event(event_data)

    # 2) Update per-attacker session summary (dashboard)
    upsert_session(event_data["session_id"], {
        "ip": event_data["ip"],
        "user_agent": event_data["user_agent"],
    })

    # 3) Save for scoring in after_request (avoid double counting)
    g.current_event = event
    g.ai_risk_score = None  # set later by /login or /admin if applicable


@app.after_request
def score_request(response):
    """
    Person 3 scoring/alerting should happen exactly ONCE per request.
    We do it here so /login and /admin can attach ai_risk_score before scoring.
    """
    try:
        event = getattr(g, "current_event", None)
        if event is not None:
            PIPELINE.process_event(event, ai_risk_score=getattr(g, "ai_risk_score", None))
    except Exception as e:
        # Don't break the honeypot if scoring fails
        print(f"[DETECTION_PIPELINE_ERROR] {e}")

    return response


@app.route("/")
def index():
    return "<h1>Welcome</h1><p>Service running.</p>"


@app.route("/login", methods=["GET", "POST"])
def login():
    context = {
        "path": "/login",
        "method": request.method,
        "ip": request.remote_addr,
        "user_agent": request.headers.get("User-Agent"),
        "headers": dict(request.headers),
        "body": request.get_json(silent=True),
        "session_id": _session_id(),
    }

    deception = generate_deception(context)

    # Make AI risk score available for Person 3 scoring in after_request
    g.ai_risk_score = deception.get("risk_score")

    # Log deception internally for dashboard/alerts
    log_deception({
        "session_id": context["session_id"],
        "path": "/login",
        "method": request.method,
        "ip": context["ip"],
        "user_agent": context["user_agent"],
        "risk_score": deception.get("risk_score"),
        "fake_logs": deception.get("fake_logs"),
        "fake_creds": deception.get("fake_creds"),
        "suggested_endpoints": deception.get("suggested_endpoints"),
        "deception_id": deception.get("deception_id"),
        "served_response": {
            "status_code": int(deception.get("status_code", 401)),
            "content": deception.get("content"),
        },
    })

    return jsonify(deception["content"]), int(deception["status_code"])


@app.route("/admin", methods=["GET"])
def admin():
    context = {
        "path": "/admin",
        "method": request.method,
        "ip": request.remote_addr,
        "user_agent": request.headers.get("User-Agent"),
        "headers": dict(request.headers),
        "body": request.get_json(silent=True),
        "session_id": _session_id(),
    }

    deception = generate_deception(context)

    # Make AI risk score available for Person 3 scoring in after_request
    g.ai_risk_score = deception.get("risk_score")

    # Log deception internally
    log_deception({
        "session_id": context["session_id"],
        "path": "/admin",
        "method": request.method,
        "ip": context["ip"],
        "user_agent": context["user_agent"],
        "risk_score": deception.get("risk_score"),
        "fake_logs": deception.get("fake_logs"),
        "fake_creds": deception.get("fake_creds"),
        "suggested_endpoints": deception.get("suggested_endpoints"),
        "deception_id": deception.get("deception_id"),
        "served_response": {
            "status_code": int(deception.get("status_code", 403)),
            "content": deception.get("content"),
        },
    })

    # resp = make_response(deception["content"], int(deception["status_code"]))
    # resp.headers["Content-Type"] = "text/html; charset=utf-8"
    # return resp
    content = deception["content"]
    code = int(deception["status_code"])

    if isinstance(content, dict):
        return jsonify(content), code   # JSON fallback
    else:
        resp = make_response(content, code)
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
        return resp


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


@app.route("/health")
def health():
    return jsonify({"status": "healthy"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)



# # app.py
# from flask import Flask, request, jsonify, make_response

# from logger import log_event, log_deception, upsert_session
# from deception_stub import generate_deception

# app = Flask(__name__)


# def _session_id() -> str:
#     return f"{request.remote_addr}|{request.headers.get('User-Agent','')}"


# @app.before_request
# def capture_request():
#     # 1) Log raw request telemetry (ONE time per request)
#     event_data = {
#         "ip": request.remote_addr,
#         "method": request.method,
#         "path": request.path,
#         "headers": dict(request.headers),
#         "query_params": request.args.to_dict(),
#         "body": request.get_json(silent=True),
#         "user_agent": request.headers.get("User-Agent"),
#         "session_id": _session_id(),
#     }
#     log_event(event_data)

#     # 2) Update per-attacker session summary (dashboard)
#     upsert_session(event_data["session_id"], {
#         "ip": event_data["ip"],
#         "user_agent": event_data["user_agent"],
#     })


# @app.route("/")
# def index():
#     return "<h1>Welcome</h1><p>Service running.</p>"


# @app.route("/login", methods=["GET", "POST"])
# def login():
#     # Build context expected by deception_stub wrapper
#     context = {
#         "path": "/login",
#         "method": request.method,
#         "ip": request.remote_addr,
#         "user_agent": request.headers.get("User-Agent"),
#         "headers": dict(request.headers),
#         "body": request.get_json(silent=True),
#         "session_id": _session_id(),
#     }

#     deception = generate_deception(context)

#     # Log deception internally for dashboard/alerts
#     log_deception({
#         "session_id": context["session_id"],
#         "path": "/login",
#         "method": request.method,
#         "ip": context["ip"],
#         "user_agent": context["user_agent"],
#         "risk_score": deception.get("risk_score"),
#         "fake_logs": deception.get("fake_logs"),
#         "fake_creds": deception.get("fake_creds"),
#         "suggested_endpoints": deception.get("suggested_endpoints"),
#         "deception_id": deception.get("deception_id"),
#         "served_response": {
#             "status_code": int(deception.get("status_code", 401)),
#             "content": deception.get("content"),
#         },
#     })

#     return jsonify(deception["content"]), int(deception["status_code"])


# @app.route("/admin", methods=["GET"])
# def admin():
#     context = {
#         "path": "/admin",
#         "method": request.method,
#         "ip": request.remote_addr,
#         "user_agent": request.headers.get("User-Agent"),
#         "headers": dict(request.headers),
#         "body": request.get_json(silent=True),
#         "session_id": _session_id(),
#     }

#     deception = generate_deception(context)

#     # Log deception internally
#     log_deception({
#         "session_id": context["session_id"],
#         "path": "/admin",
#         "method": request.method,
#         "ip": context["ip"],
#         "user_agent": context["user_agent"],
#         "risk_score": deception.get("risk_score"),
#         "fake_logs": deception.get("fake_logs"),
#         "fake_creds": deception.get("fake_creds"),
#         "suggested_endpoints": deception.get("suggested_endpoints"),
#         "deception_id": deception.get("deception_id"),
#         "served_response": {
#             "status_code": int(deception.get("status_code", 403)),
#             "content": deception.get("content"),
#         },
#     })

#     resp = make_response(deception["content"], int(deception["status_code"]))
#     resp.headers["Content-Type"] = "text/html; charset=utf-8"
#     return resp


# # ---- Optional demo endpoints ----

# @app.route("/api/<path:subpath>", methods=["GET", "POST"])
# def api(subpath):
#     return jsonify({"status": "api endpoint reached", "path": subpath})


# @app.route("/backup")
# def backup():
#     fake_backup = "FAKE_DB_BACKUP\nuser: admin\npassword: fake123"
#     response = make_response(fake_backup)
#     response.headers["Content-Disposition"] = "attachment; filename=backup.sql"
#     response.headers["Content-Type"] = "text/plain; charset=utf-8"
#     return response


# @app.route("/config")
# def config():
#     return jsonify({
#         "DB_HOST": "localhost",
#         "DB_USER": "admin",
#         "DB_PASSWORD": "fake_password"
#     })


# @app.route("/health")
# def health():
#     return jsonify({"status": "healthy"})


# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=8080, debug=True)

