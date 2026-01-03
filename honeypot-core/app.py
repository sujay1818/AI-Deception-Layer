# app.py
from flask import Flask, request, jsonify, make_response
from logger import log_event
from deception_stub import generate_deception

app = Flask(__name__)

@app.before_request
def capture_request():
    event_data = {
        "ip": request.remote_addr,
        "method": request.method,
        "path": request.path,
        "headers": dict(request.headers),
        "query_params": request.args.to_dict(),
        "body": request.get_json(silent=True),
        "user_agent": request.headers.get("User-Agent")
    }
    log_event(event_data)


@app.route("/")
def index():
    return "<h1>Welcome</h1><p>Service running.</p>"

@app.route("/login", methods=["POST", "GET"])
def login():
    context = {
        "path": "/login",
        "method": request.method,
        "ip": request.remote_addr,
        "user_agent": request.headers.get("User-Agent")
    }
    deception = generate_deception(context)
    return jsonify(deception["content"]), deception["status_code"]

@app.route("/admin")
def admin():
    context = {
        "path": "/admin",
        "method": request.method,
        "ip": request.remote_addr,
        "user_agent": request.headers.get("User-Agent")
    }
    deception = generate_deception(context)
    return make_response(deception["content"], deception["status_code"])

@app.route("/api/<path:subpath>", methods=["GET", "POST"])
def api(subpath):
    return jsonify({"status": "api endpoint reached", "path": subpath})

@app.route("/backup")
def backup():
    fake_backup = "FAKE_DB_BACKUP\nuser: admin\npassword: fake123"
    response = make_response(fake_backup)
    response.headers["Content-Disposition"] = "attachment; filename=backup.sql"
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
    app.run(host="0.0.0.0", port=8080)
