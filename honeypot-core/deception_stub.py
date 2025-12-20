def generate_deception(context):
    path = context.get("path")

    if path == "/admin":
        return {
            "response_type": "html",
            "content": "<h1>Admin Panel</h1><p>Unauthorized access logged.</p>",
            "status_code": 403,
            "deception_id": "dec-admin-001"
        }

    if path == "/login":
        return {
            "response_type": "json",
            "content": {"error": "Invalid credentials"},
            "status_code": 401,
            "deception_id": "dec-login-001"
        }

    return {
        "response_type": "text",
        "content": "OK",
        "status_code": 200,
        "deception_id": "dec-generic-001"
    }
