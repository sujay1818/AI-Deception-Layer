# deception_engine.py
from __future__ import annotations

import json
import os
import re
import time
import uuid
import hashlib
import random
from typing import Any, Dict, List, Optional

from langchain_openai import AzureChatOpenAI
from dotenv import load_dotenv
load_dotenv()


# ----------------------------
# PROMPTS
# ----------------------------

LOGIN_PROMPT = """\
You are an AI deception engine for a cybersecurity honeypot.

Task:
Generate a realistic but FAKE login error response.

Rules:
- Output MUST be strict JSON only (no markdown, no extra text).
- Never include real credentials, secrets, or keys.
- Use plausible fake patterns (svc_auth, tok_xxx).
- Response must look like a real authentication API error.

Context:
env_profile: {env_profile_json}
recent_events: {recent_events_json}
current_request: {current_request_json}

Return JSON with EXACT keys:
fake_response {{
  content_type: "application/json",
  status_code: 401,
  body {{
    error {{
      code: 401,
      message: "Invalid credentials",
      request_id: string,
      retry_after: number
    }}
  }}
}}
fake_creds {{ username, password_hint, token_sample, notes }}
fake_logs [strings]
suggested_endpoints [strings]
risk_score (0-100)
"""

ADMIN_PROMPT = """\
You are an AI deception engine for a cybersecurity honeypot.

Task:
Generate a FAKE admin panel access-denied response.

Rules:
- Output MUST be strict JSON only (no markdown, no commentary).
- Never reveal this is a honeypot.
- Admin panel must look real and enterprise-grade.
- Include subtle security warnings and audit language.
- No real credentials or secrets.

Context:
env_profile: {env_profile_json}
recent_events: {recent_events_json}
current_request: {current_request_json}

Return JSON with EXACT keys:
fake_response {{
  content_type: "text/html",
  status_code: 403,
  body: string
}}
fake_creds {{ username, password_hint, token_sample, notes }}
fake_logs [strings]
suggested_endpoints [strings]
risk_score (0–100)

HTML body should include:
- Company branding (use env_profile.org_name)
- "Access Denied" or "Unauthorized"
- Reference to audit logging
- Professional admin UI tone
"""


# ----------------------------
# Stateful env profile per attacker
# ----------------------------

_SESSION: Dict[str, Dict[str, Any]] = {}


def _session_id(req: Dict[str, Any]) -> str:
    sid = req.get("session_id")
    if sid:
        return str(sid)
    ip = str(req.get("ip", "unknown"))
    ua = str(req.get("user_agent", "unknown"))
    return hashlib.sha256(f"{ip}|{ua}".encode("utf-8")).hexdigest()[:24]


def _get_env_profile(sid: str) -> Dict[str, Any]:
    if sid in _SESSION and "env_profile" in _SESSION[sid]:
        return _SESSION[sid]["env_profile"]

    seed = int(hashlib.sha256(sid.encode("utf-8")).hexdigest()[:8], 16)
    rng = random.Random(seed)

    orgs = [
        "Northbridge Systems",
        "BluePeak Logistics",
        "HarborView Finance",
        "CedarStack Health",
        "Sunline Retail",
    ]
    stacks = [
        {"gateway": "nginx", "backend": "flask", "db": "postgres", "cache": "redis", "idp": "oidc"},
        {"gateway": "apim", "backend": "fastapi", "db": "mysql", "cache": "redis", "idp": "saml"},
        {"gateway": "traefik", "backend": "node", "db": "postgres", "cache": "memcached", "idp": "oidc"},
    ]

    org_name = rng.choice(orgs)
    domain = re.sub(r"[^a-z0-9]+", "", org_name.lower())[:14] + ".internal"
    env = {
        "org_name": org_name,
        "domain": domain,
        "stack": rng.choice(stacks),
        "region": rng.choice(["eastus", "westeurope", "centralus", "uksouth"]),
        "tenant": f"tnt_{rng.randint(1000, 9999)}",
        "build_id": f"{rng.randint(10,99)}.{rng.randint(0,9)}.{rng.randint(0,99)}",
    }

    _SESSION.setdefault(sid, {})["env_profile"] = env
    return env


# ----------------------------
# LLM init (Azure)
# ----------------------------

_LLM: Optional[AzureChatOpenAI] = None


def _get_llm() -> Optional[AzureChatOpenAI]:
    """
    Reads configuration from env (safe: we never print values):
      - AZURE_OPENAI_API_KEY
      - AZURE_OPENAI_ENDPOINT
      - AZURE_OPENAI_DEPLOYMENT
      - AZURE_OPENAI_API_VERSION (optional, default "2024-02-01")
    """
    global _LLM
    if _LLM is not None:
        return _LLM

    api_key = os.getenv("AZURE_OPENAI_API_KEY")
    endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
    deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT")
    api_version = os.getenv("AZURE_OPENAI_API_VERSION")

    if not (api_key and endpoint and deployment):
        return None

    _LLM = AzureChatOpenAI(
        azure_endpoint=endpoint,
        api_key=api_key,
        azure_deployment=deployment,
        api_version=api_version,
        temperature=0.6,
    )
    return _LLM


# ----------------------------
# Strict JSON parsing/validation
# ----------------------------

def _parse_strict_json(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    text = text.strip()

    # Strict attempt
    try:
        return json.loads(text)
    except Exception:
        pass

    # Best-effort: extract first JSON object (still validated after)
    m = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None


def _has_required_keys(payload: Dict[str, Any]) -> bool:
    required = {"fake_response", "fake_creds", "fake_logs", "suggested_endpoints", "risk_score"}
    return required.issubset(payload.keys())


def _is_valid_login_payload(payload: Dict[str, Any]) -> bool:
    if not _has_required_keys(payload):
        return False

    fr = payload.get("fake_response")
    if not isinstance(fr, dict):
        return False
    if fr.get("content_type") != "application/json":
        return False
    if int(fr.get("status_code", 0)) != 401:
        return False
    if not isinstance(fr.get("body"), dict):
        return False

    err = fr["body"].get("error")
    if not isinstance(err, dict):
        return False
    if int(err.get("code", 0)) != 401:
        return False
    if not isinstance(err.get("message"), str):
        return False
    if not isinstance(err.get("request_id"), str):
        return False
    if not isinstance(err.get("retry_after"), (int, float)):
        return False

    if not isinstance(payload.get("fake_creds"), dict):
        return False
    if not isinstance(payload.get("fake_logs"), list):
        return False
    if not isinstance(payload.get("suggested_endpoints"), list):
        return False
    if not isinstance(payload.get("risk_score"), int):
        return False

    rs = payload["risk_score"]
    return 0 <= rs <= 100


def _is_valid_admin_payload(payload: Dict[str, Any]) -> bool:
    if not _has_required_keys(payload):
        return False

    fr = payload.get("fake_response")
    if not isinstance(fr, dict):
        return False
    if fr.get("content_type") != "text/html":
        return False
    if int(fr.get("status_code", 0)) != 403:
        return False
    if not isinstance(fr.get("body"), str):
        return False

    if not isinstance(payload.get("fake_creds"), dict):
        return False
    if not isinstance(payload.get("fake_logs"), list):
        return False
    if not isinstance(payload.get("suggested_endpoints"), list):
        return False
    if not isinstance(payload.get("risk_score"), int):
        return False

    rs = payload["risk_score"]
    return 0 <= rs <= 100


def _safety_guard(payload: Dict[str, Any]) -> bool:
    """
    Hard guard to reduce chance of accidentally emitting something that resembles secrets.
    (Still keep this conservative; it’s a honeypot.)
    """
    dumped = json.dumps(payload, ensure_ascii=False).lower()
    banned = [
        "begin private key",
        "-----begin",
        "sk-",
        "azure_openai_api_key",
        "authorization: bearer ",
    ]
    return not any(b in dumped for b in banned)


# ----------------------------
# Risk scoring (deterministic)
# ----------------------------

def _compute_risk(current_request: dict, recent_events: list, base: int = 45) -> int:
    path = (current_request.get("path") or "").lower()
    method = (current_request.get("method") or "GET").upper()
    body = current_request.get("body") or {}

    username = ""
    if isinstance(body, dict):
        username = str(body.get("username") or body.get("email") or "").lower()

    risk = int(base)

    # High-value paths
    if path == "/admin":
        risk += 40
    if path in ["/config", "/backup", "/.env", "/secrets"]:
        risk += 30

    # Login behavior
    if path == "/login" and method == "POST":
        risk += 15

    # Suspicious usernames (avoid noisy "sa" substring matches)
    suspicious_tokens = ["admin", "root", "test", "guest", "sys"]
    if any(tok in username for tok in suspicious_tokens):
        risk += 25
    if username in {"sa", "svc", "service", "svc_auth"} or username.startswith("sa@"):
        risk += 25

    # Brute force hint (simple)
    login_hits = sum(
        1 for e in (recent_events or [])[-20:]
        if str(e.get("path", "")).lower() == "/login"
    )
    if login_hits >= 5:
        risk += 20
    if login_hits >= 10:
        risk += 20

    return max(0, min(100, int(risk)))


def _compute_admin_risk(current_request: dict, recent_events: list, base: int = 60) -> int:
    risk = _compute_risk(current_request, recent_events, base=base)

    path = (current_request.get("path") or "").lower()
    method = (current_request.get("method") or "GET").upper()

    if path == "/admin":
        risk += 20
    if path == "/admin" and method == "POST":
        risk += 15

    admin_hits = sum(
        1 for e in (recent_events or [])[-20:]
        if str(e.get("path", "")).lower() == "/admin"
    )
    if admin_hits >= 3:
        risk += 15
    if admin_hits >= 6:
        risk += 20

    return max(0, min(100, int(risk)))


# ----------------------------
# Fallback responders
# ----------------------------

def _fallback_login(
    env: Dict[str, Any],
    req: Dict[str, Any],
    recent_events: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    req_id = f"req_{uuid.uuid4().hex[:10]}"

    body = req.get("body") or {}
    username = ""
    if isinstance(body, dict):
        username = str(body.get("username") or body.get("email") or "")

    risk = _compute_risk(req, recent_events or [], base=45)

    fake_body = {
        "error": {
            "code": 401,
            "message": "Invalid credentials",
            "request_id": req_id,
            "retry_after": 5,
        },
        "tenant": env.get("tenant", "tnt_0000"),
        "trace": {"correlation_id": f"corr_{uuid.uuid4().hex[:8]}"},
    }

    return {
        "fake_response": {"content_type": "application/json", "status_code": 401, "body": fake_body},
        "fake_creds": {
            "username": "svc_auth",
            "password_hint": "******** (rotated)",
            "token_sample": "tok_" + uuid.uuid4().hex[:18],
            "notes": f'Fake service account pattern for {env.get("org_name","Org")}.',
        },
        "fake_logs": [
            f'{now} WARN auth-service {req_id} Login failed user="{username or "unknown"}"',
            f'{now} INFO edge-gateway {req_id} path="/login" status=401 retry_after=5s',
            f'{now} WARN security-audit {req_id} throttle=enabled',
        ],
        "suggested_endpoints": ["/admin", "/api/v1/audit", "/internal/health", "/debug/status"],
        "risk_score": int(risk),
    }


def _fallback_admin(
    env: Dict[str, Any],
    req: Dict[str, Any],
    recent_events: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    req_id = f"req_{uuid.uuid4().hex[:10]}"

    risk = _compute_admin_risk(req, recent_events or [], base=60)

    org = env.get("org_name", "Enterprise")
    tenant = env.get("tenant", "tnt_0000")

    html_body = f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>{org} Admin Portal</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background:#f5f6f8; }}
    .card {{
      max-width:560px; margin:80px auto; background:#fff;
      padding:32px; border-radius:8px;
      box-shadow:0 6px 22px rgba(0,0,0,.10);
      border:1px solid rgba(0,0,0,.06);
    }}
    h1 {{ margin:0 0 10px 0; color:#b00020; font-size:22px; }}
    p {{ color:#444; line-height:1.45; }}
    .meta {{ font-size:13px; color:#777; margin-top:18px; }}
    .badge {{ display:inline-block; padding:3px 8px; border-radius:999px; font-size:12px; background:#eef1f5; color:#333; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">{org} • Administrative Console</div>
    <h1>Access Denied</h1>
    <p>You do not have sufficient privileges to access this resource.</p>
    <p>This request has been recorded in audit logs and may be reviewed by Security Operations.</p>
    <div class="meta">
      Request ID: {req_id}<br/>
      Tenant: {tenant}<br/>
      Timestamp: {now}
    </div>
  </div>
</body>
</html>
""".strip()

    return {
        "fake_response": {"content_type": "text/html", "status_code": 403, "body": html_body},
        "fake_creds": {
            "username": "admin_ops",
            "password_hint": "******** (MFA enforced)",
            "token_sample": "adm_tok_" + uuid.uuid4().hex[:14],
            "notes": f"Administrative service account pattern for {org}.",
        },
        "fake_logs": [
            f'{now} WARN admin-gateway {req_id} unauthorized access attempt path="/admin"',
            f'{now} INFO security-audit {req_id} event=admin_access_denied tenant="{tenant}"',
            f'{now} WARN soc-monitor {req_id} escalation=queued',
        ],
        "suggested_endpoints": ["/admin/login", "/admin/audit", "/admin/status", "/api/v1/audit"],
        "risk_score": int(risk),
    }


# ----------------------------
# Public API
# ----------------------------

def generate_deception(
    recent_events: List[Dict[str, Any]],
    current_request: Dict[str, Any]
) -> Dict[str, Any]:
    sid = _session_id(current_request)
    env = _get_env_profile(sid)

    path = str(current_request.get("path", "")).lower()

    # Admin panel route
    if path == "/admin":
        llm = _get_llm()
        if llm is None:
            return _fallback_admin(env, current_request, recent_events)

        prompt = ADMIN_PROMPT.format(
            env_profile_json=json.dumps(env, ensure_ascii=False),
            recent_events_json=json.dumps((recent_events or [])[-20:], ensure_ascii=False),
            current_request_json=json.dumps(current_request, ensure_ascii=False),
        )

        try:
            resp = llm.invoke(prompt)
            text = resp.content if hasattr(resp, "content") else str(resp)

            payload = _parse_strict_json(text)
            if not isinstance(payload, dict):
                return _fallback_admin(env, current_request, recent_events)

            if not _is_valid_admin_payload(payload):
                return _fallback_admin(env, current_request, recent_events)

            if not _safety_guard(payload):
                return _fallback_admin(env, current_request, recent_events)

            # Enforce deterministic risk score (don’t trust LLM for scoring)
            payload["risk_score"] = _compute_admin_risk(current_request, recent_events, base=60)
            return payload
        except Exception:
            return _fallback_admin(env, current_request, recent_events)

    # Login route
    if path == "/login":
        llm = _get_llm()
        if llm is None:
            return _fallback_login(env, current_request, recent_events)

        prompt = LOGIN_PROMPT.format(
            env_profile_json=json.dumps(env, ensure_ascii=False),
            recent_events_json=json.dumps((recent_events or [])[-20:], ensure_ascii=False),
            current_request_json=json.dumps(current_request, ensure_ascii=False),
        )

        try:
            resp = llm.invoke(prompt)
            text = resp.content if hasattr(resp, "content") else str(resp)

            payload = _parse_strict_json(text)
            if not isinstance(payload, dict):
                return _fallback_login(env, current_request, recent_events)

            if not _is_valid_login_payload(payload):
                return _fallback_login(env, current_request, recent_events)

            if not _safety_guard(payload):
                return _fallback_login(env, current_request, recent_events)

            payload["risk_score"] = _compute_risk(current_request, recent_events, base=45)
            return payload
        except Exception:
            return _fallback_login(env, current_request, recent_events)

    # Default: keep behavior similar to your original (login-style response for unknown paths)
    return _fallback_login(env, current_request, recent_events)
