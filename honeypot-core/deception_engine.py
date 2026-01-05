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

# ----------------------------
# PROMPT (LOGIN ONLY)
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

    orgs = ["Northbridge Systems", "BluePeak Logistics", "HarborView Finance", "CedarStack Health", "Sunline Retail"]
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
        "tenant": f"tnt_{rng.randint(1000,9999)}",
        "build_id": f"{rng.randint(10,99)}.{rng.randint(0,9)}.{rng.randint(0,99)}",
    }

    _SESSION.setdefault(sid, {})["env_profile"] = env
    return env


# ----------------------------
# LLM init (Azure)
# ----------------------------

_LLM: Optional[AzureChatOpenAI] = None

def _get_llm() -> Optional[AzureChatOpenAI]:
    global _LLM
    if _LLM is not None:
        return _LLM

    api_key = ""
    endpoint = ""
    deployment = ""
    api_version = ""

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
    try:
        return json.loads(text)
    except Exception:
        pass

    m = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None

def _is_valid_payload(payload: Dict[str, Any]) -> bool:
    required = {"fake_response", "fake_creds", "fake_logs", "suggested_endpoints", "risk_score"}
    if not required.issubset(payload.keys()):
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

def _safety_guard(payload: Dict[str, Any]) -> bool:
    dumped = json.dumps(payload, ensure_ascii=False).lower()
    banned = ["begin private key", "-----begin", "sk-", "azure_openai_api_key"]
    return not any(b in dumped for b in banned)


# ----------------------------
# Fallback
# ----------------------------

def _fallback_login(env: Dict[str, Any], req: Dict[str, Any]) -> Dict[str, Any]:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    req_id = f"req_{uuid.uuid4().hex[:10]}"

    body = req.get("body") or {}
    username = ""
    if isinstance(body, dict):
        username = str(body.get("username") or body.get("email") or "")
    uname = username.lower()

    risk = 45
    if any(x in uname for x in ["admin", "root", "test", "guest"]):
        risk = 75

    fake_body = {
        "error": {
            "code": 401,
            "message": "Invalid credentials",
            "request_id": req_id,
            "retry_after": 5
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
            "notes": f'Fake service account pattern for {env.get("org_name","Org")}.'
        },
        "fake_logs": [
            f'{now} WARN auth-service {req_id} Login failed user="{username or "unknown"}"',
            f'{now} INFO edge-gateway {req_id} path="/login" status=401 retry_after=5s',
            f'{now} WARN security-audit {req_id} throttle=enabled',
        ],
        "suggested_endpoints": ["/admin", "/api/v1/audit", "/internal/health", "/debug/status"],
        "risk_score": risk
    }


# ----------------------------
# Public API (Person 2)
# ----------------------------

def generate_deception(
    recent_events: List[Dict[str, Any]],
    current_request: Dict[str, Any]
) -> Dict[str, Any]:
    sid = _session_id(current_request)
    env = _get_env_profile(sid)

    # Login-only for now
    if str(current_request.get("path", "")).lower() != "/login":
        return _fallback_login(env, current_request)

    llm = _get_llm()
    if llm is None:
        return _fallback_login(env, current_request)

    prompt = LOGIN_PROMPT.format(
        env_profile_json=json.dumps(env, ensure_ascii=False),
        recent_events_json=json.dumps(recent_events[-20:], ensure_ascii=False),
        current_request_json=json.dumps(current_request, ensure_ascii=False),
    )

    try:
        resp = llm.invoke(prompt)
        text = resp.content if hasattr(resp, "content") else str(resp)

        payload = _parse_strict_json(text)
        if not isinstance(payload, dict):
            return _fallback_login(env, current_request)

        if not _is_valid_payload(payload):
            return _fallback_login(env, current_request)

        if not _safety_guard(payload):
            return _fallback_login(env, current_request)

        return payload
    except Exception:
        return _fallback_login(env, current_request)
