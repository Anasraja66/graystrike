"""
P2: Scientific Benchmark - Intentionally Vulnerable AI SaaS Test Application
This application simulates a modern Lovable/Bolt-style AI SaaS startup with
deliberately planted, documented vulnerabilities for benchmark evaluation.

IMPORTANT: For authorized testing ONLY. Never deploy publicly.

Ground Truth Vulnerability Registry:
====================================
VLN-001: Missing Content-Security-Policy header (CWE-693)
VLN-002: Hardcoded Supabase anon key in JS bundle (CWE-798)
VLN-003: Supabase RLS disabled — user table publicly readable (CWE-284)
VLN-004: LLM chat endpoint unauthenticated (CWE-306)
VLN-005: Stripe webhook missing signature verification (CWE-345)
VLN-006: Admin API endpoint missing auth middleware (CWE-285)
VLN-007: CORS wildcard allowing any origin (CWE-942)
VLN-008: Missing HttpOnly on session cookie (CWE-1004)
VLN-009: X-Frame-Options absent (clickjacking) (CWE-1021)
VLN-010: Verbose error messages leaking stack traces (CWE-209)
VLN-011: Missing rate limiting on auth endpoint (CWE-770)
VLN-012: JWT secret hardcoded and weak (CWE-321)
VLN-013: BOLA - user can read another user's orders (CWE-639)
VLN-014: Insecure Direct Object Reference on documents (CWE-639)
VLN-015: API key leaked in HTML comments (CWE-615)
"""
import os
import json
import time
import traceback
from flask import Flask, request, jsonify, Response, render_template_string

app = Flask(__name__)

# =============================================================
# GROUND TRUTH REGISTRY (for benchmark scoring)
# =============================================================
GROUND_TRUTH_VULNERABILITIES = {
    "VLN-001": {
        "title": "Missing Content-Security-Policy Header",
        "cwe": "CWE-693", "severity": "medium",
        "owasp": "A05:2021", "category": "security_headers",
        "endpoint": "/", "detection_hint": "No CSP header in HTTP response"
    },
    "VLN-002": {
        "title": "Hardcoded Supabase Anon Key in Client JS Bundle",
        "cwe": "CWE-798", "severity": "critical",
        "owasp": "A02:2021", "category": "secret_exposure",
        "endpoint": "/static/app.js", "detection_hint": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    },
    "VLN-003": {
        "title": "Supabase RLS Disabled — Users Table Publicly Readable",
        "cwe": "CWE-284", "severity": "critical",
        "owasp": "A01:2021", "category": "supabase_rls_security",
        "endpoint": "/api/db/users", "detection_hint": "Returns all user records without auth"
    },
    "VLN-004": {
        "title": "Unauthenticated LLM Chat Endpoint",
        "cwe": "CWE-306", "severity": "high",
        "owasp": "A01:2021", "category": "llm_prompt_injection_guard",
        "endpoint": "/api/chat", "detection_hint": "No bearer token required"
    },
    "VLN-005": {
        "title": "Stripe Webhook Missing Signature Verification",
        "cwe": "CWE-345", "severity": "critical",
        "owasp": "A02:2021", "category": "webhook_signature_integrity",
        "endpoint": "/api/webhooks/stripe", "detection_hint": "Processes any POST without stripe-signature"
    },
    "VLN-006": {
        "title": "Admin API Accessible Without Authentication",
        "cwe": "CWE-285", "severity": "critical",
        "owasp": "A01:2021", "category": "admin_portal_exposure",
        "endpoint": "/api/admin/users", "detection_hint": "200 OK without Authorization header"
    },
    "VLN-007": {
        "title": "CORS Wildcard — Access-Control-Allow-Origin: *",
        "cwe": "CWE-942", "severity": "high",
        "owasp": "A05:2021", "category": "cors_misconfiguration",
        "endpoint": "/api/data", "detection_hint": "Access-Control-Allow-Origin: * in response"
    },
    "VLN-008": {
        "title": "Session Cookie Missing HttpOnly Flag",
        "cwe": "CWE-1004", "severity": "medium",
        "owasp": "A02:2021", "category": "cookie_security",
        "endpoint": "/api/auth/login", "detection_hint": "Set-Cookie without HttpOnly"
    },
    "VLN-009": {
        "title": "Missing X-Frame-Options — Clickjacking Risk",
        "cwe": "CWE-1021", "severity": "medium",
        "owasp": "A05:2021", "category": "security_headers",
        "endpoint": "/", "detection_hint": "No X-Frame-Options header"
    },
    "VLN-010": {
        "title": "Verbose Error Messages Leaking Stack Traces",
        "cwe": "CWE-209", "severity": "medium",
        "owasp": "A04:2021", "category": "information_disclosure",
        "endpoint": "/api/debug/error", "detection_hint": "Python traceback in response body"
    },
    "VLN-011": {
        "title": "Missing Rate Limiting on Authentication Endpoint",
        "cwe": "CWE-770", "severity": "high",
        "owasp": "A04:2021", "category": "rate_limiting",
        "endpoint": "/api/auth/login", "detection_hint": "Unlimited POST requests accepted"
    },
    "VLN-012": {
        "title": "Hardcoded Weak JWT Secret in Source",
        "cwe": "CWE-321", "severity": "critical",
        "owasp": "A02:2021", "category": "secret_exposure",
        "endpoint": "/static/app.js", "detection_hint": "jwt_secret=secret123 in client code"
    },
    "VLN-013": {
        "title": "BOLA — User Can Read Another User's Orders",
        "cwe": "CWE-639", "severity": "high",
        "owasp": "A01:2021", "category": "bola_idor",
        "endpoint": "/api/orders/{id}", "detection_hint": "No user ownership check on order_id"
    },
    "VLN-014": {
        "title": "IDOR — Document Accessible by Arbitrary ID",
        "cwe": "CWE-639", "severity": "high",
        "owasp": "A01:2021", "category": "bola_idor",
        "endpoint": "/api/documents/{id}", "detection_hint": "Returns any document without user binding"
    },
    "VLN-015": {
        "title": "API Key Leaked in HTML Comment",
        "cwe": "CWE-615", "severity": "high",
        "owasp": "A02:2021", "category": "secret_exposure",
        "endpoint": "/", "detection_hint": "<!-- OPENAI_API_KEY: sk-test-benchmark-key-vuln015 -->"
    }
}

# =============================================================
# INTENTIONALLY VULNERABLE ROUTES
# =============================================================

# VLN-001, VLN-009, VLN-015: No security headers, API key in HTML comment
@app.route("/")
def index():
    html = """<!DOCTYPE html>
<html>
<head><title>VulnSaaS — AI Platform</title></head>
<body>
<!-- OPENAI_API_KEY: sk-test-benchmark-key-vuln015 -->
<!-- jwt_secret=secret123 -->
<h1>Welcome to VulnSaaS</h1>
<p>Your AI-powered platform.</p>
<script src="/static/app.js"></script>
</body>
</html>"""
    resp = Response(html, content_type="text/html")
    # VLN-001: No CSP header
    # VLN-009: No X-Frame-Options header
    # NOTE: Intentionally missing security headers
    return resp


# VLN-002, VLN-012: Hardcoded Supabase anon key + JWT secret in JS bundle
@app.route("/static/app.js")
def app_js():
    js_content = """
// VulnSaaS Frontend Bundle v1.0.0
const SUPABASE_URL = "https://benchmarktest.supabase.co";
const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiZW5jaG1hcmt0ZXN0IiwiaWF0IjoxNjk5MDAwMDAwLCJleHAiOjE5OTkwMDAwMDB9.VULN002_benchmark_anon_key_exposed";
const jwt_secret = "secret123";
const STRIPE_PUBLISHABLE_KEY = "pk_test_benchmark_publishable_key_vuln";

async function fetchUserData() {
  const res = await fetch(SUPABASE_URL + "/rest/v1/users?select=*", {
    headers: { apikey: SUPABASE_ANON_KEY }
  });
  return res.json();
}
"""
    return Response(js_content, content_type="application/javascript")


# VLN-003: Supabase RLS disabled — returns all user PII without auth
@app.route("/api/db/users")
def db_users():
    # No auth check — simulates Supabase RLS disabled
    users = [
        {"id": 1, "email": "alice@example.com", "stripe_customer_id": "cus_bench001", "role": "admin"},
        {"id": 2, "email": "bob@example.com", "stripe_customer_id": "cus_bench002", "role": "user"},
        {"id": 3, "email": "carol@example.com", "stripe_customer_id": "cus_bench003", "role": "user"},
    ]
    resp = jsonify(users)
    resp.headers["Access-Control-Allow-Origin"] = "*"  # VLN-007
    return resp


# VLN-004: Unauthenticated LLM endpoint
@app.route("/api/chat", methods=["GET", "POST"])
def chat():
    # No bearer token check — anyone can invoke LLM
    return jsonify({
        "message": "Hello! I am VulnSaaS AI assistant.",
        "model": "gpt-4",
        "tokens_used": 42,
        "billing_customer": "cus_bench001"
    })


# VLN-005: Stripe webhook without signature verification
@app.route("/api/webhooks/stripe", methods=["POST"])
def stripe_webhook():
    # Missing: stripe.Webhook.construct_event() signature check
    data = request.get_json(silent=True) or {}
    event_type = data.get("type", "unknown")
    # Processes any event without verifying stripe-signature header
    return jsonify({
        "received": True,
        "event_type": event_type,
        "processed": True,
        "message": "Payment event processed (no signature verification)"
    })


# VLN-006: Admin endpoint without auth middleware
@app.route("/api/admin/users")
@app.route("/api/admin/users", methods=["GET", "DELETE", "POST"])
def admin_users():
    # No admin authentication check
    return jsonify({
        "users": [
            {"id": 1, "email": "alice@example.com", "role": "admin", "password_hash": "$2b$12$bench..."},
            {"id": 2, "email": "bob@example.com", "role": "user", "password_hash": "$2b$12$bench..."}
        ],
        "total": 2,
        "admin_console": True
    })


# VLN-007: CORS wildcard on data endpoint
@app.route("/api/data")
def api_data():
    resp = jsonify({"data": "sensitive_business_data", "internal": True})
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


# VLN-008, VLN-011: Login without HttpOnly cookie + no rate limiting
login_attempt_count = {}

@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json(silent=True) or {}
    # VLN-011: No rate limiting check
    resp = jsonify({"success": True, "token": "eyJhbGciOiJIUzI1NiJ9.benchmark_token"})
    # VLN-008: Cookie set WITHOUT HttpOnly flag
    resp.headers["Set-Cookie"] = "session=benchmark_session_token; Path=/; SameSite=Lax"
    return resp


# VLN-010: Verbose error leaking stack trace
@app.route("/api/debug/error")
def debug_error():
    try:
        raise ValueError("Database connection timeout: postgresql://admin:password@internal-db:5432/prod")
    except Exception:
        tb = traceback.format_exc()
        return Response(f"Internal Server Error\n\n{tb}", status=500, content_type="text/plain")


# VLN-013: BOLA — any order accessible by ID without ownership check
@app.route("/api/orders/<int:order_id>")
def get_order(order_id):
    # No check that request.user owns order_id
    orders = {
        1: {"id": 1, "user_id": 1, "amount": 99.99, "items": ["AI Pro Plan"], "card_last4": "4242"},
        2: {"id": 2, "user_id": 2, "amount": 299.00, "items": ["Enterprise Plan"], "card_last4": "0000"},
        3: {"id": 3, "user_id": 3, "amount": 49.99, "items": ["Starter Plan"], "card_last4": "1234"},
    }
    order = orders.get(order_id)
    if order:
        return jsonify(order)
    return jsonify({"error": "Not found"}), 404


# VLN-014: IDOR — documents accessible by ID without user binding
@app.route("/api/documents/<int:doc_id>")
def get_document(doc_id):
    # No user ownership check
    docs = {
        1: {"id": 1, "owner_id": 1, "title": "Q4 Financial Report", "content": "Revenue: $2.4M..."},
        2: {"id": 2, "owner_id": 2, "title": "HR Database Export", "content": "SSN: 123-45-6789..."},
        3: {"id": 3, "owner_id": 3, "title": "Customer Contracts", "content": "Enterprise deal terms..."},
    }
    doc = docs.get(doc_id)
    if doc:
        return jsonify(doc)
    return jsonify({"error": "Not found"}), 404


# Health check for benchmark runner
@app.route("/health")
def health():
    return jsonify({
        "status": "running",
        "app": "VulnSaaS Benchmark Target",
        "vulnerabilities_planted": len(GROUND_TRUTH_VULNERABILITIES),
        "note": "AUTHORIZED BENCHMARK TESTING ONLY"
    })


# Ground truth endpoint for benchmark scoring
@app.route("/benchmark/ground-truth")
def ground_truth():
    return jsonify({
        "total_vulnerabilities": len(GROUND_TRUTH_VULNERABILITIES),
        "vulnerabilities": GROUND_TRUTH_VULNERABILITIES
    })


if __name__ == "__main__":
    print("\n" + "="*60)
    print("  VulnSaaS Benchmark Target Application")
    print(f"  Vulnerabilities planted: {len(GROUND_TRUTH_VULNERABILITIES)}")
    print("  Running on: http://127.0.0.1:9001")
    print("  AUTHORIZED BENCHMARK TESTING ONLY")
    print("="*60 + "\n")
    app.run(host="127.0.0.1", port=9001, debug=False)
