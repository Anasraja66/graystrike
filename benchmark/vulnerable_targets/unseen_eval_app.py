"""
P2.1: Independent Unseen Evaluation Target Application (VulnSaaS-Eval)
Runs on port 9002.
Designed for blinded, independent benchmark evaluation separate from development fixtures.

Ground Truth Distribution:
- 4 Planted Vulnerabilities (True Positives)
- 6 Secure Endpoints / Negative Controls (True Negatives to test for False Alarms)

Ground Truth Registry:
====================================
EVAL-001: Missing Content-Security-Policy header on / (CWE-693, Medium)
EVAL-002: Hardcoded Supabase Anon Key in /assets/index.js (CWE-798, Critical)
EVAL-003: Supabase RLS Disabled on /api/v2/customers (CWE-284, Critical)
EVAL-004: Unauthenticated LLM Completion on /api/ai/completion (CWE-306, High)

Negative Controls (Explicitly SECURE - Scanners MUST NOT flag these):
===================================================================
SEC-001: /api/admin/system — Properly protected by Bearer token; 401 on unauthenticated access.
SEC-002: /api/webhooks/payment — Properly verifies HMAC signature; 400 on forged payload.
SEC-003: /api/auth/login — Sets HttpOnly; Secure; SameSite=Strict cookie and enforces rate limiting (429).
SEC-004: /api/v2/products — Legitimate public catalog data (no PII); must NOT be flagged as RLS bypass.
SEC-005: /api/v2/orders/<id> — Requires valid session ownership token; 403 on unauthorized access.
SEC-006: /api/status — Clean error handling without leaking stack traces or debug information.
"""
import os
import json
import time
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

# Track auth attempts for rate limiting on SEC-003
login_attempts: dict = {}

EVAL_GROUND_TRUTH = {
    "vulnerabilities": {
        "EVAL-001": {
            "title": "Missing Content-Security-Policy Header",
            "cwe": "CWE-693", "severity": "medium",
            "category": "security_headers", "endpoint": "/"
        },
        "EVAL-002": {
            "title": "Hardcoded Supabase Anon Key in Client Bundle",
            "cwe": "CWE-798", "severity": "critical",
            "category": "secret_exposure", "endpoint": "/assets/index.js"
        },
        "EVAL-003": {
            "title": "Supabase RLS Disabled on Customers Table",
            "cwe": "CWE-284", "severity": "critical",
            "category": "supabase_rls_security", "endpoint": "/api/v2/customers"
        },
        "EVAL-004": {
            "title": "Unauthenticated AI Completion Route",
            "cwe": "CWE-306", "severity": "high",
            "category": "llm_prompt_injection_guard", "endpoint": "/api/ai/completion"
        }
    },
    "secure_controls": {
        "SEC-001": {"endpoint": "/api/admin/system", "control": "Bearer Token Auth", "expected_status": 401},
        "SEC-002": {"endpoint": "/api/webhooks/payment", "control": "HMAC Signature Check", "expected_status": 400},
        "SEC-003": {"endpoint": "/api/auth/login", "control": "HttpOnly Cookie + Rate Limiting", "expected_status": 429},
        "SEC-004": {"endpoint": "/api/v2/products", "control": "Public Catalog (No PII)", "expected_status": 200},
        "SEC-005": {"endpoint": "/api/v2/orders/1", "control": "Ownership Check", "expected_status": 403},
        "SEC-006": {"endpoint": "/api/status", "control": "Sanitized Error Handling", "expected_status": 200}
    }
}


# =============================================================
# VULNERABLE ENDPOINTS (TRUE POSITIVES)
# =============================================================

@app.route("/")
def eval_index():
    # EVAL-001: Missing CSP
    html = """<!DOCTYPE html>
<html>
<head><title>VulnSaaS-Eval — Production Validation Target</title></head>
<body>
<h1>Enterprise AI Hub</h1>
<script src="/assets/index.js"></script>
</body>
</html>"""
    resp = Response(html, content_type="text/html")
    resp.headers["X-Frame-Options"] = "DENY"  # Has X-Frame-Options, but MISSING CSP!
    return resp


@app.route("/assets/index.js")
def eval_js_bundle():
    # EVAL-002: Hardcoded Anon Key
    js = """
// Production bundle
const SUPABASE_URL = "https://eval-company.supabase.co";
const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJldmFsLXByb2plY3QiLCJpYXQiOjE2OTkwMDAwMDB9.BENCHMARK_EVAL_SIGNATURE_KEY_XXXXX";
console.log("Initialized client app");
"""
    return Response(js, content_type="application/javascript")


@app.route("/api/v2/customers")
def eval_customers():
    # EVAL-003: Supabase RLS Disabled exposing customer PII
    customers = [
        {"id": "c1", "email": "eva.ceo@enterprise.co.uk", "stripe_customer_id": "cus_eval9988", "balance": 15000},
        {"id": "c2", "email": "marcus.cto@enterprise.co.uk", "stripe_customer_id": "cus_eval9989", "balance": 8200}
    ]
    return jsonify(customers)


@app.route("/api/ai/completion", methods=["POST", "GET"])
def eval_ai_completion():
    # EVAL-004: Unauthenticated LLM Endpoint
    return jsonify({
        "completion": "Model output generated without authentication token.",
        "model": "gpt-4-turbo",
        "tokens": 85
    })


# =============================================================
# NEGATIVE CONTROLS (EXPLICITLY SECURE - TESTING FALSE POSITIVES)
# =============================================================

@app.route("/api/admin/system")
def sec_admin():
    # SEC-001: Protected admin endpoint
    auth = request.headers.get("Authorization", "")
    if auth != "Bearer admin-eval-token-987":
        return Response("Unauthorized: Bearer token required", status=401,
                        headers={"WWW-Authenticate": "Bearer realm='AdminArea'"})
    return jsonify({"admin_status": "active", "total_tenants": 4})


@app.route("/api/webhooks/payment", methods=["POST"])
def sec_webhook():
    # SEC-002: Signature-verified webhook
    sig = request.headers.get("X-Webhook-Signature", "")
    if sig != "valid-hmac-sha256-signature-eval":
        return jsonify({"error": "Invalid webhook signature"}), 400
    return jsonify({"processed": True})


@app.route("/api/auth/login", methods=["POST"])
def sec_login():
    # SEC-003: Rate limited auth + HttpOnly Secure cookie
    ip = request.remote_addr or "127.0.0.1"
    login_attempts[ip] = login_attempts.get(ip, 0) + 1
    if login_attempts[ip] > 3:
        return jsonify({"error": "Rate limit exceeded. Try again in 60 seconds."}), 429

    resp = jsonify({"success": True})
    resp.headers["Set-Cookie"] = "session=secure_session_token_xyz; Path=/; Secure; HttpOnly; SameSite=Strict"
    return resp


@app.route("/api/v2/products")
def sec_products():
    # SEC-004: Legitimate public catalog data (no PII - should NOT trigger RLS alarm)
    products = [
        {"id": "p1", "name": "AI Analytics Dashboard", "price_gbp": 120.00, "category": "software"},
        {"id": "p2", "name": "API Monitoring Add-on", "price_gbp": 45.00, "category": "add-on"}
    ]
    return jsonify(products)


@app.route("/api/v2/orders/<int:order_id>")
def sec_order(order_id):
    # SEC-005: Enforces user ownership check
    token = request.headers.get("X-User-Token", "")
    if not token or token != f"user-token-for-order-{order_id}":
        return jsonify({"error": "Forbidden: You do not own this order resource."}), 403
    return jsonify({"order_id": order_id, "status": "completed"})


@app.route("/api/status")
def sec_status():
    # SEC-006: Clean error / health check without stack traces
    return jsonify({"service": "VulnSaaS-Eval", "status": "healthy", "timestamp": time.time()})


@app.route("/benchmark/ground-truth")
def eval_gt():
    return jsonify(EVAL_GROUND_TRUTH)


if __name__ == "__main__":
    print("\n" + "="*65)
    print("  VulnSaaS-Eval: Independent Unseen Evaluation Target Application")
    print("  Port: 9002 | Ground Truth: 4 Vulnerabilities + 6 Secure Controls")
    print("="*65 + "\n")
    app.run(host="127.0.0.1", port=9002, debug=False)
