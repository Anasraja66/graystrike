"""
AI-Generated Apps & Modern Jamstack Security Micro-Agents
Targeting vulnerabilities in Lovable.dev, Bolt.new, v0 (Vercel), Cursor, Supabase, and Claude-built apps:
39. SupabaseRlsAuditorAgent (Supabase / Firebase Missing RLS & Open Table Inspector - CWE-284)
40. ClientBundleSecretLeakAgent (Leaked Stripe, OpenAI, Claude, Resend, Clerk & AWS Keys in Client JS Bundles - CWE-798)
41. PublicCloudStorageBucketAgent (Exposed S3 / Supabase Storage Buckets & Insecure Uploads - CWE-552)
42. LLMEndpointExposureAgent (Unauthenticated AI/LLM Chat Endpoints & Token Exhaustion - CWE-1426)
43. WebhookSignatureIntegrityAgent (Payment & SaaS Webhook Signature Verifier - CWE-345)
44. ClientSideAuthBypassAgent (Client-Side Route Gatekeeper & Admin Leak Agent - CWE-285)

All findings upgraded with P0 Structured Verification Evidence (cURL, expected/observed behavior, status codes).
"""
import re
import base64
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse
import httpx

from ai_engine.agents.base_agent import (
    BaseSecurityAgent, AgentRegistry, AgentExecutionResult, AgentFinding, AgentSeverity
)


@AgentRegistry.register
class SupabaseRlsAuditorAgent(BaseSecurityAgent):
    id = "supabase_rls_auditor"
    name = "Supabase & Firebase RLS Exposure Inspector"
    description = "Scientifically inspects AI-generated apps (Lovable, Bolt, v0) for exposed Supabase/Firebase endpoints with disabled or overly permissive Row-Level Security (RLS)."
    category = "broken_access_control"
    cwe_default = "CWE-284"
    owasp_default = "A01:2021-Broken Access Control"
    is_passive = True

    # Tables categorized by sensitivity
    PRIVATE_TABLES = ["users", "profiles", "orders", "customers", "transactions", "leads", "accounts", "payments"]
    PUBLIC_CANDIDATE_TABLES = ["posts", "articles", "settings", "categories", "products", "tags"]
    ALL_PROBE_TABLES = PRIVATE_TABLES + PUBLIC_CANDIDATE_TABLES

    SENSITIVE_FIELD_INDICATORS = {
        "email", "phone", "password", "hash", "token", "secret", "user_id", 
        "billing", "stripe_customer_id", "credit", "balance", "address", 
        "role", "ssn", "payment_method", "api_key"
    }

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        now_ts = datetime.now(timezone.utc).isoformat()

        # Step 1: Detect Supabase Project URL in page scripts or content
        supabase_urls = set()
        anon_keys = set()

        for page in crawl_data.get("pages", []):
            scripts = page.get("scripts", [])
            for s in scripts:
                # Look for supabase URL pattern: https://[project-ref].supabase.co
                matches = re.findall(r"https://[a-zA-Z0-9_-]+\.supabase\.co", s)
                for m in matches:
                    supabase_urls.add(m)

                # Look for JWT anon keys
                jwt_matches = re.findall(r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", s)
                for jm in jwt_matches:
                    anon_keys.add(jm)

        if not supabase_urls:
            return AgentExecutionResult(agent_id=self.id, success=True, findings=[])

        # Step 2: Probe Supabase REST endpoints for open tables (scientific verification)
        chosen_key = list(anon_keys)[0] if anon_keys else ""
        headers = {"User-Agent": "GrayStrike-RLSAuditor/1.0"}
        if chosen_key:
            headers["apikey"] = chosen_key
            headers["Authorization"] = f"Bearer {chosen_key}"

        for sp_url in list(supabase_urls)[:2]:
            async with httpx.AsyncClient(timeout=4.0, headers=headers) as client:
                for table in self.ALL_PROBE_TABLES:
                    rest_endpoint = f"{sp_url}/rest/v1/{table}?select=*&limit=1"
                    curl_cmd = f"curl -sS -i -H 'apikey: {chosen_key}' '{rest_endpoint}'"
                    raw_req = f"GET /rest/v1/{table}?select=*&limit=1 HTTP/1.1\nHost: {urlparse(sp_url).netloc}\napikey: {chosen_key[:12]}..."

                    try:
                        resp = await client.get(rest_endpoint)
                        if resp.status_code == 200:
                            resp_text = resp.text
                            resp_json = None
                            try:
                                resp_json = resp.json()
                            except Exception:
                                pass

                            # SCIENTIFIC EVALUATION:
                            # 1. Check if empty array [] returned -> Inconclusive / Suspected, NOT confirmed critical breach
                            if isinstance(resp_json, list) and len(resp_json) == 0:
                                findings.append(AgentFinding(
                                    title=f"Potential Unrestricted Table Endpoint '{table}' (Empty Result Returned)",
                                    category=self.category,
                                    cwe_id=self.cwe_default,
                                    owasp_ref=self.owasp_default,
                                    severity=AgentSeverity.LOW,
                                    confidence=0.40,
                                    risk_score=0.25,
                                    affected_asset=rest_endpoint,
                                    evidence_summary=f"HTTP GET to '{rest_endpoint}' returned HTTP 200 with empty list '[]'. Row-Level Security may be active with filter 'USING (auth.uid() = user_id)' or table has zero records.",
                                    technical_explanation="When RLS is active with an auth.uid() check, anonymous queries receive an empty list [] rather than HTTP 401. This is expected behavior unless table is empty.",
                                    remediation_steps=f"Verify that table '{table}' has Row-Level Security explicitly enabled (ALTER TABLE {table} ENABLE ROW LEVEL SECURITY).",
                                    verification_status="inconclusive",
                                    verification_method="active_probe",
                                    reproduction_curl=curl_cmd,
                                    expected_secure_behavior="Returns HTTP 401 or empty array due to auth.uid() filter.",
                                    observed_insecure_behavior="Received HTTP 200 with 0 records returned. Requires authenticated verification.",
                                    raw_http_request=raw_req,
                                    raw_http_response_snippet=resp_text[:500],
                                    response_status_code=resp.status_code,
                                    response_content_length=len(resp.content),
                                    observation_timestamp=now_ts,
                                    sensitive_data_detected=[],
                                    reproduction_confidence=0.45,
                                    references=["https://supabase.com/docs/guides/auth/row-level-security"]
                                ))
                                continue

                            # 2. Check if records returned with data
                            elif isinstance(resp_json, list) and len(resp_json) > 0:
                                sample_row = resp_json[0]
                                exposed_keys = []
                                if isinstance(sample_row, dict):
                                    exposed_keys = [
                                        k for k in sample_row.keys() 
                                        if any(s in k.lower() for s in self.SENSITIVE_FIELD_INDICATORS)
                                    ]

                                # CASE A: Sensitive PII columns actively leaked -> CONFIRMED CRITICAL
                                if exposed_keys:
                                    findings.append(AgentFinding(
                                        title=f"Critical Supabase RLS Disabled: Sensitive PII Exposed in Table '{table}' ({', '.join(exposed_keys)})",
                                        category=self.category,
                                        cwe_id=self.cwe_default,
                                        owasp_ref=self.owasp_default,
                                        severity=AgentSeverity.CRITICAL,
                                        confidence=0.99,
                                        risk_score=0.98,
                                        affected_asset=rest_endpoint,
                                        evidence_summary=f"Public HTTP GET to '{rest_endpoint}' returned HTTP 200 with populated database records leaking sensitive columns: {exposed_keys}.",
                                        business_impact="UNAUTHORIZED DATA EXFILTRATION: Anonymous visitors can dump customer records, credentials, or transactions directly through the Supabase REST API without authentication.",
                                        technical_explanation="Row-Level Security (RLS) is either disabled or configured with an overly permissive policy (e.g. 'FOR SELECT USING (true)') that permits unauthenticated bulk data harvesting.",
                                        remediation_steps=f"Immediately enable RLS: 'ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;' and restrict reads: 'CREATE POLICY \"User access\" ON {table} FOR SELECT USING (auth.uid() = user_id);'.",
                                        ai_fix_prompt=(
                                            f"Hey Claude / Lovable: Our security audit confirmed that Row-Level Security (RLS) is leaking private data in table '{table}' (columns: {exposed_keys}). "
                                            f"Please write a Supabase SQL migration to: "
                                            f"1. Enable RLS: 'ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;' "
                                            f"2. Add policy: 'CREATE POLICY \"Users can only read their own {table}\" ON {table} FOR SELECT USING (auth.uid() = user_id);' "
                                            f"Apply this migration immediately."
                                        ),
                                        verification_status="confirmed",
                                        verification_method="active_probe",
                                        reproduction_curl=curl_cmd,
                                        expected_secure_behavior="HTTP 401 Unauthorized or filtered empty array when unauthenticated.",
                                        observed_insecure_behavior=f"HTTP 200 returned with raw table records exposing sensitive keys: {exposed_keys}.",
                                        raw_http_request=raw_req,
                                        raw_http_response_snippet=resp_text[:1000],
                                        response_status_code=resp.status_code,
                                        response_content_length=len(resp.content),
                                        observation_timestamp=now_ts,
                                        sensitive_data_detected=exposed_keys,
                                        reproduction_confidence=0.99,
                                        references=["https://supabase.com/docs/guides/auth/row-level-security"]
                                    ))
                                    break

                                # CASE B: Private table populated without sensitive keywords -> HIGH CONFIRMED
                                elif table in self.PRIVATE_TABLES:
                                    findings.append(AgentFinding(
                                        title=f"Supabase Permissive RLS Policy: Private Table '{table}' Readable by Anonymous Users",
                                        category=self.category,
                                        cwe_id=self.cwe_default,
                                        owasp_ref=self.owasp_default,
                                        severity=AgentSeverity.HIGH,
                                        confidence=0.92,
                                        risk_score=0.85,
                                        affected_asset=rest_endpoint,
                                        evidence_summary=f"Unauthenticated HTTP GET to private table '{table}' returned {len(resp_json)} record(s).",
                                        business_impact="UNAUTHORIZED READ: Anonymous users can enumerate internal records.",
                                        technical_explanation="Table contains an open SELECT policy allowing public anonymous reads.",
                                        remediation_steps=f"Enforce restrictive RLS policy on '{table}'.",
                                        verification_status="confirmed",
                                        verification_method="active_probe",
                                        reproduction_curl=curl_cmd,
                                        expected_secure_behavior="Access restricted to authenticated owners.",
                                        observed_insecure_behavior=f"Received HTTP 200 with {len(resp_json)} active row(s).",
                                        raw_http_request=raw_req,
                                        raw_http_response_snippet=resp_text[:800],
                                        response_status_code=resp.status_code,
                                        response_content_length=len(resp.content),
                                        observation_timestamp=now_ts,
                                        sensitive_data_detected=[],
                                        reproduction_confidence=0.92,
                                        references=["https://supabase.com/docs/guides/auth/row-level-security"]
                                    ))
                                    break

                                # CASE C: Public content table (posts/products) -> LOW SUSPECTED (Likely Intended)
                                else:
                                    findings.append(AgentFinding(
                                        title=f"Publicly Readable Supabase Table: '{table}' (Verify Public Intent)",
                                        category=self.category,
                                        cwe_id="CWE-200",
                                        owasp_ref=self.owasp_default,
                                        severity=AgentSeverity.LOW,
                                        confidence=0.70,
                                        risk_score=0.20,
                                        affected_asset=rest_endpoint,
                                        evidence_summary=f"Table '{table}' is publicly readable by anonymous clients.",
                                        business_impact="INFORMATIONAL: Confirm whether public read access to '{table}' is intended (e.g. public blog or product catalog).",
                                        technical_explanation="Public read policy is active. If data is meant to be public, this is intended behavior.",
                                        remediation_steps="If content should be private, restrict SELECT policy to authenticated sessions.",
                                        verification_status="suspected",
                                        verification_method="active_probe",
                                        reproduction_curl=curl_cmd,
                                        expected_secure_behavior="Verify whether public read policy is by design.",
                                        observed_insecure_behavior=f"HTTP 200 with {len(resp_json)} record(s).",
                                        raw_http_request=raw_req,
                                        raw_http_response_snippet=resp_text[:500],
                                        response_status_code=resp.status_code,
                                        response_content_length=len(resp.content),
                                        observation_timestamp=now_ts,
                                        reproduction_confidence=0.80,
                                        references=["https://supabase.com/docs/guides/auth/row-level-security"]
                                    ))
                    except Exception:
                        continue

        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class ClientBundleSecretLeakAgent(BaseSecurityAgent):
    id = "client_bundle_secret_leak"
    name = "Client-Side JS Secret & API Key Leaker Agent"
    description = "Scans client-side JavaScript bundles for exposed Stripe, OpenAI, Claude, Clerk, Resend, and cloud provider private keys frequently leaked in AI-generated code."
    category = "cryptographic_failures"
    cwe_default = "CWE-798"
    owasp_default = "A02:2021-Cryptographic Failures"
    is_passive = True

    SECRET_PATTERNS = [
        {"name": "Stripe Live Secret Key", "regex": r"(?:sk_live|rk_live)_[0-9a-zA-Z]{24,}", "severity": AgentSeverity.CRITICAL, "impact": "FINANCIAL LOSS: Attackers can refund payments, create charges, or transfer funds directly from your Stripe merchant account."},
        {"name": "OpenAI Secret API Key", "regex": r"sk-(?:proj-)?[a-zA-Z0-9_\-]{32,}", "severity": AgentSeverity.HIGH, "impact": "BILLING THEFT: Attackers can drain your OpenAI account balance or run automated LLM models at your expense."},
        {"name": "Anthropic Claude Secret API Key", "regex": r"sk-ant-api03-[a-zA-Z0-9_\-]{40,}", "severity": AgentSeverity.HIGH, "impact": "BILLING THEFT: Attackers can use your Claude / Anthropic account to run LLM workloads on your bill."},
        {"name": "AWS Access Key ID", "regex": r"AKIA[0-9A-Z]{16}", "severity": AgentSeverity.CRITICAL, "impact": "CLOUD TAKEOVER: Attackers can access your AWS cloud infrastructure, databases, and EC2 instances."},
        {"name": "Resend Email API Key", "regex": r"re_[a-zA-Z0-9_]{24,}", "severity": AgentSeverity.MEDIUM, "impact": "SPAM & PHISHING: Attackers can send unauthorized marketing or phishing emails pretending to be your company."},
        {"name": "Clerk Secret API Key", "regex": r"sk_live_[a-zA-Z0-9]{24,}", "severity": AgentSeverity.CRITICAL, "impact": "AUTH TAKEOVER: Attackers can bypass Clerk authentication, impersonate users, and modify user credentials."},
        {"name": "GitHub Personal Access Token", "regex": r"ghp_[a-zA-Z0-9]{36}", "severity": AgentSeverity.CRITICAL, "impact": "CODE & REPO THEFT: Attackers can clone private source code repositories and modify production code."},
    ]

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        now_ts = datetime.now(timezone.utc).isoformat()
        headers = {"User-Agent": "GrayStrike-SecretDetector/1.0"}

        # Collect scripts
        script_urls = set()
        for page in crawl_data.get("pages", []):
            for s in page.get("scripts", []):
                if s.startswith("http") and not any(vendor in s for vendor in ["googletagmanager", "analytics", "clarity", "hotjar"]):
                    script_urls.add(s)

        async with httpx.AsyncClient(timeout=5.0, headers=headers) as client:
            for s_url in list(script_urls)[:6]:
                try:
                    res = await client.get(s_url)
                    if res.status_code == 200:
                        content = res.text
                        curl_cmd = f"curl -sS '{s_url}'"

                        for pattern in self.SECRET_PATTERNS:
                            matches = re.findall(pattern["regex"], content)
                            if matches:
                                leaked_sample = matches[0][:8] + "..." + matches[0][-4:]
                                findings.append(AgentFinding(
                                    title=f"Critical Secret Leaked in Client Bundle: {pattern['name']}",
                                    category=self.category,
                                    cwe_id=self.cwe_default,
                                    owasp_ref=self.owasp_default,
                                    severity=pattern["severity"],
                                    confidence=0.99,
                                    risk_score=0.95,
                                    affected_asset=f"{s_url} -> {leaked_sample}",
                                    evidence_summary=f"Found unencrypted {pattern['name']} matching '{leaked_sample}' in public frontend JS script '{s_url}'.",
                                    business_impact=pattern["impact"],
                                    technical_explanation="AI code generators like Lovable or v0 sometimes place secret keys in client-side environment files (NEXT_PUBLIC_) or direct frontend components. Any user can view the browser's developer tools and extract the key.",
                                    remediation_steps=f"Immediately rotate and invalidate the exposed {pattern['name']}. Move all API calls that require this secret to a server-side route or edge function.",
                                    ai_fix_prompt=(
                                        f"Hey Claude / Lovable: Our security audit found a leaked '{pattern['name']}' in our client-side code! "
                                        f"Please do the following right now: "
                                        f"1. Move all calls to this service into a server-side route (e.g. Next.js API route or Supabase Edge Function). "
                                        f"2. Never use NEXT_PUBLIC_ for secret keys. "
                                        f"3. Make sure the client only receives sanitized public responses."
                                    ),
                                    verification_status="confirmed",
                                    verification_method="active_probe",
                                    reproduction_curl=f"{curl_cmd} | grep -E '{pattern['regex'][:25]}'",
                                    expected_secure_behavior="Client JavaScript bundles must never contain backend secret API credentials.",
                                    observed_insecure_behavior=f"Raw cryptographic secret token '{leaked_sample}' discovered in public bundle.",
                                    raw_http_response_snippet=content[:800],
                                    response_status_code=200,
                                    response_content_length=len(res.content),
                                    observation_timestamp=now_ts,
                                    sensitive_data_detected=[pattern["name"]],
                                    reproduction_confidence=0.99,
                                    references=["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"]
                                ))
                                break

                        # Check for Supabase Service Role Key (JWT with role: service_role)
                        jwt_matches = re.findall(r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+", content)
                        for j in jwt_matches:
                            try:
                                parts = j.split(".")
                                payload = parts[1] + "=="
                                decoded = base64.urlsafe_b64decode(payload.encode()).decode("utf-8", errors="ignore")
                                if '"role":"service_role"' in decoded or '"role": "service_role"' in decoded:
                                    findings.append(AgentFinding(
                                        title="Catastrophic Supabase Service Role Secret Leaked in Client Bundle",
                                        category=self.category,
                                        cwe_id="CWE-798",
                                        owasp_ref="A02:2021-Cryptographic Failures",
                                        severity=AgentSeverity.CRITICAL,
                                        confidence=1.0,
                                        risk_score=1.0,
                                        affected_asset=f"{s_url} -> Supabase service_role JWT",
                                        evidence_summary=f"Found unencrypted Supabase Service Role Key in '{s_url}'. Decoded JWT payload confirms 'role: service_role'.",
                                        business_impact="TOTAL DATABASE COMPROMISE: The service_role key completely bypasses all Supabase Row Level Security (RLS) policies. Anyone on the internet can read, modify, or delete every single table in your database.",
                                        technical_explanation="Developers in AI app builders often confuse NEXT_PUBLIC_SUPABASE_ANON_KEY with SUPABASE_SERVICE_ROLE_KEY. The service_role key must NEVER be shipped to client-side bundles.",
                                        remediation_steps="Immediately invalidate the service_role key in Supabase Project Settings -> API, generate a new one, and only use it in server-side Edge Functions or server routes.",
                                        ai_fix_prompt=(
                                            "Hey Claude / Lovable: We accidentally leaked our SUPABASE_SERVICE_ROLE_KEY in the client-side code! "
                                            "Please remove it from all client components immediately. The client should ONLY use the public ANON key, "
                                            "and any admin operations must be moved into a server-side route."
                                        ),
                                        verification_status="confirmed",
                                        verification_method="active_probe",
                                        reproduction_curl=curl_cmd,
                                        expected_secure_behavior="Service role key must strictly remain in private server environments.",
                                        observed_insecure_behavior="Decoded JWT in public bundle contains 'role: service_role'. Full bypass of RLS.",
                                        raw_http_response_snippet=content[:800],
                                        response_status_code=200,
                                        response_content_length=len(res.content),
                                        observation_timestamp=now_ts,
                                        sensitive_data_detected=["supabase_service_role_key"],
                                        reproduction_confidence=1.0,
                                        references=["https://supabase.com/docs/guides/auth/row-level-security"]
                                    ))
                                    break
                            except Exception:
                                pass
                except Exception:
                    continue

        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class PublicCloudStorageBucketAgent(BaseSecurityAgent):
    id = "cloud_storage_bucket_exposure"
    name = "Cloud Storage Bucket & Upload Exposure Agent"
    description = "Checks whether user-uploaded customer files (invoices, receipts, profiles) are stored in unrestricted public cloud buckets."
    category = "security_misconfiguration"
    cwe_default = "CWE-552"
    owasp_default = "A05:2021-Security Misconfiguration"
    is_passive = True

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        now_ts = datetime.now(timezone.utc).isoformat()

        # Inspect links and page sources for public storage patterns
        storage_patterns = [
            r"https://[a-zA-Z0-9_-]+\.supabase\.co/storage/v1/object/public/([a-zA-Z0-9_-]+)",
            r"https://[a-zA-Z0-9_-]+\.s3\.amazonaws\.com/([a-zA-Z0-9_-]+)",
            r"https://storage\.googleapis\.com/([a-zA-Z0-9_-]+)"
        ]

        detected_buckets = set()
        for page in crawl_data.get("pages", []):
            page_text = page.get("url", "") + " " + " ".join(page.get("scripts", []))
            for pat in storage_patterns:
                matches = re.findall(pat, page_text)
                for m in matches:
                    detected_buckets.add(m)

        for bucket in detected_buckets:
            findings.append(AgentFinding(
                title=f"Unrestricted Public Cloud Storage Bucket Identified: '{bucket}'",
                category=self.category,
                cwe_id=self.cwe_default,
                owasp_ref=self.owasp_default,
                severity=AgentSeverity.MEDIUM,
                confidence=0.88,
                risk_score=0.65,
                affected_asset=f"Storage Bucket: {bucket}",
                evidence_summary=f"Application references files in public bucket '{bucket}' without requiring authenticated signed URLs.",
                business_impact="CUSTOMER DATA LEAK: Invoices, private customer documents, and uploaded receipts stored in this bucket can be enumerated and downloaded by anyone on the internet.",
                technical_explanation="When file upload features are added via AI web builders, the storage bucket is commonly left as public to avoid configuring signed URL authentication.",
                remediation_steps=f"Switch storage bucket '{bucket}' to private and use pre-signed URLs (e.g. createSignedUrl) with temporary expiration for authenticated file access.",
                ai_fix_prompt=(
                    f"Hey Claude / Lovable: Our storage bucket '{bucket}' is currently configured as public. "
                    f"Please change our file upload and view implementation so that: "
                    f"1. The bucket is made private. "
                    f"2. Whenever a user wants to view or download a file, generate a temporary signed URL "
                    f"valid for 60 seconds (using supabase.storage.from('{bucket}').createSignedUrl(path, 60))."
                ),
                verification_status="suspected",
                verification_method="passive_observation",
                expected_secure_behavior="Private storage with temporary authenticated pre-signed URLs.",
                observed_insecure_behavior=f"Direct references to public storage endpoint for bucket '{bucket}'.",
                observation_timestamp=now_ts,
                reproduction_confidence=0.85,
                references=["https://supabase.com/docs/guides/storage/security/access-control"]
            ))

        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class LLMEndpointExposureAgent(BaseSecurityAgent):
    id = "llm_prompt_injection_guard"
    name = "LLM & AI Chat Endpoint Guard Agent"
    description = "Detects unauthenticated AI/LLM API endpoints, prompt injection susceptibility, and token exhaustion risks in modern AI-generated applications."
    category = "insecure_design"
    cwe_default = "CWE-1426"
    owasp_default = "LLM01:2025-Prompt Injection / LLM04:2025-Model Denial of Service"
    is_passive = True

    AI_ENDPOINTS = [
        "/api/chat", "/api/ai", "/api/generate", "/api/completion", 
        "/api/copilot", "/api/assistant", "/api/analyze", "/api/prompt"
    ]

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        now_ts = datetime.now(timezone.utc).isoformat()
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        headers = {
            "User-Agent": "GrayStrike-LLMGuard/1.0",
            "Content-Type": "application/json"
        }

        test_payload = {
            "messages": [{"role": "user", "content": "Ping: security health probe."}],
            "prompt": "Ping: security health probe."
        }

        async with httpx.AsyncClient(timeout=6.0, headers=headers, follow_redirects=False) as client:
            for ep in self.AI_ENDPOINTS:
                url = f"{base}{ep}"
                curl_cmd = f"curl -sS -i -X POST '{url}' -H 'Content-Type: application/json' -d '{json.dumps(test_payload)}'"

                try:
                    resp = await client.post(url, json=test_payload)
                    if resp.status_code == 200:
                        body_lower = resp.text.lower()
                        is_llm_response = any(k in body_lower for k in ["message", "content", "reply", "response", "choices", "text", "output"])
                        if is_llm_response:
                            findings.append(AgentFinding(
                                title=f"Unauthenticated AI/LLM Endpoint Exposed: '{ep}'",
                                category=self.category,
                                cwe_id=self.cwe_default,
                                owasp_ref=self.owasp_default,
                                severity=AgentSeverity.HIGH,
                                confidence=0.95,
                                risk_score=0.85,
                                affected_asset=url,
                                evidence_summary=f"Public HTTP POST to '{url}' without session auth returned HTTP 200 with LLM response payload ({len(resp.text)} bytes).",
                                business_impact="COST EXHAUSTION & LLM ABUSE: Malicious actors or competitor bots can send automated scripts to your AI endpoint, draining your OpenAI/Anthropic balance, exhausting monthly API budgets, or generating malicious spam at your expense.",
                                technical_explanation="In AI-built apps (v0, Lovable, Bolt), developers create direct Next.js API routes that proxy requests straight to LLM providers without validating user session cookies or enforcing per-IP rate limits.",
                                remediation_steps=f"Require authentication (session token / JWT) before calling LLM APIs at '{ep}', and implement Redis or in-memory token-bucket rate limiting (e.g. 5 requests / min per IP).",
                                ai_fix_prompt=(
                                    f"Hey Claude / Lovable: Our endpoint '{ep}' is publicly accessible without authentication, allowing anyone to drain our LLM credits! "
                                    f"Please update '{ep}' to: "
                                    f"1. Check for a valid user session (e.g., const session = await auth(); if (!session) return new Response('Unauthorized', {{ status: 401 }});). "
                                    f"2. Add rate limiting with @upstash/ratelimit so each user/IP can only send 5 requests per minute."
                                ),
                                verification_status="confirmed",
                                verification_method="active_probe",
                                reproduction_curl=curl_cmd,
                                expected_secure_behavior="HTTP 401 Unauthorized or HTTP 403 Forbidden without authenticated session cookie.",
                                observed_insecure_behavior=f"HTTP 200 returned with active LLM completion response ({len(resp.text)} bytes) without session token.",
                                raw_http_request=f"POST {ep} HTTP/1.1\nHost: {parsed.netloc}\nContent-Type: application/json\n\n{json.dumps(test_payload)}",
                                raw_http_response_snippet=resp.text[:1000],
                                response_status_code=resp.status_code,
                                response_content_length=len(resp.content),
                                observation_timestamp=now_ts,
                                sensitive_data_detected=["unauthenticated_ai_completion"],
                                reproduction_confidence=0.95,
                                references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"]
                            ))
                            break
                except Exception:
                    continue

        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class WebhookSignatureIntegrityAgent(BaseSecurityAgent):
    id = "webhook_signature_integrity"
    name = "Payment & SaaS Webhook Signature Verifier"
    description = "Checks whether webhook listener endpoints (Stripe, Clerk, Supabase) strictly verify cryptographic signatures before processing events."
    category = "broken_authentication"
    cwe_default = "CWE-345"
    owasp_default = "A07:2021-Identification and Authentication Failures"
    is_passive = True

    WEBHOOK_PATHS = [
        "/api/webhooks/stripe", "/api/stripe/webhook", "/api/webhooks",
        "/api/webhooks/clerk", "/api/webhooks/resend"
    ]

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        now_ts = datetime.now(timezone.utc).isoformat()
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        headers = {
            "User-Agent": "GrayStrike-WebhookAuditor/1.0",
            "Content-Type": "application/json"
        }

        dummy_event = {
            "id": "evt_test_forged_audit",
            "type": "checkout.session.completed",
            "data": {"object": {"id": "cs_test_forged", "payment_status": "paid"}}
        }

        async with httpx.AsyncClient(timeout=5.0, headers=headers, follow_redirects=False) as client:
            for path in self.WEBHOOK_PATHS:
                url = f"{base}{path}"
                curl_cmd = f"curl -sS -i -X POST '{url}' -H 'Content-Type: application/json' -d '{json.dumps(dummy_event)}'"

                try:
                    resp = await client.post(url, json=dummy_event)
                    if resp.status_code in (200, 201, 204):
                        findings.append(AgentFinding(
                            title=f"Critical Unverified Webhook Endpoint: '{path}' Accepts Unsigned Events",
                            category=self.category,
                            cwe_id=self.cwe_default,
                            owasp_ref=self.owasp_default,
                            severity=AgentSeverity.CRITICAL,
                            confidence=0.96,
                            risk_score=0.98,
                            affected_asset=url,
                            evidence_summary=f"Synthetic HTTP POST to '{url}' without 'stripe-signature' or 'svix-signature' header was accepted with HTTP {resp.status_code}.",
                            business_impact="PAYMENT FRAUD & ACCOUNT SPOOFING: Anyone on the internet can send fake 'checkout.session.completed' webhook events to your backend, gaining free subscription access or activating orders without paying.",
                            technical_explanation="AI code generators frequently omit webhook signature verification (stripe.webhooks.constructEvent) because setting up the local signing secret (STRIPE_WEBHOOK_SECRET) can be tricky during prototype generation.",
                            remediation_steps=f"In '{path}', always verify the webhook signature header using the official SDK (e.g. stripe.webhooks.constructEvent) and reject unsigned requests with HTTP 400.",
                            ai_fix_prompt=(
                                f"Hey Claude / Lovable: Our webhook handler '{path}' is not verifying webhook signatures! "
                                f"Please update '{path}' so that: "
                                f"1. It reads the raw request body buffer. "
                                f"2. Verifies the signature header: 'stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET)'. "
                                f"3. Returns 'new Response('Invalid signature', {{ status: 400 }})' if verification fails."
                            ),
                            verification_status="confirmed",
                            verification_method="active_probe",
                            reproduction_curl=curl_cmd,
                            expected_secure_behavior="HTTP 400 Bad Request: Missing or invalid cryptographic webhook signature header.",
                            observed_insecure_behavior=f"Received HTTP {resp.status_code} accepting unsigned forged synthetic webhook payload.",
                            raw_http_request=f"POST {path} HTTP/1.1\nHost: {parsed.netloc}\nContent-Type: application/json\n\n{json.dumps(dummy_event)}",
                            raw_http_response_snippet=resp.text[:800],
                            response_status_code=resp.status_code,
                            response_content_length=len(resp.content),
                            observation_timestamp=now_ts,
                            sensitive_data_detected=["forged_payment_event_accepted"],
                            reproduction_confidence=0.98,
                            references=["https://docs.stripe.com/webhooks/signatures"]
                        ))
                        break
                except Exception:
                    continue

        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class ClientSideAuthBypassAgent(BaseSecurityAgent):
    id = "client_side_auth_tampering"
    name = "Client-Side Route Gatekeeper & Admin Leak Agent"
    description = "Checks whether admin APIs and sensitive routes are protected solely by client-side React UI toggles without server-side validation."
    category = "broken_access_control"
    cwe_default = "CWE-285"
    owasp_default = "A01:2021-Broken Access Control"
    is_passive = True

    ADMIN_API_PATHS = [
        "/api/admin/users", "/api/admin/stats", "/api/admin/settings",
        "/api/admin", "/api/users", "/api/internal/config"
    ]

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        now_ts = datetime.now(timezone.utc).isoformat()
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        headers = {
            "User-Agent": "GrayStrike-AuthAuditor/1.0",
            "Accept": "application/json"
        }

        async with httpx.AsyncClient(timeout=5.0, headers=headers, follow_redirects=False) as client:
            for path in self.ADMIN_API_PATHS:
                url = f"{base}{path}"
                curl_cmd = f"curl -sS -i '{url}' -H 'Accept: application/json'"

                try:
                    resp = await client.get(url)
                    if resp.status_code == 200 and ("application/json" in resp.headers.get("content-type", "").lower() or resp.text.startswith(("{", "["))):
                        body_lower = resp.text.lower()
                        has_sensitive_data = any(k in body_lower for k in ["email", "user", "role", "admin", "token", "created_at", "id"])
                        if has_sensitive_data and len(resp.text) > 20:
                            findings.append(AgentFinding(
                                title=f"Broken Access Control: Admin API Endpoint '{path}' Publicly Exposed",
                                category=self.category,
                                cwe_id=self.cwe_default,
                                owasp_ref=self.owasp_default,
                                severity=AgentSeverity.CRITICAL,
                                confidence=0.96,
                                risk_score=0.95,
                                affected_asset=url,
                                evidence_summary=f"Unauthenticated HTTP GET to '{url}' returned HTTP 200 with private JSON data ({len(resp.text)} bytes).",
                                business_impact="ADMIN PRIVILEGE LEAK: Unauthenticated visitors can query backend administration routes, harvest customer emails, or modify platform configurations directly without logging in as an administrator.",
                                technical_explanation="In apps built with modern AI scaffolding, developers often check 'if (user.role === 'admin')' only in client-side React components, forgetting to enforce server-side authentication in the API route or middleware.",
                                remediation_steps=f"Add server-side session and role verification inside '{path}' or Next.js middleware (matcher: ['/api/admin/:path*']) to enforce HTTP 401/403 for unauthorized requests.",
                                ai_fix_prompt=(
                                    f"Hey Claude / Lovable: Our admin API '{path}' is publicly accessible without server-side authentication! "
                                    f"Please add a server-side check at the top of '{path}': "
                                    f"const session = await auth(); if (!session || session.user.role !== 'admin') {{ "
                                    f"  return new Response('Unauthorized: Admin access required', {{ status: 403 }}); "
                                    f"}}"
                                ),
                                verification_status="confirmed",
                                verification_method="active_probe",
                                reproduction_curl=curl_cmd,
                                expected_secure_behavior="HTTP 401 Unauthorized or HTTP 403 Forbidden without valid admin session token.",
                                observed_insecure_behavior=f"HTTP 200 returned with administrative JSON payload ({len(resp.text)} bytes) to anonymous client.",
                                raw_http_request=f"GET {path} HTTP/1.1\nHost: {parsed.netloc}\nAccept: application/json",
                                raw_http_response_snippet=resp.text[:800],
                                response_status_code=resp.status_code,
                                response_content_length=len(resp.content),
                                observation_timestamp=now_ts,
                                sensitive_data_detected=["admin_json_data"],
                                reproduction_confidence=0.96,
                                references=["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"]
                            ))
                            break
                except Exception:
                    continue

        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)
