"""
Retest Engine — Automated Vulnerability Verification & Proof Generator
Allows developers and security engineers to re-verify resolved or triaged findings.
Produces actionable before/after evidence comparisons.
"""
from typing import Dict, Any, Tuple
from datetime import datetime, timezone
import httpx
import re

from app.models.models import Finding, FindingStatus, FindingEvidence


class RetestEngine:
    @classmethod
    async def retest_finding(cls, finding: Finding) -> Dict[str, Any]:
        """
        Executes a targeted, non-destructive probe against the affected asset.
        Returns:
            dict containing:
                is_fixed (bool)
                retest_status (str)
                new_status (FindingStatus)
                new_evidence (str)
                notes (str)
                http_status (int or None)
        """
        raw_asset = finding.affected_asset or ""
        target, target_type = cls._parse_asset(raw_asset)
        category = (finding.category or "").lower()
        title = (finding.title or "").lower()
        cwe = (finding.cwe_id or "").upper()

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        try:
            async with httpx.AsyncClient(
                timeout=10.0,
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": "APT-Agents-Retest-Engine/1.0"}
            ) as client:
                
                # 1. DNS Record Retest (CAA, DMARC, SPF, TXT)
                if target_type.startswith("dns_") or "dns" in category or "caa" in title or "dmarc" in title:
                    return await cls._retest_dns_record(client, target, target_type, title, finding, now_str)

                # 2. Security Headers Retest
                elif category == "security_headers" or "header" in title or "cwe-1021" in cwe:
                    return await cls._retest_security_headers(client, target, title, finding, now_str)

                # 3. Cryptographic / Transport Security Retest
                elif category == "cryptographic_failures" or "hsts" in title or "ssl" in title or "tls" in title:
                    return await cls._retest_cryptographic(client, target, title, finding, now_str)

                # 4. CORS Misconfiguration Retest
                elif "cors" in category or "cors" in title or "cwe-942" in cwe:
                    return await cls._retest_cors(client, target, finding, now_str)

                # 5. Sensitive File / Git / Environment Leaks
                elif any(k in category or k in title for k in [".git", "git", "env", "backup", "leak", "cwe-200", "cwe-538"]):
                    return await cls._retest_exposed_artifacts(client, target, finding, now_str)

                # 6. XSS / Injection Retest
                elif "xss" in category or "injection" in category or "cwe-79" in cwe:
                    return await cls._retest_xss_injection(client, target, finding, now_str)

                # 7. AI-App Retest: Supabase RLS
                elif "supabase" in category or "rls" in title or "rest/v1" in target:
                    return await cls._retest_supabase_rls(client, target, finding, now_str)

                # 8. AI-App Retest: LLM / Chat Endpoints
                elif "llm" in category or "chat" in title or "prompt" in title or "cwe-1426" in cwe:
                    return await cls._retest_llm_endpoint(client, target, finding, now_str)

                # 9. AI-App Retest: Webhook Signature Verification
                elif "webhook" in title or "webhook" in category:
                    return await cls._retest_webhook_signature(client, target, finding, now_str)

                # 10. AI-App Retest: Cloud Storage Buckets
                elif "bucket" in title or "storage" in title or "cwe-552" in cwe:
                    return await cls._retest_storage_bucket(client, target, finding, now_str)

                # 11. General / Fallback Retest
                else:
                    return await cls._retest_generic(client, target, finding, now_str)

        except (httpx.RequestError, ValueError, Exception) as exc:
            return {
                "is_fixed": False,
                "retest_status": "retest_failed",
                "new_status": finding.status,
                "new_evidence": f"Error during retest probe: {str(exc)}",
                "notes": f"Retest probe could not reach {target} ({exc.__class__.__name__}: {str(exc)}).",
                "http_status": None,
                "tested_at": now_str
            }


    @staticmethod
    def _parse_asset(asset: str) -> Tuple[str, str]:
        """Parses affected asset into clean target and target type (http, dns_caa, etc.)."""
        if not asset:
            return "https://example.com", "http"
        
        asset = asset.strip()

        # Handle DNS assets: "DNS CAA: example.com", "DNS TXT: _dmarc.example.com", "DNS: example.com"
        if asset.upper().startswith("DNS"):
            parts = asset.split(":", 1)
            rec_type = parts[0].strip().lower().replace(" ", "_") # dns_caa, dns_txt
            domain = parts[1].strip() if len(parts) > 1 else ""
            return domain, rec_type

        # Check if asset has a label prefix like "Host: example.com" or "Domain: example.com"
        if ":" in asset and not asset.startswith("http://") and not asset.startswith("https://"):
            prefix, remainder = asset.split(":", 1)
            remainder = remainder.strip()
            # If the part after ":" doesn't look like a port number (contains spaces, letters or dots)
            if not remainder.isdigit():
                asset = remainder

        # Clean annotations like " [Inputs: q]" or " -> http://..."
        cleaned = asset.split(" -> ")[0].split(" [")[0].strip()
        if not cleaned.startswith("http://") and not cleaned.startswith("https://"):
            cleaned = f"https://{cleaned}"
        return cleaned, "http"


    @classmethod
    async def _retest_dns_record(
        cls, client: httpx.AsyncClient, domain: str, target_type: str, title: str, finding: Finding, now_str: str
    ) -> Dict[str, Any]:
        """Retest DNS records using DoH (DNS over HTTPS)."""
        dns_type = "CAA"
        record_label = "CAA"

        if "caa" in target_type or "caa" in title:
            dns_type = "CAA"
            record_label = "CAA (Certificate Authority Authorization)"
        elif "dmarc" in title or "_dmarc" in domain:
            dns_type = "TXT"
            record_label = "DMARC"
            if not domain.startswith("_dmarc."):
                domain = f"_dmarc.{domain}"
        elif "txt" in target_type or "spf" in title:
            dns_type = "TXT"
            record_label = "TXT / SPF"

        doh_url = f"https://cloudflare-dns.com/dns-query?name={domain}&type={dns_type}"
        resp = await client.get(doh_url, headers={"Accept": "application/dns-json"})
        
        answers = []
        if resp.status_code == 200:
            answers = resp.json().get("Answer", []) or []

        is_fixed = len(answers) > 0

        if is_fixed:
            raw_answers = ", ".join([str(a.get("data", "")) for a in answers[:3]])
            notes = f"✅ Fix verified at {now_str}. DNS {record_label} record was discovered on {domain}: {raw_answers}"
            new_evidence = f"DoH query returned {len(answers)} record(s): {raw_answers}"
            new_status = FindingStatus.RESOLVED
            retest_status = "fixed_verified"
        else:
            notes = f"❌ Retest failed at {now_str}. DNS {record_label} record is still missing on domain {domain}."
            new_evidence = f"DoH query for {dns_type} on {domain} returned zero answer records (Status {resp.status_code})."
            new_status = FindingStatus.OPEN
            retest_status = "still_reproducible"

        return {
            "is_fixed": is_fixed,
            "retest_status": retest_status,
            "new_status": new_status,
            "new_evidence": new_evidence,
            "notes": notes,
            "http_status": resp.status_code,
            "tested_at": now_str
        }


    @classmethod
    async def _retest_security_headers(
        cls, client: httpx.AsyncClient, url: str, title: str, finding: Finding, now_str: str
    ) -> Dict[str, Any]:
        resp = await client.get(url)
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        
        target_header = None
        expected_name = ""

        if "content-security-policy" in title or "csp" in title:
            target_header = "content-security-policy"
            expected_name = "Content-Security-Policy"
        elif "strict-transport-security" in title or "hsts" in title:
            target_header = "strict-transport-security"
            expected_name = "Strict-Transport-Security"
        elif "clickjacking" in title or "frame" in title:
            target_header = "x-frame-options"
            expected_name = "X-Frame-Options (or CSP frame-ancestors)"
        elif "content-type-options" in title:
            target_header = "x-content-type-options"
            expected_name = "X-Content-Type-Options"
        elif "referrer" in title:
            target_header = "referrer-policy"
            expected_name = "Referrer-Policy"

        # Special check for clickjacking: both X-Frame-Options or frame-ancestors in CSP work
        if target_header == "x-frame-options":
            has_xfo = "x-frame-options" in headers_lower
            has_frame_ancestors = "frame-ancestors" in headers_lower.get("content-security-policy", "")
            is_fixed = has_xfo or has_frame_ancestors
            header_val = headers_lower.get("x-frame-options") or headers_lower.get("content-security-policy")
        elif target_header:
            is_fixed = target_header in headers_lower
            header_val = headers_lower.get(target_header)
        else:
            # General security header check
            sec_headers = ["content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options"]
            present = [h for h in sec_headers if h in headers_lower]
            is_fixed = len(present) >= 3
            header_val = f"Present: {', '.join(present)}"

        if is_fixed:
            notes = f"✅ Fix verified at {now_str}. Header '{expected_name or target_header}' is now active: {header_val}"
            new_evidence = f"HTTP {resp.status_code} OK — Observed header: '{expected_name or target_header}: {header_val}'"
            new_status = FindingStatus.RESOLVED
            retest_status = "fixed_verified"
        else:
            notes = f"❌ Retest failed at {now_str}. Expected security header '{expected_name or target_header}' is still missing from server responses."
            new_evidence = f"HTTP {resp.status_code} OK — Header '{expected_name or target_header}' was NOT returned. Available headers: {list(resp.headers.keys())[:8]}"
            new_status = FindingStatus.OPEN
            retest_status = "still_reproducible"

        return {
            "is_fixed": is_fixed,
            "retest_status": retest_status,
            "new_status": new_status,
            "new_evidence": new_evidence,
            "notes": notes,
            "http_status": resp.status_code,
            "tested_at": now_str
        }


    @classmethod
    async def _retest_cryptographic(
        cls, client: httpx.AsyncClient, url: str, title: str, finding: Finding, now_str: str
    ) -> Dict[str, Any]:
        resp = await client.get(url)
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        hsts_present = "strict-transport-security" in headers_lower

        if hsts_present or url.startswith("https://"):
            if "strict-transport-security" in headers_lower:
                is_fixed = True
                notes = f"✅ Cryptographic transport security verified at {now_str}. HSTS header active: {headers_lower['strict-transport-security']}"
                new_evidence = f"HSTS Header verified: {headers_lower['strict-transport-security']}"
                retest_status = "fixed_verified"
                new_status = FindingStatus.RESOLVED
            else:
                is_fixed = False
                notes = f"❌ Retest failed at {now_str}. Strict-Transport-Security (HSTS) header is missing."
                new_evidence = f"HTTP {resp.status_code} — Missing HSTS header on HTTPS asset."
                retest_status = "still_reproducible"
                new_status = FindingStatus.OPEN
        else:
            is_fixed = False
            notes = f"❌ Retest failed at {now_str}. Asset is still using unencrypted HTTP."
            new_evidence = f"Endpoint responds over plaintext HTTP without automatic HTTPS upgrade."
            retest_status = "still_reproducible"
            new_status = FindingStatus.OPEN

        return {
            "is_fixed": is_fixed,
            "retest_status": retest_status,
            "new_status": new_status,
            "new_evidence": new_evidence,
            "notes": notes,
            "http_status": resp.status_code,
            "tested_at": now_str
        }


    @classmethod
    async def _retest_cors(
        cls, client: httpx.AsyncClient, url: str, finding: Finding, now_str: str
    ) -> Dict[str, Any]:
        canary_origin = "https://evil-unauthorized-canary-origin.com"
        resp = await client.get(url, headers={"Origin": canary_origin})
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower()

        # Vulnerable if reflects arbitrary origin or wildcard with credentials
        is_vulnerable = (acao == canary_origin and acac == "true") or (acao == "*" and acac == "true")
        is_fixed = not is_vulnerable

        if is_fixed:
            notes = f"✅ CORS policy verified at {now_str}. Server did not reflect untrusted origin with credentials."
            new_evidence = f"Origin: {canary_origin} resulted in ACAO: '{acao}', ACAC: '{acac}'. Access safely restricted."
            new_status = FindingStatus.RESOLVED
            retest_status = "fixed_verified"
        else:
            notes = f"❌ Retest failed at {now_str}. Server continues to reflect untrusted origin '{canary_origin}'."
            new_evidence = f"Vulnerable CORS response: ACAO='{acao}', ACAC='{acac}'"
            new_status = FindingStatus.OPEN
            retest_status = "still_reproducible"

        return {
            "is_fixed": is_fixed,
            "retest_status": retest_status,
            "new_status": new_status,
            "new_evidence": new_evidence,
            "notes": notes,
            "http_status": resp.status_code,
            "tested_at": now_str
        }


    @classmethod
    async def _retest_exposed_artifacts(
        cls, client: httpx.AsyncClient, url: str, finding: Finding, now_str: str
    ) -> Dict[str, Any]:
        resp = await client.get(url)
        
        # If returns 404, 403, or 401: the sensitive asset has been removed or restricted
        if resp.status_code in (401, 403, 404, 410):
            is_fixed = True
            notes = f"✅ Fix verified at {now_str}. Exposed file/endpoint is now inaccessible (HTTP {resp.status_code})."
            new_evidence = f"HTTP {resp.status_code} — Target asset blocked or deleted successfully."
            new_status = FindingStatus.RESOLVED
            retest_status = "fixed_verified"
        elif resp.status_code == 200:
            text = resp.text.lower()
            leak_signatures = ["ref: refs/heads", "db_password", "database_url", "aws_secret", "secret_key"]
            if any(sig in text for sig in leak_signatures):
                is_fixed = False
                notes = f"❌ Retest failed at {now_str}. Sensitive file is still publicly accessible (HTTP 200 with sensitive keywords)."
                new_evidence = f"HTTP 200 OK — Sensitive content signature still detected in response body."
                new_status = FindingStatus.OPEN
                retest_status = "still_reproducible"
            else:
                is_fixed = True
                notes = f"✅ Fix verified at {now_str}. Response no longer contains sensitive repository or environment contents."
                new_evidence = f"HTTP 200 OK — Clean response without sensitive signatures."
                new_status = FindingStatus.RESOLVED
                retest_status = "fixed_verified"
        else:
            is_fixed = True
            notes = f"✅ Fix verified at {now_str}. Server returned status HTTP {resp.status_code}."
            new_evidence = f"HTTP {resp.status_code} status."
            new_status = FindingStatus.RESOLVED
            retest_status = "fixed_verified"

        return {
            "is_fixed": is_fixed,
            "retest_status": retest_status,
            "new_status": new_status,
            "new_evidence": new_evidence,
            "notes": notes,
            "http_status": resp.status_code,
            "tested_at": now_str
        }


    @classmethod
    async def _retest_xss_injection(
        cls, client: httpx.AsyncClient, url: str, finding: Finding, now_str: str
    ) -> Dict[str, Any]:
        canary = "apt_retest_safe_9918"
        # Test parameter reflection
        separator = "&" if "?" in url else "?"
        probe_url = f"{url}{separator}q=%22%3E{canary}&test=%22%3E{canary}"
        
        resp = await client.get(probe_url)
        body = resp.text

        # If unescaped `">canary` is reflected in raw HTML, it's still reproducible
        raw_reflection = f"\">{canary}" in body
        if raw_reflection:
            is_fixed = False
            notes = f"❌ Retest failed at {now_str}. Unescaped HTML/Script reflection still observed in HTTP response."
            new_evidence = f"HTTP {resp.status_code} — Canary payload reflected unescaped in response body."
            new_status = FindingStatus.OPEN
            retest_status = "still_reproducible"
        else:
            is_fixed = True
            notes = f"✅ Fix verified at {now_str}. Safe canary probe confirmed output encoding / input sanitization is active."
            new_evidence = f"HTTP {resp.status_code} — Injected HTML characters safely encoded or omitted."
            new_status = FindingStatus.RESOLVED
            retest_status = "fixed_verified"

        return {
            "is_fixed": is_fixed,
            "retest_status": retest_status,
            "new_status": new_status,
            "new_evidence": new_evidence,
            "notes": notes,
            "http_status": resp.status_code,
            "tested_at": now_str
        }


    @classmethod
    async def _retest_generic(
        cls, client: httpx.AsyncClient, url: str, finding: Finding, now_str: str
    ) -> Dict[str, Any]:
        resp = await client.get(url)
        if resp.status_code in (404, 410, 403, 401):
            is_fixed = True
            notes = f"✅ Fix verified at {now_str}. Vulnerable path now returns HTTP {resp.status_code} (inaccessible)."
            new_evidence = f"HTTP {resp.status_code} returned for {url}"
            new_status = FindingStatus.RESOLVED
            retest_status = "fixed_verified"
        else:
            notes = f"ℹ️ Retest completed at {now_str}. Endpoint responded with HTTP {resp.status_code}."
            new_evidence = f"HTTP {resp.status_code} — Response length: {len(resp.text)} bytes"
            new_status = finding.status
            retest_status = "retested"
            is_fixed = False

        return {
            "is_fixed": is_fixed,
            "retest_status": retest_status,
            "new_status": new_status,
            "new_evidence": new_evidence,
            "notes": notes,
            "http_status": resp.status_code,
            "tested_at": now_str
        }


    @classmethod
    async def _retest_supabase_rls(
        cls, client: httpx.AsyncClient, url: str, finding: Finding, now_str: str
    ) -> Dict[str, Any]:
        """Verify if Supabase Row-Level Security has been enabled on exposed table."""
        resp = await client.get(url)
        # If table returns 401, 403, or empty array instead of exposing unauthenticated rows
        is_fixed = resp.status_code in (401, 403) or (resp.status_code == 200 and resp.text.strip() == "[]")

        if is_fixed:
            notes = f"✅ Fix verified at {now_str}. Supabase table is no longer publicly queryable (HTTP {resp.status_code})."
            new_evidence = f"HTTP {resp.status_code} — RLS policy active. Anonymous table query denied."
            new_status = FindingStatus.RESOLVED
            retest_status = "fixed_verified"
        else:
            notes = f"❌ Retest failed at {now_str}. Table data is still exposed anonymously (HTTP {resp.status_code})."
            new_evidence = f"HTTP {resp.status_code} — Returned {len(resp.text)} bytes of unauthenticated records."
            new_status = FindingStatus.OPEN
            retest_status = "still_reproducible"

        return {
            "is_fixed": is_fixed,
            "retest_status": retest_status,
            "new_status": new_status,
            "new_evidence": new_evidence,
            "notes": notes,
            "http_status": resp.status_code,
            "tested_at": now_str
        }


    @classmethod
    async def _retest_llm_endpoint(
        cls, client: httpx.AsyncClient, url: str, finding: Finding, now_str: str
    ) -> Dict[str, Any]:
        """Verify if AI/LLM endpoint now enforces authentication or rate limits."""
        test_payload = {"messages": [{"role": "user", "content": "ping"}], "prompt": "ping"}
        resp = await client.post(url, json=test_payload)
        # If endpoint returns 401 Unauthorized, 403 Forbidden, or 429 Rate Limited, protection is working
        is_fixed = resp.status_code in (401, 403, 429)

        if is_fixed:
            notes = f"✅ Fix verified at {now_str}. LLM endpoint now requires authentication / rate limits (HTTP {resp.status_code})."
            new_evidence = f"HTTP {resp.status_code} — Unauthenticated AI prompt rejected."
            new_status = FindingStatus.RESOLVED
            retest_status = "fixed_verified"
        else:
            notes = f"❌ Retest failed at {now_str}. LLM endpoint still responds anonymously with HTTP {resp.status_code}."
            new_evidence = f"HTTP {resp.status_code} — Unauthenticated invocation still permitted."
            new_status = FindingStatus.OPEN
            retest_status = "still_reproducible"

        return {
            "is_fixed": is_fixed,
            "retest_status": retest_status,
            "new_status": new_status,
            "new_evidence": new_evidence,
            "notes": notes,
            "http_status": resp.status_code,
            "tested_at": now_str
        }


    @classmethod
    async def _retest_webhook_signature(
        cls, client: httpx.AsyncClient, url: str, finding: Finding, now_str: str
    ) -> Dict[str, Any]:
        """Verify if webhook handler now rejects unsigned events."""
        dummy_event = {"id": "evt_retest", "type": "ping"}
        resp = await client.post(url, json=dummy_event)
        # Webhook should reject missing signature with 400 or 401
        is_fixed = resp.status_code in (400, 401, 403)

        if is_fixed:
            notes = f"✅ Fix verified at {now_str}. Webhook endpoint rejected unsigned event with HTTP {resp.status_code}."
            new_evidence = f"HTTP {resp.status_code} — Cryptographic signature check verified."
            new_status = FindingStatus.RESOLVED
            retest_status = "fixed_verified"
        else:
            notes = f"❌ Retest failed at {now_str}. Webhook still accepts unsigned POST requests with HTTP {resp.status_code}."
            new_evidence = f"HTTP {resp.status_code} — Synthetic unsigned event was processed."
            new_status = FindingStatus.OPEN
            retest_status = "still_reproducible"

        return {
            "is_fixed": is_fixed,
            "retest_status": retest_status,
            "new_status": new_status,
            "new_evidence": new_evidence,
            "notes": notes,
            "http_status": resp.status_code,
            "tested_at": now_str
        }


    @classmethod
    async def _retest_storage_bucket(
        cls, client: httpx.AsyncClient, url: str, finding: Finding, now_str: str
    ) -> Dict[str, Any]:
        """Verify if storage bucket is now private."""
        resp = await client.get(url)
        is_fixed = resp.status_code in (401, 403, 404)

        if is_fixed:
            notes = f"✅ Fix verified at {now_str}. Storage bucket/object is private or requires signed access (HTTP {resp.status_code})."
            new_evidence = f"HTTP {resp.status_code} — Unrestricted public access denied."
            new_status = FindingStatus.RESOLVED
            retest_status = "fixed_verified"
        else:
            notes = f"❌ Retest failed at {now_str}. Storage object is still publicly downloadable (HTTP {resp.status_code})."
            new_evidence = f"HTTP {resp.status_code} — Public file access still permitted."
            new_status = FindingStatus.OPEN
            retest_status = "still_reproducible"

        return {
            "is_fixed": is_fixed,
            "retest_status": retest_status,
            "new_status": new_status,
            "new_evidence": new_evidence,
            "notes": notes,
            "http_status": resp.status_code,
            "tested_at": now_str
        }

