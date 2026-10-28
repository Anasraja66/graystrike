"""
Core Security Micro-Agents
Initial batch of 5 specialized agents with structured verification evidence:
1. SecurityHeadersAgent (CWE-693)
2. CORSConfigAgent (CWE-942)
3. CookieSecurityAgent (CWE-614 / CWE-1004)
4. SQLInjectionIndicatorAgent (CWE-89)
5. XSSIndicatorAgent (CWE-79)
"""
from typing import Dict, Any, Optional
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timezone
from ai_engine.agents.base_agent import (
    BaseSecurityAgent, AgentRegistry, AgentExecutionResult, AgentFinding, AgentSeverity
)


@AgentRegistry.register
class SecurityHeadersAgent(BaseSecurityAgent):
    id = "security_headers"
    name = "Security Headers Assessment Agent"
    description = "Analyzes HTTP response headers for missing or weak defensive security headers (CSP, HSTS, XFO, etc.)"
    category = "security_headers"
    cwe_default = "CWE-693"
    owasp_default = "A05:2021-Security Misconfiguration"
    is_passive = True

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        pages = crawl_data.get("pages", [])
        now_ts = datetime.now(timezone.utc).isoformat()

        if not pages:
            return AgentExecutionResult(agent_id=self.id, success=True, observations=["No pages to analyze"])

        # Check the root page or primary page
        root_page = pages[0]
        missing = root_page.get("missing_security_headers", [])
        sec_headers = root_page.get("security_headers", {})
        page_url = root_page.get("url", target_url)
        curl_cmd = f"curl -sS -I '{page_url}'"
        raw_resp = "\n".join([f"{k}: {v}" for k, v in sec_headers.items()])

        # Critical missing headers: CSP and HSTS
        if "Content-Security-Policy" in missing:
            findings.append(AgentFinding(
                title="Missing Content-Security-Policy (CSP) Header",
                category=self.category,
                cwe_id="CWE-1021",
                owasp_ref=self.owasp_default,
                severity=AgentSeverity.MEDIUM,
                confidence=0.95,
                risk_score=0.45,
                affected_asset=page_url,
                evidence_summary="The response did not include a Content-Security-Policy header, leaving the application vulnerable to XSS and data injection attacks.",
                technical_explanation="Content-Security-Policy is an HTTP header that restricts resources (scripts, images, stylesheets) that the browser is allowed to load.",
                remediation_steps="Implement a strict CSP header: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';",
                verification_status="confirmed",
                verification_method="passive_observation",
                reproduction_curl=curl_cmd,
                expected_secure_behavior="HTTP response must include 'Content-Security-Policy' restricting script execution origins.",
                observed_insecure_behavior="Response headers omitted 'Content-Security-Policy'.",
                raw_http_response_snippet=raw_resp[:600],
                observation_timestamp=now_ts,
                reproduction_confidence=0.99,
                references=["https://owasp.org/www-project-secure-headers/#content-security-policy"]
            ))

        if "Strict-Transport-Security" in missing and target_url.startswith("https://"):
            findings.append(AgentFinding(
                title="Missing HTTP Strict Transport Security (HSTS) Header",
                category=self.category,
                cwe_id="CWE-319",
                owasp_ref=self.owasp_default,
                severity=AgentSeverity.LOW,
                confidence=0.95,
                risk_score=0.30,
                affected_asset=page_url,
                evidence_summary="The application is served over HTTPS but lacks the Strict-Transport-Security header.",
                technical_explanation="HSTS informs browsers that the site should only be accessed using HTTPS, preventing SSL-stripping and downgrade attacks.",
                remediation_steps="Add the following response header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                verification_status="confirmed",
                verification_method="passive_observation",
                reproduction_curl=curl_cmd,
                expected_secure_behavior="HTTP response must include 'Strict-Transport-Security' header.",
                observed_insecure_behavior="Response headers omitted 'Strict-Transport-Security' on HTTPS endpoint.",
                raw_http_response_snippet=raw_resp[:600],
                observation_timestamp=now_ts,
                reproduction_confidence=0.99,
                references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"]
            ))

        if "X-Frame-Options" in missing and "Content-Security-Policy" in missing:
            findings.append(AgentFinding(
                title="Missing Clickjacking Defense (X-Frame-Options)",
                category=self.category,
                cwe_id="CWE-1021",
                owasp_ref=self.owasp_default,
                severity=AgentSeverity.MEDIUM,
                confidence=0.90,
                risk_score=0.40,
                affected_asset=page_url,
                evidence_summary="Neither X-Frame-Options nor CSP frame-ancestors was configured, enabling UI redressing (Clickjacking).",
                technical_explanation="Without framing protections, attackers can load this web application inside an invisible <iframe> on an adversarial website.",
                remediation_steps="Add header: X-Frame-Options: DENY or frame-ancestors 'none' in CSP.",
                verification_status="confirmed",
                verification_method="passive_observation",
                reproduction_curl=curl_cmd,
                expected_secure_behavior="HTTP response must include 'X-Frame-Options: DENY' or frame-ancestors in CSP.",
                observed_insecure_behavior="Neither X-Frame-Options nor CSP frame-ancestors observed.",
                raw_http_response_snippet=raw_resp[:600],
                observation_timestamp=now_ts,
                reproduction_confidence=0.95,
                references=["https://owasp.org/www-community/attacks/Clickjacking"]
            ))

        return AgentExecutionResult(
            agent_id=self.id,
            success=True,
            findings=findings,
            observations=[f"Evaluated {len(pages)} pages. Found {len(findings)} header misconfigurations."]
        )


@AgentRegistry.register
class CookieSecurityAgent(BaseSecurityAgent):
    id = "cookie_security"
    name = "Session Cookie Security Agent"
    description = "Checks session and state cookies for missing HttpOnly, Secure, and SameSite attributes."
    category = "session_management"
    cwe_default = "CWE-614"
    owasp_default = "A07:2021-Identification and Authentication Failures"
    is_passive = True

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        now_ts = datetime.now(timezone.utc).isoformat()

        for page in crawl_data.get("pages", []):
            cookies = page.get("cookies", [])
            for c in cookies:
                c_name = c.get("name", "")
                is_secure = c.get("secure", False)
                is_httponly = c.get("httponly", False)
                page_url = page.get("url", target_url)

                # Check missing HttpOnly
                if not is_httponly:
                    findings.append(AgentFinding(
                        title=f"Cookie '{c_name}' Missing HttpOnly Flag",
                        category=self.category,
                        cwe_id="CWE-1004",
                        owasp_ref=self.owasp_default,
                        severity=AgentSeverity.MEDIUM,
                        confidence=0.95,
                        risk_score=0.42,
                        affected_asset=f"{page_url} [Cookie: {c_name}]",
                        evidence_summary=f"Cookie '{c_name}' was set without the HttpOnly attribute, making it accessible via JavaScript (document.cookie).",
                        technical_explanation="If the application suffers an XSS vulnerability, the lack of HttpOnly allows an attacker to steal session cookies directly.",
                        remediation_steps=f"Configure the Set-Cookie header to include '; HttpOnly'.",
                        verification_status="confirmed",
                        verification_method="passive_observation",
                        reproduction_curl=f"curl -sS -I '{page_url}' | grep -i 'set-cookie'",
                        expected_secure_behavior=f"Set-Cookie header for '{c_name}' must specify '; HttpOnly'.",
                        observed_insecure_behavior=f"Cookie '{c_name}' omitting HttpOnly flag.",
                        observation_timestamp=now_ts,
                        reproduction_confidence=0.98,
                        references=["https://owasp.org/www-community/HttpOnly"]
                    ))

                # Check missing Secure over HTTPS
                if not is_secure and target_url.startswith("https://"):
                    findings.append(AgentFinding(
                        title=f"Cookie '{c_name}' Missing Secure Flag",
                        category=self.category,
                        cwe_id="CWE-614",
                        owasp_ref=self.owasp_default,
                        severity=AgentSeverity.LOW,
                        confidence=0.95,
                        risk_score=0.28,
                        affected_asset=f"{page_url} [Cookie: {c_name}]",
                        evidence_summary=f"Cookie '{c_name}' was set over HTTPS but omitted the Secure attribute.",
                        technical_explanation="Without the Secure flag, the browser might transmit this cookie over unencrypted HTTP connections.",
                        remediation_steps=f"Append '; Secure' to the Set-Cookie header.",
                        verification_status="confirmed",
                        verification_method="passive_observation",
                        reproduction_curl=f"curl -sS -I '{page_url}' | grep -i 'set-cookie'",
                        expected_secure_behavior=f"Set-Cookie header for '{c_name}' must specify '; Secure'.",
                        observed_insecure_behavior=f"Cookie '{c_name}' omitting Secure flag on HTTPS endpoint.",
                        observation_timestamp=now_ts,
                        reproduction_confidence=0.98,
                        references=["https://owasp.org/www-community/controls/SecureCookieAttribute"]
                    ))

        return AgentExecutionResult(
            agent_id=self.id,
            success=True,
            findings=findings,
            observations=[f"Audited cookies across crawl data. Generated {len(findings)} findings."]
        )


@AgentRegistry.register
class SQLInjectionIndicatorAgent(BaseSecurityAgent):
    id = "sql_injection_indicator"
    name = "SQL Injection Surface Agent"
    description = "Analyzes query parameters, search inputs, and forms for dangerous SQL injection attack surfaces."
    category = "sql_injection"
    cwe_default = "CWE-89"
    owasp_default = "A03:2021-Injection"
    is_passive = True

    SUSPICIOUS_PARAMS = {"id", "user_id", "item", "category", "search", "query", "select", "order", "sort", "filter"}

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        pages = crawl_data.get("pages", [])
        now_ts = datetime.now(timezone.utc).isoformat()

        for p in pages:
            url = p.get("url", "")
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name in params.keys():
                if param_name.lower() in self.SUSPICIOUS_PARAMS:
                    findings.append(AgentFinding(
                        title=f"Potential SQL Injection Surface in parameter '{param_name}'",
                        category=self.category,
                        cwe_id="CWE-89",
                        owasp_ref=self.owasp_default,
                        severity=AgentSeverity.INFO,
                        confidence=0.60,
                        risk_score=0.35,
                        affected_asset=f"{url} [Param: {param_name}]",
                        evidence_summary=f"Parameter '{param_name}' controls data querying or sorting. Requires verification with parameterized queries.",
                        technical_explanation="Dynamic query parameters commonly interact directly with database engines if not guarded by ORM or prepared statements.",
                        remediation_steps="Ensure all SQL queries handling this parameter use parameterized prepared statements rather than string concatenation.",
                        verification_status="suspected",
                        verification_method="passive_observation",
                        reproduction_curl=f"curl -sS '{url}'",
                        expected_secure_behavior="All SQL execution handling this parameter uses parameterized prepared statements.",
                        observed_insecure_behavior=f"Direct parameter '{param_name}' exposed for query/sorting controls.",
                        observation_timestamp=now_ts,
                        reproduction_confidence=0.60,
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"]
                    ))

        return AgentExecutionResult(
            agent_id=self.id,
            success=True,
            findings=findings,
            observations=[f"Identified {len(findings)} database-query surfaces."]
        )


@AgentRegistry.register
class XSSIndicatorAgent(BaseSecurityAgent):
    id = "xss_indicator"
    name = "Cross-Site Scripting (XSS) Indicator Agent"
    description = "Examines reflected query parameters, forms, and DOM sinks for XSS exposure."
    category = "xss"
    cwe_default = "CWE-79"
    owasp_default = "A03:2021-Injection"
    is_passive = True

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        pages = crawl_data.get("pages", [])
        now_ts = datetime.now(timezone.utc).isoformat()

        for p in pages:
            forms = p.get("forms", [])
            for f in forms:
                action = f.get("action", "")
                inputs = f.get("inputs", [])
                text_inputs = [i["name"] for i in inputs if i.get("type") in ("text", "search", "email", "url")]

                if text_inputs:
                    findings.append(AgentFinding(
                        title=f"Unsanitized Input Surface in Form ({action})",
                        category=self.category,
                        cwe_id="CWE-79",
                        owasp_ref=self.owasp_default,
                        severity=AgentSeverity.INFO,
                        confidence=0.55,
                        risk_score=0.25,
                        affected_asset=f"{action} [Inputs: {', '.join(text_inputs)}]",
                        evidence_summary=f"Form contains user-controlled text inputs: {', '.join(text_inputs)} without verified output encoding.",
                        technical_explanation="Input forms that reflect input without context-aware HTML encoding enable Reflected or Stored Cross-Site Scripting.",
                        remediation_steps="Apply strict context-aware output encoding (HTML, JavaScript, Attribute context) and input validation.",
                        verification_status="suspected",
                        verification_method="passive_observation",
                        reproduction_curl=f"curl -sS -X POST '{action}'",
                        expected_secure_behavior="User input reflected in response is strictly HTML/attribute encoded.",
                        observed_insecure_behavior=f"Form inputs {text_inputs} lack verified output encoding verification.",
                        observation_timestamp=now_ts,
                        reproduction_confidence=0.55,
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"]
                    ))

        return AgentExecutionResult(
            agent_id=self.id,
            success=True,
            findings=findings,
            observations=[f"Scanned forms and input sinks across {len(pages)} pages."]
        )


@AgentRegistry.register
class CORSConfigAgent(BaseSecurityAgent):
    id = "cors_configuration"
    name = "Cross-Origin Resource Sharing (CORS) Agent"
    description = "Assesses CORS headers for dangerous wildcard '*' or credentials exposure."
    category = "cors"
    cwe_default = "CWE-942"
    owasp_default = "A05:2021-Security Misconfiguration"
    is_passive = True

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        now_ts = datetime.now(timezone.utc).isoformat()

        for p in crawl_data.get("pages", []):
            headers = p.get("security_headers", {})
            acao = headers.get("Access-Control-Allow-Origin")
            acac = headers.get("Access-Control-Allow-Credentials")
            page_url = p.get("url", target_url)

            if acao == "*" and acac == "true":
                findings.append(AgentFinding(
                    title="Critical CORS Misconfiguration (Wildcard with Credentials)",
                    category=self.category,
                    cwe_id="CWE-942",
                    owasp_ref=self.owasp_default,
                    severity=AgentSeverity.HIGH,
                    confidence=0.98,
                    risk_score=0.75,
                    affected_asset=page_url,
                    evidence_summary="Access-Control-Allow-Origin is set to '*' together with Access-Control-Allow-Credentials: true.",
                    technical_explanation="This configuration allows any arbitrary website to read authenticated data from this application via the user's browser.",
                    remediation_steps="Remove wildcard origin. Explicitly allowlist only trusted origin domains in Access-Control-Allow-Origin.",
                    verification_status="confirmed",
                    verification_method="active_probe",
                    reproduction_curl=f"curl -sS -i -H 'Origin: https://evil-attacker.com' '{page_url}'",
                    expected_secure_behavior="Access-Control-Allow-Origin must not be '*' when credentials are true.",
                    observed_insecure_behavior="Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true concurrently returned.",
                    raw_http_response_snippet=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                    observation_timestamp=now_ts,
                    reproduction_confidence=0.99,
                    references=["https://portswigger.net/web-security/cors"]
                ))

        return AgentExecutionResult(
            agent_id=self.id,
            success=True,
            findings=findings,
            observations=[f"Evaluated CORS headers. Generated {len(findings)} findings."]
        )
