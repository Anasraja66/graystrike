"""
Extended Security Micro-Agents (Completing the 20 Security Agents Suite)
Safe, passive, evidence-based security auditing agents:
6. IDORIndicatorAgent (CWE-639 / Broken Object Level Auth)
7. PrivilegeEscalationAgent (CWE-269 / Access Control)
8. CommandInjectionIndicatorAgent (CWE-78 / Command Injection Surface)
9. JWTSecurityAgent (CWE-1295 / JWT Weaknesses)
10. CSRFProtectionAgent (CWE-352 / Cross-Site Request Forgery)
11. SSRFIndicatorAgent (CWE-918 / Server-Side Request Forgery Surface)
12. FileUploadSecurityAgent (CWE-434 / Unrestricted File Upload)
13. PathTraversalIndicatorAgent (CWE-22 / Path Traversal Surface)
14. TLSConfigurationAgent (CWE-319 / Cleartext Transmission & Mixed Content)
15. SensitiveInfoDisclosureAgent (CWE-200 / Information Exposure)
16. APIAuthorizationAgent (CWE-285 / Unauthenticated API Endpoints)
17. RateLimitAgent (CWE-799 / Improper Control of Interaction Frequency)
18. DependencyExposureAgent (CWE-1104 / Outdated Components)
19. BusinessLogicRiskAgent (CWE-840 / Business Logic Vulnerabilities)
20. SecurityConfigWeaknessAgent (CWE-16 / Security Misconfiguration)
"""
import re
from typing import Dict, Any, Optional
from urllib.parse import urlparse, parse_qs
from ai_engine.agents.base_agent import (
    BaseSecurityAgent, AgentRegistry, AgentExecutionResult, AgentFinding, AgentSeverity
)


@AgentRegistry.register
class IDORIndicatorAgent(BaseSecurityAgent):
    id = "idor_indicator"
    name = "IDOR & Object-Level Authorization Agent"
    description = "Detects predictable sequential identifiers and direct object reference parameters in URLs and APIs."
    category = "broken_access_control"
    cwe_default = "CWE-639"
    owasp_default = "A01:2021-Broken Access Control"
    is_passive = True

    ID_PARAMS = {"id", "user_id", "account_id", "order_id", "doc_id", "profile_id", "invoice_id"}

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        for p in crawl_data.get("pages", []):
            url = p.get("url", "")
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            # Check for query parameters containing sequential numeric IDs
            for param, values in params.items():
                if param.lower() in self.ID_PARAMS:
                    for v in values:
                        if v.isdigit():
                            findings.append(AgentFinding(
                                title=f"Predictable Object Identifier Detected in Parameter '{param}'",
                                category=self.category,
                                cwe_id=self.cwe_default,
                                owasp_ref=self.owasp_default,
                                severity=AgentSeverity.MEDIUM,
                                confidence=0.75,
                                risk_score=0.55,
                                affected_asset=f"{url} [{param}={v}]",
                                evidence_summary=f"URL contains sequential integer identifier '{v}' for parameter '{param}'.",
                                technical_explanation="Direct reference to internal database keys without contextual authorization validation leads to Insecure Direct Object Reference (IDOR).",
                                remediation_steps="Enforce strict server-side authorization checks verifying that the authenticated session owns the requested object. Use unguessable UUIDs instead of sequential integers.",
                                references=["https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"]
                            ))

            # Check path segments with integer IDs e.g. /users/123/profile
            path_segments = [s for s in parsed.path.split("/") if s]
            for i, seg in enumerate(path_segments):
                if seg.isdigit() and len(seg) < 8 and i > 0:
                    entity_name = path_segments[i - 1]
                    findings.append(AgentFinding(
                        title=f"Potential REST API IDOR Endpoint for Entity '{entity_name}'",
                        category=self.category,
                        cwe_id=self.cwe_default,
                        owasp_ref=self.owasp_default,
                        severity=AgentSeverity.LOW,
                        confidence=0.70,
                        risk_score=0.45,
                        affected_asset=f"{url} [/{entity_name}/{seg}]",
                        evidence_summary=f"RESTful path segment reveals numeric object reference '{seg}' for resource '{entity_name}'.",
                        technical_explanation="Sequential IDs in RESTful endpoints make it straightforward for unauthorized users to enumerate and access peer records.",
                        remediation_steps="Implement object-level access control filters at the service layer.",
                        references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"]
                    ))

        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class PrivilegeEscalationAgent(BaseSecurityAgent):
    id = "privilege_escalation"
    name = "Privilege Escalation & Administrative Surface Agent"
    description = "Identifies exposed administrative dashboards, role-switching parameters, and privilege endpoints."
    category = "broken_access_control"
    cwe_default = "CWE-269"
    owasp_default = "A01:2021-Broken Access Control"
    is_passive = True

    ADMIN_PATHS = ["/admin", "/administrator", "/manage", "/dashboard/admin", "/api/v1/admin", "/portal/admin"]

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        for p in crawl_data.get("pages", []):
            url = p.get("url", "")
            parsed = urlparse(url)
            path = parsed.path.lower()

            for ap in self.ADMIN_PATHS:
                if path.startswith(ap) and p.get("status_code", 0) in (200, 301, 302):
                    findings.append(AgentFinding(
                        title=f"Exposed Administrative Interface at '{path}'",
                        category=self.category,
                        cwe_id=self.cwe_default,
                        owasp_ref=self.owasp_default,
                        severity=AgentSeverity.MEDIUM,
                        confidence=0.85,
                        risk_score=0.50,
                        affected_asset=url,
                        evidence_summary=f"Administrative portal path '{path}' responded with status code {p.get('status_code')}.",
                        technical_explanation="Administrative interfaces accessible from public networks without IP-whitelisting or multi-factor authentication are high-value brute-force targets.",
                        remediation_steps="Restrict administrative endpoints using VPN, IP allowlists, or dedicated administrative subnets with mandatory MFA.",
                        references=["https://owasp.org/www-community/attacks/Privilege_escalation"]
                    ))
        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class CommandInjectionIndicatorAgent(BaseSecurityAgent):
    id = "command_injection_indicator"
    name = "Command Injection Indicator Agent"
    description = "Surfaces dangerous parameters associated with system command execution (ping, host, exec, daemon)."
    category = "injection"
    cwe_default = "CWE-78"
    owasp_default = "A03:2021-Injection"
    is_passive = True

    CMD_PARAMS = {"ip", "host", "domain", "ping", "exec", "cmd", "command", "process", "tool", "query_exec"}

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        for p in crawl_data.get("pages", []):
            url = p.get("url", "")
            params = parse_qs(urlparse(url).query)
            for param in params.keys():
                if param.lower() in self.CMD_PARAMS:
                    findings.append(AgentFinding(
                        title=f"Potential OS Command Injection Surface in Parameter '{param}'",
                        category=self.category,
                        cwe_id=self.cwe_default,
                        owasp_ref=self.owasp_default,
                        severity=AgentSeverity.INFO,
                        confidence=0.65,
                        risk_score=0.40,
                        affected_asset=f"{url} [Param: {param}]",
                        evidence_summary=f"Parameter name '{param}' matches patterns frequently forwarded to shell interpreters.",
                        technical_explanation="Web applications that take host/IP inputs and pass them to system diagnostics (like ping or traceroute) risk command concatenation injection.",
                        remediation_steps="Avoid invoking OS shell commands directly. Use language-native APIs (e.g., socket libraries) or strictly validate inputs against an exact alphanumeric allowlist.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"]
                    ))
        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class JWTSecurityAgent(BaseSecurityAgent):
    id = "jwt_security"
    name = "JSON Web Token (JWT) Security Agent"
    description = "Examines authorization headers and local storage references for unencrypted, weak, or algorithm-none JWTs."
    category = "identification_and_auth_failures"
    cwe_default = "CWE-1295"
    owasp_default = "A07:2021-Identification and Authentication Failures"
    is_passive = True

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        jwt_pattern = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*")

        for p in crawl_data.get("pages", []):
            # Check cookies for JWT patterns
            for c in p.get("cookies", []):
                val = c.get("value", "")
                if jwt_pattern.match(val):
                    parts = val.split(".")
                    if len(parts) == 3 and not parts[2]:  # Alg 'none' with empty signature
                        findings.append(AgentFinding(
                            title=f"JWT Signature Disabled (Alg: None) in Cookie '{c.get('name')}'",
                            category=self.category,
                            cwe_id="CWE-347",
                            owasp_ref=self.owasp_default,
                            severity=AgentSeverity.CRITICAL,
                            confidence=0.98,
                            risk_score=0.90,
                            affected_asset=f"{p.get('url')} [Cookie: {c.get('name')}]",
                            evidence_summary=f"Detected unsigned JWT token in cookie '{c.get('name')}'.",
                            technical_explanation="JWTs generated without a signature or accepting the 'none' algorithm permit attackers to forge arbitrary claims, including administrative roles.",
                            remediation_steps="Configure the JWT verification engine to explicitly reject the 'none' algorithm and enforce robust asymmetric (RS256/EdDSA) or HMAC validation.",
                            references=["https://portswigger.net/web-security/jwt"]
                        ))
        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class CSRFProtectionAgent(BaseSecurityAgent):
    id = "csrf_protection"
    name = "CSRF Protection Assessment Agent"
    description = "Checks state-changing forms (POST/PUT) for the presence of anti-CSRF tokens and SameSite cookies."
    category = "security_misconfiguration"
    cwe_default = "CWE-352"
    owasp_default = "A01:2021-Broken Access Control"
    is_passive = True

    TOKEN_NAMES = {"csrf", "token", "_csrf", "authenticity_token", "csrf_token", "_token", "xsrf_token"}

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        for p in crawl_data.get("pages", []):
            for form in p.get("forms", []):
                method = form.get("method", "GET").upper()
                if method in ("POST", "PUT", "DELETE"):
                    input_names = [i.get("name", "").lower() for i in form.get("inputs", [])]
                    has_csrf_token = any(name in self.TOKEN_NAMES for name in input_names)

                    if not has_csrf_token:
                        findings.append(AgentFinding(
                            title="State-Changing Form Missing Anti-CSRF Token",
                            category=self.category,
                            cwe_id=self.cwe_default,
                            owasp_ref=self.owasp_default,
                            severity=AgentSeverity.MEDIUM,
                            confidence=0.85,
                            risk_score=0.55,
                            affected_asset=f"{form.get('action')} [Method: {method}]",
                            evidence_summary=f"Form submitting to '{form.get('action')}' lacks a recognized anti-CSRF token hidden input.",
                            technical_explanation="Without synchronized anti-CSRF tokens or strict SameSite cookie enforcement, external adversarial sites can induce users to execute unintended actions.",
                            remediation_steps="Implement unique, cryptographically random anti-CSRF tokens tied to the user's session for all state-changing requests, and set SameSite=Lax or Strict on session cookies.",
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"]
                        ))
        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class SSRFIndicatorAgent(BaseSecurityAgent):
    id = "ssrf_indicator"
    name = "Server-Side Request Forgery (SSRF) Surface Agent"
    description = "Surfaces parameters designed to fetch external URLs, webhooks, or remote images."
    category = "ssrf"
    cwe_default = "CWE-918"
    owasp_default = "A10:2021-Server-Side Request Forgery"
    is_passive = True

    URL_PARAMS = {"url", "dest", "destination", "redirect", "uri", "path", "feed", "webhook", "api_url", "fetch", "image_url"}

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        for p in crawl_data.get("pages", []):
            url = p.get("url", "")
            params = parse_qs(urlparse(url).query)
            for param in params.keys():
                if param.lower() in self.URL_PARAMS:
                    findings.append(AgentFinding(
                        title=f"Potential SSRF Exposure in Parameter '{param}'",
                        category=self.category,
                        cwe_id=self.cwe_default,
                        owasp_ref=self.owasp_default,
                        severity=AgentSeverity.LOW,
                        confidence=0.70,
                        risk_score=0.45,
                        affected_asset=f"{url} [Param: {param}]",
                        evidence_summary=f"Parameter '{param}' accepts external URLs or destination endpoints.",
                        technical_explanation="Parameters that cause the back-end server to fetch remote resources risk exposing internal metadata endpoints (169.254.169.254) or intranet systems.",
                        remediation_steps="Enforce strict protocol and domain allowlists for outbound fetches. Disable redirects and block private IP ranges (RFC 1918) at the network layer.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"]
                    ))
        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class FileUploadSecurityAgent(BaseSecurityAgent):
    id = "file_upload_security"
    name = "File Upload Configuration Agent"
    description = "Checks file upload elements for client-side MIME restrictions and dangerous multipart forms."
    category = "unrestricted_file_upload"
    cwe_default = "CWE-434"
    owasp_default = "A04:2021-Insecure Design"
    is_passive = True

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        for p in crawl_data.get("pages", []):
            for form in p.get("forms", []):
                file_inputs = [i for i in form.get("inputs", []) if i.get("type") == "file"]
                if file_inputs:
                    action = form.get("action", "")
                    findings.append(AgentFinding(
                        title="Unrestricted File Upload Form Detected",
                        category=self.category,
                        cwe_id=self.cwe_default,
                        owasp_ref=self.owasp_default,
                        severity=AgentSeverity.MEDIUM,
                        confidence=0.75,
                        risk_score=0.60,
                        affected_asset=f"{action} [Inputs: {len(file_inputs)} file field(s)]",
                        evidence_summary=f"Form at '{action}' accepts binary file uploads.",
                        technical_explanation="File upload forms without strict server-side validation of file extensions, MIME types, and file contents can allow remote web shells or executable code upload.",
                        remediation_steps="Enforce an allowlist of permitted file extensions. Re-encode uploaded files, randomize filenames, and store them outside the web root or in isolated object storage.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"]
                    ))
        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class PathTraversalIndicatorAgent(BaseSecurityAgent):
    id = "path_traversal_indicator"
    name = "Path Traversal Surface Agent"
    description = "Identifies parameters commonly vulnerable to local file inclusion (LFI) and directory traversal."
    category = "path_traversal"
    cwe_default = "CWE-22"
    owasp_default = "A01:2021-Broken Access Control"
    is_passive = True

    FILE_PARAMS = {"file", "filename", "path", "folder", "doc", "document", "view", "template", "load", "page"}

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        for p in crawl_data.get("pages", []):
            url = p.get("url", "")
            params = parse_qs(urlparse(url).query)
            for param in params.keys():
                if param.lower() in self.FILE_PARAMS:
                    findings.append(AgentFinding(
                        title=f"Path Traversal Surface in Parameter '{param}'",
                        category=self.category,
                        cwe_id=self.cwe_default,
                        owasp_ref=self.owasp_default,
                        severity=AgentSeverity.LOW,
                        confidence=0.65,
                        risk_score=0.40,
                        affected_asset=f"{url} [Param: {param}]",
                        evidence_summary=f"Parameter '{param}' references files or page templates dynamically.",
                        technical_explanation="If the server does not canonicalize paths or validate against a base directory, directory traversal sequences (../) can expose sensitive system files.",
                        remediation_steps="Avoid passing direct file paths from user inputs. Map allowed file keys to an internal dictionary or database ID.",
                        references=["https://portswigger.net/web-security/file-path-traversal"]
                    ))
        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class TLSConfigurationAgent(BaseSecurityAgent):
    id = "tls_configuration"
    name = "TLS & Transport Encryption Agent"
    description = "Verifies HTTPS protocol enforcement and flags mixed content and plaintext transmissions."
    category = "cryptographic_failures"
    cwe_default = "CWE-319"
    owasp_default = "A02:2021-Cryptographic Failures"
    is_passive = True

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        if target_url.startswith("http://"):
            findings.append(AgentFinding(
                title="Unencrypted HTTP Protocol in Use",
                category=self.category,
                cwe_id=self.cwe_default,
                owasp_ref=self.owasp_default,
                severity=AgentSeverity.HIGH,
                confidence=0.99,
                risk_score=0.75,
                affected_asset=target_url,
                evidence_summary="The application allows communication over plain unencrypted HTTP.",
                technical_explanation="Without TLS encryption, network adversaries can intercept, inspect, or tamper with credentials, session cookies, and sensitive payload data.",
                remediation_steps="Enforce HTTPS redirection permanently via HTTP 301 redirects and deploy a trusted TLS certificate.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"]
            ))

        for p in crawl_data.get("pages", []):
            url = p.get("url", "")
            if url.startswith("https://"):
                for link in p.get("links", []):
                    if link.startswith("http://"):
                        findings.append(AgentFinding(
                            title="Mixed Content Link Detected",
                            category=self.category,
                            cwe_id=self.cwe_default,
                            owasp_ref=self.owasp_default,
                            severity=AgentSeverity.LOW,
                            confidence=0.90,
                            risk_score=0.25,
                            affected_asset=f"{url} -> {link}",
                            evidence_summary=f"HTTPS page contains unencrypted HTTP reference: '{link}'.",
                            technical_explanation="Mixed active/passive content degrades the security assurances of HTTPS connections and can be blocked by modern browsers.",
                            remediation_steps="Update all embedded resources and links to use protocol-relative '//' or strict 'https://' URLs.",
                            references=["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"]
                        ))
        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class SensitiveInfoDisclosureAgent(BaseSecurityAgent):
    id = "sensitive_info_disclosure"
    name = "Sensitive Information Exposure Agent"
    description = "Checks HTTP response headers and responses for software version disclosure, debug traces, and internal paths."
    category = "identification_and_auth_failures"
    cwe_default = "CWE-200"
    owasp_default = "A05:2021-Security Misconfiguration"
    is_passive = True

    EXPOSURE_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-runtime"]

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        for p in crawl_data.get("pages", []):
            headers = p.get("security_headers", {})
            for h in self.EXPOSURE_HEADERS:
                val = headers.get(h)
                if val:
                    findings.append(AgentFinding(
                        title=f"Detailed Technology Version Exposure in '{h}' Header",
                        category=self.category,
                        cwe_id=self.cwe_default,
                        owasp_ref=self.owasp_default,
                        severity=AgentSeverity.LOW,
                        confidence=0.95,
                        risk_score=0.25,
                        affected_asset=f"{p.get('url')} [{h}: {val}]",
                        evidence_summary=f"Response includes explicit banner header '{h}: {val}'.",
                        technical_explanation="Exposing exact framework and web server versions assists adversaries in discovering matching published CVE vulnerabilities.",
                        remediation_steps=f"Disable the '{h}' banner header in your web server (e.g. server_tokens off in Nginx, expose_php = Off in php.ini).",
                        references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"]
                    ))
        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class APIAuthorizationAgent(BaseSecurityAgent):
    id = "api_authorization"
    name = "API Endpoint Security & Documentation Agent"
    description = "Identifies public API documentation endpoints (Swagger, OpenAPI, GraphQL) and checks unauthenticated API paths."
    category = "broken_access_control"
    cwe_default = "CWE-285"
    owasp_default = "A01:2021-Broken Access Control"
    is_passive = True

    DOC_PATHS = ["/swagger", "/swagger-ui.html", "/openapi.json", "/api-docs", "/graphql", "/v1/api-docs"]

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        api_endpoints = crawl_data.get("api_endpoints", [])

        for ep in api_endpoints:
            parsed = urlparse(ep)
            for dp in self.DOC_PATHS:
                if parsed.path.lower().startswith(dp):
                    findings.append(AgentFinding(
                        title=f"Exposed API Schema Documentation at '{dp}'",
                        category=self.category,
                        cwe_id="CWE-200",
                        owasp_ref=self.owasp_default,
                        severity=AgentSeverity.LOW,
                        confidence=0.95,
                        risk_score=0.30,
                        affected_asset=ep,
                        evidence_summary=f"Publicly accessible API documentation discovered at '{ep}'.",
                        technical_explanation="Unauthenticated OpenAPI/Swagger schemas provide attackers with a blueprint of all endpoints, parameters, and business logic.",
                        remediation_steps="Restrict API documentation portals to authenticated developers or internal environments only.",
                        references=["https://owasp.org/www-project-api-security/"]
                    ))
        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class RateLimitAgent(BaseSecurityAgent):
    id = "rate_limit_configuration"
    name = "Rate Limiting & Anti-Brute-Force Agent"
    description = "Evaluates login, auth, and API endpoints for rate-limiting headers and burst protections."
    category = "insufficient_anti_automation"
    cwe_default = "CWE-799"
    owasp_default = "A04:2021-Insecure Design"
    is_passive = True

    AUTH_PATHS = ["/login", "/auth", "/signin", "/token", "/api/v1/auth/login", "/password/reset"]

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        for p in crawl_data.get("pages", []):
            url = p.get("url", "")
            path = urlparse(url).path.lower()
            if any(auth_path in path for auth_path in self.AUTH_PATHS):
                headers = p.get("security_headers", {})
                has_rate_limit = any("ratelimit" in k.lower() or "retry-after" in k.lower() for k in headers.keys())

                if not has_rate_limit:
                    findings.append(AgentFinding(
                        title=f"Authentication Endpoint Lacks Visible Rate Limiting at '{path}'",
                        category=self.category,
                        cwe_id=self.cwe_default,
                        owasp_ref=self.owasp_default,
                        severity=AgentSeverity.MEDIUM,
                        confidence=0.80,
                        risk_score=0.50,
                        affected_asset=url,
                        evidence_summary="No RateLimit or Retry-After headers returned on critical authentication endpoint.",
                        technical_explanation="Login endpoints without request throttling allow attackers to execute credential stuffing and automated brute-force attacks.",
                        remediation_steps="Deploy adaptive rate limiting (e.g. 5 requests per minute per IP for authentication) with exponential backoff.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"]
                    ))
        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class DependencyExposureAgent(BaseSecurityAgent):
    id = "dependency_exposure"
    name = "Component & Dependency Exposure Agent"
    description = "Identifies known client-side libraries and versions loaded in script references."
    category = "vulnerable_and_outdated_components"
    cwe_default = "CWE-1104"
    owasp_default = "A06:2021-Vulnerable and Outdated Components"
    is_passive = True

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        techs = crawl_data.get("technologies", {})
        for tech, confidence in techs.items():
            if tech in ("jQuery", "Bootstrap"):
                findings.append(AgentFinding(
                    title=f"Detected Client-Side Library: {tech}",
                    category=self.category,
                    cwe_id=self.cwe_default,
                    owasp_ref=self.owasp_default,
                    severity=AgentSeverity.INFO,
                    confidence=0.80,
                    risk_score=0.20,
                    affected_asset=f"{target_url} [Library: {tech}]",
                    evidence_summary=f"Identified {tech} loaded on public pages with {confidence} confidence.",
                    technical_explanation="Legacy or unpinned client libraries often carry publicly known DOM-based XSS vulnerabilities.",
                    remediation_steps="Ensure all front-end dependencies are maintained at the latest stable release and audited using npm audit or Dependabot.",
                    references=["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"]
                ))
        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class BusinessLogicRiskAgent(BaseSecurityAgent):
    id = "business_logic_risk"
    name = "Business Logic & Workflow Risk Agent"
    description = "Assesses e-commerce and checkout forms for price tampering, negative values, and bypassable steps."
    category = "business_logic"
    cwe_default = "CWE-840"
    owasp_default = "A04:2021-Insecure Design"
    is_passive = True

    MONEY_PARAMS = {"price", "amount", "total", "qty", "quantity", "discount", "fee", "cost"}

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        for p in crawl_data.get("pages", []):
            for form in p.get("forms", []):
                for inp in form.get("inputs", []):
                    name = inp.get("name", "").lower()
                    if name in self.MONEY_PARAMS and inp.get("type") in ("text", "hidden", "number"):
                        findings.append(AgentFinding(
                            title=f"Client-Controlled Financial Parameter '{name}' in Form",
                            category=self.category,
                            cwe_id=self.cwe_default,
                            owasp_ref=self.owasp_default,
                            severity=AgentSeverity.HIGH,
                            confidence=0.85,
                            risk_score=0.70,
                            affected_asset=f"{form.get('action')} [Field: {name}]",
                            evidence_summary=f"Form exposes financial parameter '{name}' in client-side HTML.",
                            technical_explanation="Allowing clients to pass price or total amounts in forms enables price tampering if prices are not verified strictly against the product catalog on the server.",
                            remediation_steps="Calculate all prices, quantities, and totals strictly server-side using authoritative database records. Never trust client-submitted prices.",
                            references=["https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability"]
                        ))
        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class SecurityConfigWeaknessAgent(BaseSecurityAgent):
    id = "security_config_weakness"
    name = "Security Configuration & Default Credentials Agent"
    description = "Checks robots.txt, sitemaps, error pages, and test directories for configuration weaknesses."
    category = "security_misconfiguration"
    cwe_default = "CWE-16"
    owasp_default = "A05:2021-Security Misconfiguration"
    is_passive = True

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        for p in crawl_data.get("pages", []):
            code = p.get("status_code", 0)
            if code == 500:
                findings.append(AgentFinding(
                    title="Internal Server Error (HTTP 500) Unhandled Exception",
                    category=self.category,
                    cwe_id="CWE-209",
                    owasp_ref=self.owasp_default,
                    severity=AgentSeverity.LOW,
                    confidence=0.90,
                    risk_score=0.35,
                    affected_asset=p.get("url", target_url),
                    evidence_summary=f"Endpoint '{p.get('url')}' returned an unhandled HTTP 500 response.",
                    technical_explanation="Unhandled server errors often expose diagnostic information, framework stack traces, or database dialect details in the response body.",
                    remediation_steps="Implement global exception handlers to serve generic, sanitized error pages to end-users while writing detailed error traces to secure private log aggregators.",
                    references=["https://cwe.mitre.org/data/definitions/209.html"]
                ))
        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)
