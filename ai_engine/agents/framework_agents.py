"""
Framework-Specific Security Micro-Agents
Targeting modern application frameworks, NoSQL databases, and API paradigms:
21. NoSQLInjectionAgent (MongoDB / DynamoDB / Document stores - CWE-943)
22. GraphQLSecurityAgent (GraphQL Introspection & Schema leakage - CWE-200)
23. PrototypePollutionAgent (Node.js & Express Object prototype manipulation - CWE-1321)
24. SSTIIndicatorAgent (Server-Side Template Injection - Jinja2, Blade, Thymeleaf - CWE-1336)
25. FrameworkDebugExposureAgent (Spring Boot Actuator, Django Debug, Next.js manifests - CWE-215)
"""
import re
from typing import Dict, Any, Optional
from urllib.parse import urlparse, parse_qs
from ai_engine.agents.base_agent import (
    BaseSecurityAgent, AgentRegistry, AgentExecutionResult, AgentFinding, AgentSeverity
)


@AgentRegistry.register
class NoSQLInjectionAgent(BaseSecurityAgent):
    id = "nosql_injection_indicator"
    name = "NoSQL Injection Surface Agent (MongoDB / Document Stores)"
    description = "Detects JSON query parameter structures and inputs susceptible to MongoDB/NoSQL operator injection."
    category = "injection"
    cwe_default = "CWE-943"
    owasp_default = "A03:2021-Injection"
    is_passive = True

    NOSQL_KEYS = {"$where", "$regex", "$ne", "$gt", "$lt", "$in", "$nin", "$or", "$and"}

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        for p in crawl_data.get("pages", []):
            forms = p.get("forms", [])
            for f in forms:
                action = f.get("action", "")
                inputs = [i.get("name", "") for i in f.get("inputs", [])]

                # Auth forms or lookup forms accepting raw JSON or object-like parameters
                if any(k in ["username", "user", "email", "login"] for k in inputs) and any(k in ["password", "pass"] for k in inputs):
                    findings.append(AgentFinding(
                        title="Potential NoSQL Authentication Bypass Surface",
                        category=self.category,
                        cwe_id=self.cwe_default,
                        owasp_ref=self.owasp_default,
                        severity=AgentSeverity.INFO,
                        confidence=0.70,
                        risk_score=0.45,
                        affected_asset=f"{action} [Inputs: {', '.join(inputs)}]",
                        evidence_summary="Login form inputs accept structured parameters that must be protected against MongoDB/NoSQL operator injections ($ne, $gt).",
                        technical_explanation="If the application backend uses MongoDB (e.g. Mongoose or PyMongo) and parses JSON request bodies directly into findOne() queries without type casting to string, sending {'password': {'$ne': ''}} bypasses authentication.",
                        remediation_steps="Enforce strict type validation ensuring credential inputs are primitive strings. In Express, use mongo-sanitize or express-mongo-sanitize middleware.",
                        references=["https://owasp.org/www-community/attacks/NoSQL_Injection"]
                    ))
        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class GraphQLSecurityAgent(BaseSecurityAgent):
    id = "graphql_security"
    name = "GraphQL Security & Introspection Agent"
    description = "Evaluates GraphQL endpoints for public Introspection query schema leakage and denial-of-service batching."
    category = "security_misconfiguration"
    cwe_default = "CWE-200"
    owasp_default = "A05:2021-Security Misconfiguration"
    is_passive = True

    GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/gql", "/v1/graphql"]

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        api_endpoints = crawl_data.get("api_endpoints", [])
        discovered_urls = [p.get("url", "") for p in crawl_data.get("pages", [])] + api_endpoints

        for u in discovered_urls:
            path = urlparse(u).path.lower()
            if any(path == gp or path.endswith(gp) for gp in self.GRAPHQL_PATHS):
                findings.append(AgentFinding(
                    title=f"GraphQL API Endpoint Exposed at '{path}'",
                    category=self.category,
                    cwe_id="CWE-200",
                    owasp_ref=self.owasp_default,
                    severity=AgentSeverity.MEDIUM,
                    confidence=0.90,
                    risk_score=0.55,
                    affected_asset=u,
                    evidence_summary=f"Discovered GraphQL interface at '{path}'. Introspection schemas must be disabled in production.",
                    technical_explanation="GraphQL endpoints with introspection enabled allow adversaries to reverse-engineer all types, queries, mutations, and hidden administrative fields.",
                    remediation_steps="Disable schema introspection in production deployments. Implement query depth limiting and query cost analysis to prevent nested batching denial-of-service.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"]
                ))
        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class PrototypePollutionAgent(BaseSecurityAgent):
    id = "prototype_pollution"
    name = "Prototype Pollution & Node.js Security Agent"
    description = "Identifies Express and Node.js JSON merge/extend sinks vulnerable to Object.prototype manipulation."
    category = "prototype_pollution"
    cwe_default = "CWE-1321"
    owasp_default = "A03:2021-Injection"
    is_passive = True

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        techs = crawl_data.get("technologies", {})

        # If Node/Express/React full-stack detected
        if "React" in techs or any("express" in p.get("security_headers", {}).get("x-powered-by", "").lower() for p in crawl_data.get("pages", [])):
            for p in crawl_data.get("pages", []):
                for form in p.get("forms", []):
                    if form.get("method") == "POST" and len(form.get("inputs", [])) > 3:
                        findings.append(AgentFinding(
                            title="Complex JSON Input Sink (Prototype Pollution Risk)",
                            category=self.category,
                            cwe_id=self.cwe_default,
                            owasp_ref=self.owasp_default,
                            severity=AgentSeverity.LOW,
                            confidence=0.70,
                            risk_score=0.40,
                            affected_asset=f"{form.get('action')} [Node.js / Express Environment]",
                            evidence_summary="Multi-field form targets Node.js/Express backend accepting nested object structures.",
                            technical_explanation="Recursive object cloning or merge libraries (like unpatched lodash.merge) that accept '__proto__' or 'constructor' allow attackers to alter global Object prototypes.",
                            remediation_steps="Freeze Object.prototype using Object.freeze() at startup, use Map objects instead of plain objects, or use schema validation (Zod / Joi) that rejects __proto__ properties.",
                            references=["https://portswigger.net/web-security/prototype-pollution"]
                        ))
                        break
        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class SSTIIndicatorAgent(BaseSecurityAgent):
    id = "ssti_indicator"
    name = "Server-Side Template Injection (SSTI) Agent"
    description = "Assesses template reflection sinks for Jinja2 (Python), Blade (PHP), Twig, and Thymeleaf (Java)."
    category = "injection"
    cwe_default = "CWE-1336"
    owasp_default = "A03:2021-Injection"
    is_passive = True

    TEMPLATE_PARAMS = {"template", "preview", "view", "render", "msg", "content", "theme", "layout"}

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        for p in crawl_data.get("pages", []):
            url = p.get("url", "")
            params = parse_qs(urlparse(url).query)
            for param in params.keys():
                if param.lower() in self.TEMPLATE_PARAMS:
                    findings.append(AgentFinding(
                        title=f"Potential Template Reflection Surface in Parameter '{param}'",
                        category=self.category,
                        cwe_id=self.cwe_default,
                        owasp_ref=self.owasp_default,
                        severity=AgentSeverity.MEDIUM,
                        confidence=0.75,
                        risk_score=0.60,
                        affected_asset=f"{url} [Param: {param}]",
                        evidence_summary=f"Parameter '{param}' controls dynamic content rendering or preview generation.",
                        technical_explanation="When user inputs are concatenated directly into server-side template strings (such as Jinja2 in Django/Flask or Twig/Blade in PHP), template expression evaluation can escalate to remote code execution.",
                        remediation_steps="Never pass user-controlled input as the template body itself. Always pass user input as context variables into pre-compiled static template files.",
                        references=["https://portswigger.net/web-security/server-side-template-injection"]
                    ))
        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class FrameworkDebugExposureAgent(BaseSecurityAgent):
    id = "framework_debug_exposure"
    name = "Framework Diagnostics & Secret Leakage Agent"
    description = "Checks for exposed Spring Boot Actuators (/actuator), Django Debug traces, and Next.js sourcemap manifests."
    category = "security_misconfiguration"
    cwe_default = "CWE-215"
    owasp_default = "A05:2021-Security Misconfiguration"
    is_passive = True

    DEBUG_PATHS = [
        "/actuator", "/actuator/env", "/actuator/health",
        "/_next/static/development/_buildManifest.js",
        "/debug/default/view", "/phpinfo.php", "/.env"
    ]

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        for p in crawl_data.get("pages", []):
            url = p.get("url", "")
            path = urlparse(url).path.lower()

            for dp in self.DEBUG_PATHS:
                if path.startswith(dp) and p.get("status_code", 0) in (200, 301, 302):
                    findings.append(AgentFinding(
                        title=f"Critical Framework Diagnostic Endpoint Exposed at '{dp}'",
                        category=self.category,
                        cwe_id=self.cwe_default,
                        owasp_ref=self.owasp_default,
                        severity=AgentSeverity.HIGH,
                        confidence=0.95,
                        risk_score=0.85,
                        affected_asset=url,
                        evidence_summary=f"Diagnostic path '{dp}' responded with status code {p.get('status_code')}.",
                        technical_explanation="Endpoints like Spring Boot Actuators, phpinfo(), or Next.js development manifests leak database credentials, environment variables, internal IP topologies, and encryption keys.",
                        remediation_steps="Disable development endpoints in production configurations (e.g., management.endpoints.web.exposure.exclude=* in Spring Boot, DEBUG=False in Django).",
                        references=["https://cwe.mitre.org/data/definitions/215.html"]
                    ))
        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)
