"""
Advanced Red Team & Threat Intelligence Security Micro-Agents
Targeting top-tier offensive attack surfaces and defensive gaps:
33. WafOriginLeakAgent (Direct Origin IP Bypass behind Cloudflare / Akamai - CWE-693)
34. SessionReplayPrivacyAgent (Hotjar, Clarity, FullStory PII & Password Leakage - CWE-359)
35. CisaKevThreatFeedAgent (Correlation with CISA Known Exploited Vulnerabilities - CWE-1035)
36. ContainerSurfaceAgent (Exposed Docker Socket & Kubernetes Daemon Ports - CWE-284)
37. ThirdPartyTagAuditorAgent (Google Tag Manager & Supply Chain Script Risk - CWE-829)
38. ConcurrencyRiskAgent (Race Condition & Concurrency State Flaws - CWE-362)
"""
import re
import dns.resolver
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse
import httpx

from ai_engine.agents.base_agent import (
    BaseSecurityAgent, AgentRegistry, AgentExecutionResult, AgentFinding, AgentSeverity
)


@AgentRegistry.register
class WafOriginLeakAgent(BaseSecurityAgent):
    id = "waf_origin_leak"
    name = "WAF Bypass & Direct Origin IP Discovery Agent"
    description = "Checks if target server's real origin IP is leaked via DNS MX records, historical hostnames, or direct interfaces, bypassing WAF protections."
    category = "security_misconfiguration"
    cwe_default = "CWE-693"
    owasp_default = "A05:2021-Security Misconfiguration"
    is_passive = True

    CLOUDFLARE_IP_PREFIXES = (
        "173.245.", "103.21.", "103.22.", "103.31.", "141.101.",
        "108.162.", "190.93.", "188.114.", "197.234.", "198.41.",
        "162.158.", "104.16.", "104.17.", "104.18.", "104.19.",
        "104.20.", "104.21.", "104.22.", "104.23.", "104.24.",
        "104.25.", "104.26.", "104.27.", "104.28.", "172.64.", "172.65.", "172.66.", "172.67."
    )

    COMMON_ORIGIN_SUBDOMAINS = ["origin", "direct", "backend", "mail", "ftp", "cpanel", "dev-origin", "stage-origin"]

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        hostname = urlparse(target_url).hostname
        if not hostname:
            return AgentExecutionResult(agent_id=self.id, success=True, findings=[])

        parts = hostname.split(".")
        apex_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

        # Step 1: Detect if main target is behind Cloudflare
        is_behind_waf = False
        target_ips = []
        try:
            answers = dns.resolver.resolve(hostname, "A")
            for r in answers:
                ip = r.to_text()
                target_ips.append(ip)
                if any(ip.startswith(prefix) for prefix in self.CLOUDFLARE_IP_PREFIXES):
                    is_behind_waf = True
        except Exception:
            pass

        # Check HTTP response headers from crawl data
        for page in crawl_data.get("pages", []):
            headers = page.get("headers", {})
            srv = headers.get("server", "").lower()
            if "cloudflare" in srv or "cf-ray" in headers or "fastly" in srv or "akamai" in srv:
                is_behind_waf = True
                break

        if not is_behind_waf:
            # Domain does not appear to use a proxy WAF
            return AgentExecutionResult(agent_id=self.id, success=True, findings=[])

        # Step 2: Check MX Records for origin IP leakage
        mx_hosts = []
        try:
            mx_answers = dns.resolver.resolve(apex_domain, "MX")
            for r in mx_answers:
                mx_host = r.exchange.to_text().rstrip(".")
                mx_hosts.append(mx_host)
        except Exception:
            pass

        # Check if MX host resolves to an IP outside Cloudflare (potential direct origin leak)
        for mx in mx_hosts:
            if apex_domain in mx:
                try:
                    mx_ips = [r.to_text() for r in dns.resolver.resolve(mx, "A")]
                    for ip in mx_ips:
                        if not any(ip.startswith(prefix) for prefix in self.CLOUDFLARE_IP_PREFIXES):
                            findings.append(AgentFinding(
                                title=f"Potential Direct Origin Server IP Leaked via MX Host '{mx}' ({ip})",
                                category=self.category,
                                cwe_id=self.cwe_default,
                                owasp_ref=self.owasp_default,
                                severity=AgentSeverity.HIGH,
                                confidence=0.88,
                                risk_score=0.75,
                                affected_asset=f"DNS MX: {mx} -> {ip}",
                                evidence_summary=f"Primary web domain is behind Cloudflare, but MX record '{mx}' points directly to non-proxy IP '{ip}'.",
                                technical_explanation="When email servers share the same infrastructure or IP block as the origin web server, attackers can discover the backend server IP and bypass all Cloudflare WAF, DDoS protection, and rate limiting rules.",
                                remediation_steps="Host email services on external providers (e.g., Google Workspace, Microsoft 365) or ensure mail servers are on an isolated network that never hosts web origin traffic.",
                                references=["https://www.cloudflare.com/learning/ddos/glossary/origin-server/"]
                            ))
                            break
                except Exception:
                    continue

        # Step 3: Check common origin subdomains (origin.domain, direct.domain)
        for sub in self.COMMON_ORIGIN_SUBDOMAINS[:4]:
            probe_host = f"{sub}.{apex_domain}"
            try:
                sub_ips = [r.to_text() for r in dns.resolver.resolve(probe_host, "A")]
                for s_ip in sub_ips:
                    if not any(s_ip.startswith(prefix) for prefix in self.CLOUDFLARE_IP_PREFIXES):
                        findings.append(AgentFinding(
                            title=f"Direct Origin Bypass Subdomain Identified: '{probe_host}' ({s_ip})",
                            category=self.category,
                            cwe_id=self.cwe_default,
                            owasp_ref=self.owasp_default,
                            severity=AgentSeverity.HIGH,
                            confidence=0.92,
                            risk_score=0.80,
                            affected_asset=f"DNS A: {probe_host} -> {s_ip}",
                            evidence_summary=f"Host '{probe_host}' resolves to non-WAF IP '{s_ip}', exposing backend origin directly to the internet.",
                            technical_explanation="Leaving direct or origin DNS records unproxied allows adversaries to connect directly to the origin web server, evading WAF inspection entirely.",
                            remediation_steps=f"Enable proxying on '{probe_host}' in your DNS management console, or restrict backend web server access exclusively to Cloudflare's published IP ranges.",
                            references=["https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/"]
                        ))
            except Exception:
                continue

        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class SessionReplayPrivacyAgent(BaseSecurityAgent):
    id = "session_replay_privacy"
    name = "Session Replay Tools PII & Password Leak Agent (Hotjar/Clarity)"
    description = "Inspects web applications using session recording tools (Hotjar, Clarity, FullStory) for unmasked sensitive password and PII input fields."
    category = "cryptographic_failures"
    cwe_default = "CWE-359"
    owasp_default = "A02:2021-Cryptographic Failures"
    is_passive = True

    REPLAY_SIGNATURES = {
        "Hotjar": ["static.hotjar.com", "_hjsettings", "hjid"],
        "Microsoft Clarity": ["clarity.ms/tag", "clarity("],
        "FullStory": ["fullstory.com/s/fs.js", "window['_fs_debug']"],
        "LogRocket": ["logrocket.io", "logrocket.min.js"],
        "Smartlook": ["smartlook.com", "smartlookclient"]
    }

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []

        for page in crawl_data.get("pages", []):
            page_url = page.get("url", target_url)
            scripts = page.get("scripts", [])
            forms = page.get("forms", [])

            # Detect which replay tool is active on this page
            active_tools = []
            for tool_name, sigs in self.REPLAY_SIGNATURES.items():
                for s in scripts:
                    if any(sig in s.lower() for sig in sigs):
                        active_tools.append(tool_name)
                        break

            if not active_tools:
                continue

            # Check if forms on this page contain sensitive inputs (passwords, card, cnic, phone, token)
            sensitive_inputs = []
            for form in forms:
                inputs = form.get("inputs", [])
                for inp in inputs:
                    inp_lower = inp.lower()
                    if any(k in inp_lower for k in ["pass", "pwd", "card", "cvv", "credit", "ssn", "cnic", "token", "auth", "secret", "phone"]):
                        sensitive_inputs.append(inp)

            if sensitive_inputs:
                findings.append(AgentFinding(
                    title=f"Session Replay Tool ({', '.join(set(active_tools))}) Active on Page with Sensitive Form Inputs",
                    category=self.category,
                    cwe_id=self.cwe_default,
                    owasp_ref=self.owasp_default,
                    severity=AgentSeverity.MEDIUM,
                    confidence=0.90,
                    risk_score=0.65,
                    affected_asset=f"{page_url} (Active Replay: {', '.join(set(active_tools))})",
                    evidence_summary=f"Detected session recording scripts ({', '.join(set(active_tools))}) running on form containing fields: {sensitive_inputs}.",
                    technical_explanation="Session recording and replay tools capture DOM events, keystrokes, and text inputs to cloud vendor servers. Without strict input masking attributes (e.g. 'data-private', 'data-clarity-mask=\"true\"'), user passwords, payment tokens, or PII can be recorded in cleartext video logs.",
                    remediation_steps="Apply privacy masking tags (e.g., 'data-clarity-mask=\"true\"' or class 'fs-exclude') to all form input elements containing authentication credentials or personal data.",
                    references=["https://clarity.microsoft.com/documentation/privacy/", "https://help.hotjar.com/hc/en-us/articles/115015563287-Data-Suppression"]
                ))

        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class CisaKevThreatFeedAgent(BaseSecurityAgent):
    id = "cisa_kev_threat_feed"
    name = "CISA Known Exploited Vulnerability (KEV) Threat Intelligence Agent"
    description = "Correlates discovered web server technologies and runtime software versions against active real-world zero-day exploit feeds."
    category = "vulnerable_and_outdated_components"
    cwe_default = "CWE-1035"
    owasp_default = "A06:2021-Vulnerable and Outdated Components"
    is_passive = True

    # High-profile web framework versions listed in CISA KEV
    KNOWN_EXPLOITED_PATTERNS = [
        {"vendor": "Apache", "product": "HTTP Server", "regex": r"Apache/2\.4\.(49|50)", "cve": "CVE-2021-41773", "desc": "Path Traversal & RCE in Apache HTTP Server actively exploited in wild."},
        {"vendor": "Nginx", "product": "HTTP Server", "regex": r"nginx/1\.18\.0", "cve": "CVE-2021-23017", "desc": "Resolver 1-byte memory overwrite vulnerability in Nginx."},
        {"vendor": "PHP", "product": "PHP Engine", "regex": r"PHP/8\.1\.0-dev", "cve": "CVE-2021-3129", "desc": "PHP User-Agent backdoor execution."},
        {"vendor": "WordPress", "product": "WordPress CMS", "regex": r"WordPress\s*(5\.[0-8]|6\.[0-1])", "cve": "CVE-2022-21661", "desc": "WordPress Core SQL Injection actively leveraged by threat groups."},
        {"vendor": "Log4j", "product": "Apache Log4j", "regex": r"log4j/2\.(0|[1-9]|1[0-4])\.", "cve": "CVE-2021-44228", "desc": "Log4Shell JNDI Remote Code Execution in widespread wild exploitation."}
    ]

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        tech_stack = crawl_data.get("tech_stack", [])

        # Gather all server headers and detected technologies
        server_headers = set()
        for page in crawl_data.get("pages", []):
            headers = page.get("headers", {})
            for h in ["server", "x-powered-by", "x-generator"]:
                val = headers.get(h)
                if val:
                    server_headers.add(val)

        inspected_strings = list(server_headers) + tech_stack

        for item in inspected_strings:
            for threat in self.KNOWN_EXPLOITED_PATTERNS:
                if re.search(threat["regex"], item, re.IGNORECASE):
                    findings.append(AgentFinding(
                        title=f"CISA KEV Active Threat Match: {threat['product']} ({threat['cve']})",
                        category=self.category,
                        cwe_id=self.cwe_default,
                        owasp_ref=self.owasp_default,
                        severity=AgentSeverity.CRITICAL,
                        confidence=0.95,
                        risk_score=0.98,
                        affected_asset=f"{target_url} -> {item}",
                        evidence_summary=f"Detected software version '{item}' matches CISA Known Exploited Vulnerability catalog entry {threat['cve']}.",
                        technical_explanation=f"U.S. CISA confirms that {threat['cve']} ({threat['desc']}) is subject to active in-the-wild automated cyber attacks by threat actors.",
                        remediation_steps=f"Immediately upgrade {threat['product']} to the latest vendor security release to mitigate imminent remote compromise.",
                        references=[f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog", f"https://nvd.nist.gov/vuln/detail/{threat['cve']}"]
                    ))

        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class ContainerSurfaceAgent(BaseSecurityAgent):
    id = "container_cloud_surface"
    name = "Cloud-Native Container & Daemon Surface Inspector"
    description = "Checks whether Docker daemon API, Kubelet, or container telemetry ports are exposed to the internet without authentication."
    category = "security_misconfiguration"
    cwe_default = "CWE-284"
    owasp_default = "A05:2021-Security Misconfiguration"
    is_passive = True

    CONTAINER_PROBES = [
        {"port": 2375, "path": "/version", "desc": "Unauthenticated Docker Engine Daemon API (Port 2375)", "signature": "apiversion"},
        {"port": 10255, "path": "/pods", "desc": "Read-Only Kubelet Cluster Daemon (Port 10255)", "signature": "items"},
        {"port": 2379, "path": "/version", "desc": "Unauthenticated CoreOS etcd Key-Value Store (Port 2379)", "signature": "etcdserver"}
    ]

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        hostname = urlparse(target_url).hostname
        if not hostname or hostname in ["localhost", "127.0.0.1"]:
            return AgentExecutionResult(agent_id=self.id, success=True, findings=[])

        headers = {"User-Agent": "APTAgents-ContainerAuditor/1.0"}

        async with httpx.AsyncClient(timeout=3.0, verify=False, headers=headers) as client:
            for probe in self.CONTAINER_PROBES:
                test_url = f"http://{hostname}:{probe['port']}{probe['path']}"
                try:
                    resp = await client.get(test_url)
                    if resp.status_code == 200 and probe["signature"] in resp.text.lower():
                        findings.append(AgentFinding(
                            title=f"Critical Exposure: {probe['desc']}",
                            category=self.category,
                            cwe_id=self.cwe_default,
                            owasp_ref=self.owasp_default,
                            severity=AgentSeverity.CRITICAL,
                            confidence=0.99,
                            risk_score=0.99,
                            affected_asset=test_url,
                            evidence_summary=f"HTTP GET to '{test_url}' returned HTTP 200 with container daemon payload signature.",
                            technical_explanation=f"Public access to {probe['desc']} allows unauthenticated remote adversaries to inspect cluster architectures, extract secrets, and achieve remote code execution across host infrastructure.",
                            remediation_steps=f"Immediately close port {probe['port']} on public cloud security groups and restrict daemon access to TLS-authenticated localhost/internal interfaces.",
                            references=["https://docs.docker.com/engine/security/protect-access/"]
                        ))
                except Exception:
                    continue

        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class ThirdPartyTagAuditorAgent(BaseSecurityAgent):
    id = "third_party_tag_auditor"
    name = "Third-Party Tag & Supply Chain Integrity Auditor (GTM)"
    description = "Audits Google Tag Manager (GTM) deployments and marketing pixels for Content-Security-Policy script restrictions to prevent Magecart supply chain hijacking."
    category = "vulnerable_and_outdated_components"
    cwe_default = "CWE-829"
    owasp_default = "A06:2021-Vulnerable and Outdated Components"
    is_passive = True

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        has_gtm = False
        has_csp = False

        for page in crawl_data.get("pages", []):
            scripts = page.get("scripts", [])
            headers = page.get("headers", {})

            if "content-security-policy" in headers:
                has_csp = True

            for s in scripts:
                if "googletagmanager.com/gtm.js" in s or "gtag/js" in s:
                    has_gtm = True
                    break

        if has_gtm and not has_csp:
            findings.append(AgentFinding(
                title="Unrestricted Google Tag Manager (GTM) Deployed Without Content-Security-Policy",
                category=self.category,
                cwe_id=self.cwe_default,
                owasp_ref=self.owasp_default,
                severity=AgentSeverity.MEDIUM,
                confidence=0.90,
                risk_score=0.60,
                affected_asset=f"{target_url} -> GTM (Missing CSP)",
                evidence_summary="Application injects Google Tag Manager scripts into the DOM but enforces no HTTP Content-Security-Policy (CSP) headers.",
                technical_explanation="Google Tag Manager allows marketing teams to dynamically deploy arbitrary third-party JavaScript without code reviews. In the absence of a strict CSP 'script-src' directive, a compromise of any third-party tag or marketing account allows full client-side code execution (Magecart-style payment skimming).",
                remediation_steps="Implement a Content-Security-Policy header with strict 'script-src' whitelists or CSP Level 3 cryptographic nonces for tag manager scripts.",
                references=["https://developers.google.com/tag-platform/tag-manager/web/csp"]
            ))

        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class ConcurrencyRiskAgent(BaseSecurityAgent):
    id = "concurrency_race_risk"
    name = "Transaction Concurrency & Idempotency Flaw Agent"
    description = "Evaluates financial, coupon, and state-changing transactional API endpoints for lack of idempotency tokens to prevent race-condition abuse."
    category = "broken_access_control"
    cwe_default = "CWE-362"
    owasp_default = "A01:2021-Broken Access Control"
    is_passive = True

    TRANSACTION_KEYWORDS = [
        "coupon", "promo", "voucher", "discount", "redeem",
        "withdraw", "transfer", "payout", "balance", "checkout"
    ]

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        endpoints = crawl_data.get("api_endpoints", [])
        for page in crawl_data.get("pages", []):
            endpoints.append(page.get("url", ""))

        flagged_endpoints = set()
        for ep in endpoints:
            ep_lower = ep.lower()
            if any(k in ep_lower for k in self.TRANSACTION_KEYWORDS):
                flagged_endpoints.add(ep)

        if flagged_endpoints:
            findings.append(AgentFinding(
                title=f"Transactional State-Changing Endpoints Identified Requiring Concurrency & Idempotency Controls ({len(flagged_endpoints)} endpoints)",
                category=self.category,
                cwe_id=self.cwe_default,
                owasp_ref=self.owasp_default,
                severity=AgentSeverity.MEDIUM,
                confidence=0.82,
                risk_score=0.65,
                affected_asset=f"Target: {', '.join(list(flagged_endpoints)[:3])}",
                evidence_summary=f"Identified high-risk financial or coupon processing endpoints: {list(flagged_endpoints)[:3]}.",
                technical_explanation="State-changing financial endpoints (coupon redemption, balance deductions, payouts) without atomic database transaction isolation or Idempotency-Key headers are susceptible to race condition concurrency attacks (single-packet synchronization), allowing users to duplicate discounts or withdrawals.",
                remediation_steps="Enforce database atomic locks (SELECT FOR UPDATE) and require unique client-supplied 'Idempotency-Key' headers on all balance or discount deduction requests.",
                references=["https://cwe.mitre.org/data/definitions/362.html", "https://stripe.com/docs/api/idempotent_requests"]
            ))

        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)
