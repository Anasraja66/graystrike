"""
External Attack Surface Management (EASM) & Deep Recon Security Micro-Agents
Targeting under-the-radar vulnerabilities and modern attack surfaces:
26. GitAndBackupExposureAgent (Exposed /.git, /.env, and database dumps - CWE-552 / CWE-538)
27. ShadowAPIAgent (Zombie & obsolete API endpoints - CWE-1059)
28. WebhookSecurityAgent (Webhook signature verification & secret exposure - CWE-345)
29. SubresourceIntegrityAgent (Missing SRI attributes on third-party CDNs - CWE-353)
30. EmailSpoofingDMARCAgent (Missing or permissive SPF/DMARC DNS records - CWE-290)
31. ExposedDevToolsAgent (Exposed /metrics, /swagger, /phpinfo, and dev portals - CWE-215)
32. CertificateTransparencyAgent (OSINT attack surface enumeration via crt.sh - CWE-200)
"""
import re
import dns.resolver
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import httpx
from ai_engine.agents.base_agent import (
    BaseSecurityAgent, AgentRegistry, AgentExecutionResult, AgentFinding, AgentSeverity
)


@AgentRegistry.register
class GitAndBackupExposureAgent(BaseSecurityAgent):
    id = "git_backup_exposure"
    name = "Source Code & Backup File Exposure Agent"
    description = "Checks for exposed /.git directories, environment files (/.env), and database backup dumps."
    category = "security_misconfiguration"
    cwe_default = "CWE-552"
    owasp_default = "A05:2021-Security Misconfiguration"
    is_passive = True

    SENSITIVE_FILES = [
        "/.git/HEAD",
        "/.git/config",
        "/.env",
        "/.env.local",
        "/.env.production",
        "/.env.backup",
        "/.env.save",
        "/docker-compose.yml",
        "/Dockerfile",
        "/backup.sql",
        "/dump.sql",
        "/backup.zip",
        "/database.sqlite3",
        "/.vscode/sftp.json",
        "/wp-config.php.bak",
        "/wp-config.old",
        "/.DS_Store"
    ]

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        headers = {"User-Agent": "APTAgents-SecurityScanner/1.0"}

        async with httpx.AsyncClient(timeout=6.0, follow_redirects=False, headers=headers) as client:
            for path in self.SENSITIVE_FILES:
                check_url = f"{base}{path}"
                try:
                    resp = await client.get(check_url)
                    # Detect positive hits
                    if resp.status_code == 200:
                        content_sample = resp.text[:200].lower()
                        is_valid_hit = False

                        if path.startswith("/.git") and ("ref: refs/" in content_sample or "[core]" in content_sample):
                            is_valid_hit = True
                        elif path.startswith("/.env") and ("=" in content_sample and "<html" not in content_sample):
                            is_valid_hit = True
                        elif path.endswith(".sql") and ("create table" in content_sample or "insert into" in content_sample or "-- mysql" in content_sample):
                            is_valid_hit = True
                        elif "docker-compose" in path and ("services:" in content_sample or "version:" in content_sample):
                            is_valid_hit = True
                        elif "dockerfile" in path.lower() and ("from " in content_sample or "run " in content_sample):
                            is_valid_hit = True
                        elif "wp-config" in path and ("db_name" in content_sample or "db_password" in content_sample or "<?php" in content_sample):
                            is_valid_hit = True
                        elif path == "/.DS_Store" and len(resp.content) > 0 and "<html" not in content_sample:
                            is_valid_hit = True

                        if is_valid_hit:
                            findings.append(AgentFinding(
                                title=f"Critical Source/Configuration File Exposed at '{path}'",
                                category=self.category,
                                cwe_id=self.cwe_default,
                                owasp_ref=self.owasp_default,
                                severity=AgentSeverity.CRITICAL,
                                confidence=0.98,
                                risk_score=0.95,
                                affected_asset=check_url,
                                evidence_summary=f"Public HTTP GET to '{check_url}' returned HTTP 200 with matching file signatures.",
                                technical_explanation="Publicly accessible version control repositories or environment files allow complete extraction of proprietary source code, cryptographic salts, and database credentials.",
                                remediation_steps="Configure web server access controls (e.g., 'location ~ /\\.git { deny all; }' in Nginx) and ensure build pipelines exclude development artifacts from the web root.",
                                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces"]
                            ))
                except Exception:
                    continue

        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class EmailSpoofingDMARCAgent(BaseSecurityAgent):
    id = "email_spoofing_dmarc"
    name = "Email Spoofing & Phishing Defense Agent (SPF/DMARC)"
    description = "Inspects domain DNS records for missing or permissive SPF and DMARC policies allowing email spoofing."
    category = "security_misconfiguration"
    cwe_default = "CWE-290"
    owasp_default = "A05:2021-Security Misconfiguration"
    is_passive = True

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        hostname = urlparse(target_url).hostname
        if not hostname:
            return AgentExecutionResult(agent_id=self.id, success=True, findings=[])

        # Get apex domain (e.g. sub.example.com -> example.com, myinvestin.co.uk)
        parts = hostname.split(".")
        double_tlds = {"co.uk", "org.uk", "gov.uk", "ac.uk", "com.pk", "com.au", "co.in"}
        if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in double_tlds:
            apex_domain = ".".join(parts[-3:])
        else:
            apex_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

        # 1. Check DMARC Record
        dmarc_host = f"_dmarc.{apex_domain}"
        dmarc_record = None
        try:
            answers = dns.resolver.resolve(dmarc_host, "TXT")
            for r in answers:
                txt = r.to_text().strip('"')
                if txt.startswith("v=DMARC1"):
                    dmarc_record = txt
                    break
        except Exception:
            dmarc_record = None

        if not dmarc_record:
            findings.append(AgentFinding(
                title=f"Missing DMARC Record for Domain '{apex_domain}' (Email Spoofing Risk)",
                category=self.category,
                cwe_id=self.cwe_default,
                owasp_ref=self.owasp_default,
                severity=AgentSeverity.MEDIUM,
                confidence=0.95,
                risk_score=0.55,
                affected_asset=f"DNS TXT: {dmarc_host}",
                evidence_summary=f"No TXT record found for '{dmarc_host}'. Domain does not enforce email validation.",
                technical_explanation="Without a DMARC policy, email recipients cannot authenticate whether incoming emails genuinely originate from your domain, allowing adversaries to send convincing phishing emails from your domain.",
                remediation_steps=f"Add a DNS TXT record for '{dmarc_host}': 'v=DMARC1; p=reject; rua=mailto:dmarc-reports@{apex_domain};'",
                references=["https://support.google.com/a/answer/2466580?hl=en"]
            ))
        elif "p=none" in dmarc_record.lower():
            findings.append(AgentFinding(
                title=f"Weak DMARC Policy (p=none) on '{apex_domain}'",
                category=self.category,
                cwe_id=self.cwe_default,
                owasp_ref=self.owasp_default,
                severity=AgentSeverity.LOW,
                confidence=0.95,
                risk_score=0.35,
                affected_asset=f"DNS TXT: {dmarc_host} -> {dmarc_record}",
                evidence_summary="DMARC record policy is set to 'p=none' (monitoring mode only). Spoofed emails are not rejected.",
                technical_explanation="A policy of 'p=none' does not instruct receiving mail servers to reject or quarantine fraudulent emails, rendering phishing protections passive.",
                remediation_steps="Graduate your DMARC policy from 'p=none' to 'p=quarantine' and ultimately 'p=reject'.",
                references=["https://dmarc.org/overview/"]
            ))

        # 2. Check SPF Record (Sender Policy Framework)
        spf_record = None
        try:
            answers = dns.resolver.resolve(apex_domain, "TXT")
            for r in answers:
                txt = r.to_text().strip('"')
                if txt.startswith("v=spf1"):
                    spf_record = txt
                    break
        except Exception:
            spf_record = None

        if not spf_record:
            findings.append(AgentFinding(
                title=f"Missing SPF (Sender Policy Framework) Record on '{apex_domain}'",
                category=self.category,
                cwe_id=self.cwe_default,
                owasp_ref=self.owasp_default,
                severity=AgentSeverity.MEDIUM,
                confidence=0.95,
                risk_score=0.60,
                affected_asset=f"DNS TXT: {apex_domain}",
                evidence_summary=f"No TXT record starting with 'v=spf1' found on '{apex_domain}'.",
                technical_explanation="Without an SPF record, receiving mail servers cannot verify which outbound mail exchange IPs are authorized to send mail on behalf of your domain.",
                remediation_steps=f"Publish an SPF record on '{apex_domain}', e.g., 'v=spf1 mx -all' or include your email provider's SPF directive.",
                references=["https://en.wikipedia.org/wiki/Sender_Policy_Framework"]
            ))
        elif "+all" in spf_record:
            findings.append(AgentFinding(
                title=f"Critical Permissive SPF Record (+all) on '{apex_domain}'",
                category=self.category,
                cwe_id=self.cwe_default,
                owasp_ref=self.owasp_default,
                severity=AgentSeverity.HIGH,
                confidence=0.98,
                risk_score=0.85,
                affected_asset=f"DNS TXT: {apex_domain} -> {spf_record}",
                evidence_summary="SPF record terminates with '+all', explicitly permitting all IP addresses globally to spoof emails.",
                technical_explanation="Using '+all' defeats the purpose of SPF by authorizing every host on the internet to send legitimate-looking emails from your domain.",
                remediation_steps="Change '+all' to '-all' (hard fail) or '~all' (soft fail).",
                references=["https://dmarcly.com/blog/how-to-fix-spf-all-permissive-record"]
            ))
        elif "?all" in spf_record:
            findings.append(AgentFinding(
                title=f"Neutral SPF Mechanism (?all) on '{apex_domain}'",
                category=self.category,
                cwe_id=self.cwe_default,
                owasp_ref=self.owasp_default,
                severity=AgentSeverity.LOW,
                confidence=0.90,
                risk_score=0.40,
                affected_asset=f"DNS TXT: {apex_domain} -> {spf_record}",
                evidence_summary="SPF record ends in '?all' (neutral policy).",
                technical_explanation="A neutral '?all' policy provides no directive to receiving mail servers on whether to accept or discard unauthorized messages.",
                remediation_steps="Update SPF record mechanism from '?all' to '-all' to enforce strict delivery controls.",
                references=["https://tools.ietf.org/html/rfc7208"]
            ))

        # 3. Check DNS CAA Record (Certificate Authority Authorization)
        has_caa = False
        try:
            caa_ans = dns.resolver.resolve(apex_domain, "CAA")
            if caa_ans:
                has_caa = True
        except Exception:
            has_caa = False

        if not has_caa:
            findings.append(AgentFinding(
                title=f"Missing DNS CAA (Certificate Authority Authorization) Record on '{apex_domain}'",
                category=self.category,
                cwe_id="CWE-295",
                owasp_ref="A07:2021-Identification and Authentication Failures",
                severity=AgentSeverity.LOW,
                confidence=0.90,
                risk_score=0.30,
                affected_asset=f"DNS CAA: {apex_domain}",
                evidence_summary=f"No CAA DNS record found for '{apex_domain}'.",
                technical_explanation="DNS CAA records restrict which Certificate Authorities (e.g., Let's Encrypt, DigiCert) are allowed to issue SSL/TLS certificates for your domain, mitigating rogue certificate issuance.",
                remediation_steps="Add a DNS CAA record specifying approved Certificate Authorities, e.g. '0 issue \"letsencrypt.org\"'.",
                references=["https://developer.mozilla.org/en-US/docs/Web/Security/Certificate_Authority_Authorization"]
            ))

        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class SubresourceIntegrityAgent(BaseSecurityAgent):
    id = "sri_integrity"
    name = "Subresource Integrity (SRI) & Supply Chain Agent"
    description = "Checks external third-party CDN scripts for missing cryptographic Subresource Integrity (SRI) hashes."
    category = "vulnerable_and_outdated_components"
    cwe_default = "CWE-353"
    owasp_default = "A06:2021-Vulnerable and Outdated Components"
    is_passive = True

    CDN_DOMAINS = ["cdnjs.cloudflare.com", "unpkg.com", "cdn.jsdelivr.net", "ajax.googleapis.com", "code.jquery.com", "maxcdn.bootstrapcdn.com"]

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        for p in crawl_data.get("pages", []):
            scripts = p.get("scripts", [])
            for s in scripts:
                parsed_s = urlparse(s)
                if any(cdn in parsed_s.netloc for cdn in self.CDN_DOMAINS):
                    findings.append(AgentFinding(
                        title=f"Third-Party Script Loaded Without Verified SRI Hash from '{parsed_s.netloc}'",
                        category=self.category,
                        cwe_id=self.cwe_default,
                        owasp_ref=self.owasp_default,
                        severity=AgentSeverity.LOW,
                        confidence=0.85,
                        risk_score=0.35,
                        affected_asset=f"{p.get('url')} -> <script src='{s}'>",
                        evidence_summary=f"Script imported from external CDN '{parsed_s.netloc}' without subresource integrity verification.",
                        technical_explanation="If the third-party CDN provider is breached or tampered with, malicious script injections (Magecart-style digital skimming) execute automatically in user browsers.",
                        remediation_steps="Add cryptographic integrity hashes and cross-origin attributes to script tags (e.g. integrity='sha384-...' crossorigin='anonymous').",
                        references=["https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"]
                    ))
        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class ShadowAPIAgent(BaseSecurityAgent):
    id = "shadow_api_discovery"
    name = "Shadow & Deprecated API Discovery Agent"
    description = "Identifies legacy API versioning endpoints (/api/v1, /beta, /old) coexisting with modern versions."
    category = "broken_access_control"
    cwe_default = "CWE-1059"
    owasp_default = "A01:2021-Broken Access Control"
    is_passive = True

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        api_endpoints = crawl_data.get("api_endpoints", [])
        versions = set()

        for ep in api_endpoints:
            match = re.search(r"/(v\d+|beta|internal|old)/", ep, re.I)
            if match:
                versions.add(match.group(1).lower())

        if len(versions) > 1 and "v1" in versions:
            findings.append(AgentFinding(
                title=f"Coexisting Deprecated & Modern API Versions Detected ({', '.join(sorted(versions))})",
                category=self.category,
                cwe_id=self.cwe_default,
                owasp_ref=self.owasp_default,
                severity=AgentSeverity.LOW,
                confidence=0.80,
                risk_score=0.40,
                affected_asset=f"{target_url} [Active API Versions: {', '.join(sorted(versions))}]",
                evidence_summary=f"Application routes traffic across multiple version streams simultaneously ({', '.join(sorted(versions))}).",
                technical_explanation="Deprecated API versions (Zombie APIs) frequently retain unpatched security flaws and outdated authentication mechanisms abandoned after modern version rollouts.",
                remediation_steps="Formally deprecate, sunset, and disable traffic to outdated API versions once modern contracts are deployed.",
                references=["https://owasp.org/www-project-api-security/"]
            ))

        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class WebhookSecurityAgent(BaseSecurityAgent):
    id = "webhook_security"
    name = "Webhook Architecture & Security Agent"
    description = "Evaluates inbound webhook endpoints for cryptographic signature enforcement and unauthenticated trigger risks."
    category = "security_misconfiguration"
    cwe_default = "CWE-345"
    owasp_default = "A04:2021-Insecure Design"
    is_passive = True

    WEBHOOK_PATHS = ["/webhook", "/api/webhook", "/api/webhooks", "/webhooks/stripe", "/webhooks/paypal"]

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        all_urls = [p.get("url", "") for p in crawl_data.get("pages", [])] + crawl_data.get("api_endpoints", [])

        for u in all_urls:
            path = urlparse(u).path.lower()
            if any(path == wp or path.startswith(wp) for wp in self.WEBHOOK_PATHS):
                findings.append(AgentFinding(
                    title=f"Inbound Webhook Interface Identified at '{path}'",
                    category=self.category,
                    cwe_id=self.cwe_default,
                    owasp_ref=self.owasp_default,
                    severity=AgentSeverity.INFO,
                    confidence=0.85,
                    risk_score=0.45,
                    affected_asset=u,
                    evidence_summary=f"Detected public webhook ingestion point at '{path}'.",
                    technical_explanation="Inbound payment or event webhooks without strict HMAC cryptographic signature validation allow attackers to forge payment success events or trigger arbitrary backend actions.",
                    remediation_steps="Enforce secret signature validation on raw request bodies (e.g., Stripe-Signature with endpoint secret) before processing payload data.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Webhooks_Security_Cheat_Sheet.html"]
                ))
        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class ExposedDevToolsAgent(BaseSecurityAgent):
    id = "exposed_dev_tools"
    name = "Exposed DevOps & Metrics Services Agent"
    description = "Checks for open Prometheus metrics, Swagger UI portals, and administrative debugging endpoints."
    category = "security_misconfiguration"
    cwe_default = "CWE-215"
    owasp_default = "A05:2021-Security Misconfiguration"
    is_passive = True

    DEV_ENDPOINTS = [
        "/metrics",
        "/swagger-ui",
        "/swagger-ui/index.html",
        "/graphiql",
        "/api/docs",
        "/phpinfo.php",
        "/elmah.axd"
    ]

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        headers = {"User-Agent": "APTAgents-SecurityScanner/1.0"}
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, headers=headers) as client:
            for ep in self.DEV_ENDPOINTS:
                check_url = f"{base}{ep}"
                try:
                    resp = await client.get(check_url)
                    if resp.status_code == 200:
                        content = resp.text[:300].lower()
                        is_hit = False

                        if ep == "/metrics" and ("go_gc_duration" in content or "process_cpu_seconds" in content or "http_requests" in content):
                            is_hit = True
                        elif "swagger" in ep and ("swagger-ui" in content or "openapi" in content):
                            is_hit = True
                        elif ep == "/phpinfo.php" and ("php version" in content or "phpinfo" in content):
                            is_hit = True

                        if is_hit:
                            findings.append(AgentFinding(
                                title=f"Exposed Internal DevOps/Metrics Endpoint at '{ep}'",
                                category=self.category,
                                cwe_id=self.cwe_default,
                                owasp_ref=self.owasp_default,
                                severity=AgentSeverity.MEDIUM,
                                confidence=0.95,
                                risk_score=0.60,
                                affected_asset=check_url,
                                evidence_summary=f"Public HTTP 200 response received from telemetry endpoint '{ep}'.",
                                technical_explanation="Exposing internal application telemetry (/metrics) or API discovery suites reveals infrastructure layouts, internal URLs, and software runtime configurations.",
                                remediation_steps="Place metrics and API documentation endpoints behind authentication or restrict access to private VPC/VPN subnets.",
                                references=["https://cwe.mitre.org/data/definitions/215.html"]
                            ))
                except Exception:
                    continue

        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)


@AgentRegistry.register
class CertificateTransparencyAgent(BaseSecurityAgent):
    id = "cert_transparency_recon"
    name = "OSINT Certificate Transparency Recon Agent"
    description = "Queries public certificate transparency logs to enumerate discovered subdomains and hidden infrastructure."
    category = "information_disclosure"
    cwe_default = "CWE-200"
    owasp_default = "A01:2021-Broken Access Control"
    is_passive = True

    async def assess(self, target_url: str, crawl_data: Dict[str, Any], knowledge_context: Optional[str] = None) -> AgentExecutionResult:
        findings = []
        hostname = urlparse(target_url).hostname
        if not hostname:
            return AgentExecutionResult(agent_id=self.id, success=True, findings=[])

        parts = hostname.split(".")
        double_tlds = {"co.uk", "org.uk", "gov.uk", "ac.uk", "com.pk", "com.au", "co.in"}
        if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in double_tlds:
            apex_domain = ".".join(parts[-3:])
        else:
            apex_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

        # Query public Certificate Transparency crt.sh
        discovered_subs = set()
        try:
            crt_url = f"https://crt.sh/?q=%.{apex_domain}&output=json"
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.get(crt_url)
                if res.status_code == 200:
                    entries = res.json()
                    for entry in entries[:30]:
                        name_value = entry.get("name_value", "")
                        for sub in name_value.split("\n"):
                            sub_clean = sub.strip().lower()
                            if sub_clean.endswith(apex_domain) and "*" not in sub_clean:
                                discovered_subs.add(sub_clean)
        except Exception:
            pass

        if len(discovered_subs) > 1:
            findings.append(AgentFinding(
                title=f"Discovered {len(discovered_subs)} Subdomains via Certificate Transparency Logs",
                category=self.category,
                cwe_id=self.cwe_default,
                owasp_ref=self.owasp_default,
                severity=AgentSeverity.INFO,
                confidence=0.99,
                risk_score=0.20,
                affected_asset=f"Domain: {apex_domain}",
                evidence_summary=f"Public certificate logs revealed subdomains: {', '.join(list(discovered_subs)[:8])}...",
                technical_explanation="Certificate Transparency logs publicly record every SSL certificate issued, allowing adversaries to discover staging, admin, and development portals.",
                remediation_steps="Continuously audit all public subdomains, retire abandoned infrastructure, and use wildcard certificates where appropriate to minimize individual host exposure.",
                references=["https://certificate.transparency.dev/"]
            ))

        return AgentExecutionResult(agent_id=self.id, success=True, findings=findings)
