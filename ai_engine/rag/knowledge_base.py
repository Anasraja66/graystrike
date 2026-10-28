"""
Security RAG Knowledge Base Service
Curated defensive security patterns, remediation guidance, and vulnerability taxonomies
sourced from OWASP, PortSwigger, CWE, and NIST.
"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class KnowledgeChunk(BaseModel):
    category: str
    cwe_id: str
    owasp_mapping: str
    title: str
    summary: str
    impact: str
    remediation_guidance: str
    reference_url: str


class SecurityKnowledgeBase:
    """In-memory & Vector-ready defensive security knowledge base."""

    KNOWLEDGE_DOCS: List[KnowledgeChunk] = [
        KnowledgeChunk(
            category="sql_injection",
            cwe_id="CWE-89",
            owasp_mapping="A03:2021-Injection",
            title="SQL Injection Prevention Guidance",
            summary="SQL injection occurs when untrusted user input is directly concatenated into dynamic SQL query strings.",
            impact="Unauthorized database readout, data corruption, administrative authentication bypass, or remote code execution via database extensions.",
            remediation_guidance="Use parameterized queries / prepared statements exclusively (e.g. PDO in PHP, parameterized SQL in Python SQLAlchemy). Enforce least privilege database user permissions.",
            reference_url="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ),
        KnowledgeChunk(
            category="xss",
            cwe_id="CWE-79",
            owasp_mapping="A03:2021-Injection",
            title="Cross-Site Scripting (XSS) Defensive Standard",
            summary="XSS vulnerabilities occur when web applications include untrusted input in web pages without proper HTML encoding or sanitization.",
            impact="Session hijacking via stolen cookie tokens, credential harvesting via DOM phish, defacement, or arbitrary client actions executed under victim session.",
            remediation_guidance="Apply context-aware output encoding (HTML body, attributes, JavaScript variables). Deploy a strict Content-Security-Policy (CSP) with nonce-based script execution.",
            reference_url="https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        ),
        KnowledgeChunk(
            category="broken_access_control",
            cwe_id="CWE-639",
            owasp_mapping="A01:2021-Broken Access Control",
            title="Insecure Direct Object Reference (IDOR) & Object-Level Auth",
            summary="Occurs when an application exposes a reference to an internal implementation object (such as a database record integer) without validating user ownership.",
            impact="Horizontal and vertical privilege escalation, unauthorized record disclosure, and bulk data scraping.",
            remediation_guidance="Enforce authorization checks on every state read/write at the domain service layer. Use cryptographically random UUIDv4 identifiers instead of auto-incrementing integers.",
            reference_url="https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"
        ),
        KnowledgeChunk(
            category="security_headers",
            cwe_id="CWE-693",
            owasp_mapping="A05:2021-Security Misconfiguration",
            title="Defensive HTTP Response Headers Baseline",
            summary="HTTP response headers allow servers to restrict browser execution capabilities and establish cryptographic defense-in-depth.",
            impact="Susceptibility to Clickjacking, protocol downgrade attacks, MIME-type sniffing exploits, and cross-site scripting.",
            remediation_guidance="Configure Content-Security-Policy, Strict-Transport-Security (max-age=31536000), X-Content-Type-Options: nosniff, and X-Frame-Options: DENY across all response paths.",
            reference_url="https://owasp.org/www-project-secure-headers/"
        ),
        KnowledgeChunk(
            category="ssrf",
            cwe_id="CWE-918",
            owasp_mapping="A10:2021-Server-Side Request Forgery",
            title="Server-Side Request Forgery (SSRF) Defense Guidance",
            summary="SSRF flaws allow an attacker to induce the backend web application to make HTTP requests to an arbitrary domain chosen by the attacker.",
            impact="Extraction of cloud metadata tokens (e.g. AWS IMDSv1 at 169.254.169.254), internal port scanning, and remote server access to unauthenticated microservices.",
            remediation_guidance="Sanitize and validate all user-supplied destination URLs against a strict allowlist. Block loopback and RFC 1918 private subnets at both DNS resolution and firewall layers.",
            reference_url="https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
        ),
        KnowledgeChunk(
            category="cors",
            cwe_id="CWE-942",
            owasp_mapping="A05:2021-Security Misconfiguration",
            title="Cross-Origin Resource Sharing (CORS) Security Model",
            summary="CORS defines how a browser and server interact to determine whether it is safe to allow cross-origin requests.",
            impact="Allowing wildcard origins with credentials enables malicious third-party websites to read private user data via victim browser sessions.",
            remediation_guidance="Never combine 'Access-Control-Allow-Origin: *' with 'Access-Control-Allow-Credentials: true'. Dynamically validate Origin headers against a strict whitelist of trusted partner domains.",
            reference_url="https://portswigger.net/web-security/cors"
        )
    ]

    @classmethod
    def get_guidance(cls, category: str) -> Optional[KnowledgeChunk]:
        """Fetch defensive knowledge chunk for a specific vulnerability category."""
        category_lower = category.lower()
        for doc in cls.KNOWLEDGE_DOCS:
            if doc.category == category_lower:
                return doc
        return None

    @classmethod
    def search_guidance(cls, query: str) -> List[KnowledgeChunk]:
        """Simple lexical match across knowledge chunks."""
        query_lower = query.lower()
        results = []
        for doc in cls.KNOWLEDGE_DOCS:
            if (
                query_lower in doc.title.lower()
                or query_lower in doc.summary.lower()
                or query_lower in doc.category.lower()
            ):
                results.append(doc)
        return results
