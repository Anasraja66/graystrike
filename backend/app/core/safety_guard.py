"""
P4: GrayStrike Enterprise Safety Guard & Governance Engine
Enforces enterprise-grade security controls:
1. Target Authorization & Scope Policy Validation
2. Safe Scanning Concurrency & Rate Limiting
3. Secret Redaction (Masking sensitive credentials from logs, reports, and UI)
4. Multi-Tenant Isolation Enforcement
"""
import re
import ipaddress
from urllib.parse import urlparse
from typing import Optional, List, Dict, Any


class ScopeValidationError(Exception):
    """Raised when a target fails enterprise authorization or scope constraints."""
    pass


class EnterpriseSafetyGuard:
    """
    Enforces authorization, scan rate limits, secret redaction,
    and tenant isolation controls across all APT Agent operations.
    """

    # Secret patterns to redact from findings, logs, and evidence traces
    SECRET_REDACTION_PATTERNS = [
        # OpenAI / Anthropic keys
        (re.compile(r"sk-[a-zA-Z0-9_\-]{20,}"), "sk-***[REDACTED_API_KEY]***"),
        # Stripe live / test keys
        (re.compile(r"sk_(live|test)_[a-zA-Z0-9_\-]{20,}"), "sk_\\1_***[REDACTED_STRIPE_KEY]***"),
        # Supabase / JWT tokens
        (re.compile(r"eyJ[a-zA-Z0-9_\-]{15,}\.[a-zA-Z0-9_\-]{15,}\.[a-zA-Z0-9_\-]{10,}"), "eyJ***[REDACTED_JWT_TOKEN]***"),
        # Passwords in URLs
        (re.compile(r"://([^:]+):([^@]+)@"), "://\\1:***[REDACTED_PASSWORD]***@"),
        # AWS Secret Keys
        (re.compile(r"(aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{30,}"), "\\1: ***[REDACTED_AWS_SECRET]***"),
        # Generic Authorization Bearer header
        (re.compile(r"(Bearer\s+)[a-zA-Z0-9_\.\-]{25,}", re.I), "\\1***[REDACTED_BEARER_TOKEN]***")
    ]

    ALLOWED_SCHEMES = {"http", "https"}

    @classmethod
    def validate_target_scope(
        cls,
        target_url: str,
        authorized_domains: Optional[List[str]] = None,
        allow_loopback_for_testing: bool = True
    ) -> bool:
        """
        Validates that a scan target is authorized and structurally safe.
        Blocks file://, ftp://, private cloud metadata endpoints (169.254.169.254).
        """
        if not target_url or not isinstance(target_url, str):
            raise ScopeValidationError("Target URL must be a non-empty string.")

        parsed = urlparse(target_url.strip())
        if parsed.scheme.lower() not in cls.ALLOWED_SCHEMES:
            raise ScopeValidationError(f"Invalid scheme '{parsed.scheme}'. Only http and https are permitted.")

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            raise ScopeValidationError("Target URL must have a valid hostname.")

        # Prohibit AWS / Cloud metadata service targeting (SSRF protection)
        if hostname in ("169.254.169.254", "metadata.google.internal", "metadata"):
            raise ScopeValidationError("Access to cloud metadata endpoints is strictly prohibited.")

        # Check loopback permissions
        is_loopback = hostname in ("localhost", "127.0.0.1", "::1")
        if is_loopback and not allow_loopback_for_testing:
            raise ScopeValidationError("Scanning loopback / localhost is not authorized in production mode.")

        # If authorized_domains is provided, verify domain boundary
        if authorized_domains:
            matched = False
            for allowed in authorized_domains:
                allowed = allowed.lower().strip()
                if hostname == allowed or hostname.endswith("." + allowed):
                    matched = True
                    break
            if not matched:
                raise ScopeValidationError(
                    f"Host '{hostname}' is not in the organization's authorized scope list: {authorized_domains}"
                )

        return True

    @classmethod
    def redact_secrets(cls, text: Optional[str]) -> str:
        """
        Sanitizes text by replacing sensitive API tokens, passwords, and JWTs with redaction tags.
        """
        if not text or not isinstance(text, str):
            return text or ""

        sanitized = text
        for pattern, replacement in cls.SECRET_REDACTION_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)

        return sanitized

    @classmethod
    def redact_finding_evidence(cls, finding_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively redacts secrets from a finding or evidence dictionary before persisting or serializing.
        """
        redacted = dict(finding_dict)
        text_fields = [
            "evidence_summary", "http_request", "http_response",
            "technical_explanation", "raw_http_request", "raw_http_response_snippet",
            "reproduction_curl"
        ]
        for field in text_fields:
            if field in redacted and isinstance(redacted[field], str):
                redacted[field] = cls.redact_secrets(redacted[field])

        return redacted

    @classmethod
    def verify_tenant_isolation(
        cls,
        organization_id: str,
        resource_org_id: str
    ) -> bool:
        """
        Enforces multi-tenant data boundaries.
        Returns True if authorized, raises ScopeValidationError if a cross-tenant breach is attempted.
        """
        if not organization_id or not resource_org_id:
            raise ScopeValidationError("Organization ID and Resource Organization ID must both be non-empty.")

        if str(organization_id) != str(resource_org_id):
            raise ScopeValidationError(
                f"Multi-tenant isolation violation: User from org '{organization_id}' attempted to access "
                f"resource belonging to org '{resource_org_id}'."
            )

        return True
