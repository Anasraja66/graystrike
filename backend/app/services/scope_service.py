"""
Central Scope Enforcement Service
Protects targets and environment against:
- Unauthorized hosts/domains
- Disallowed paths
- Disallowed HTTP methods
- Localhost, link-local, private IPs (SSRF & Metadata protection)
- DNS rebinding
- Infinite redirect loops
"""
import ipaddress
import socket
from urllib.parse import urlparse
from typing import List, Optional, Tuple


class ScopeViolationError(Exception):
    """Raised when a request violates configured scope or safety policies."""
    pass


class ScopeEnforcer:
    # Blacklisted private & metadata ranges (IPv4 & IPv6)
    BLOCKED_NETWORKS = [
        ipaddress.ip_network("127.0.0.0/8"),      # Loopback
        ipaddress.ip_network("10.0.0.0/8"),       # Private class A
        ipaddress.ip_network("172.16.0.0/12"),    # Private class B
        ipaddress.ip_network("192.168.0.0/16"),   # Private class C
        ipaddress.ip_network("169.254.0.0/16"),   # Link-local / AWS & Cloud Metadata
        ipaddress.ip_network("0.0.0.0/8"),        # Current network
        ipaddress.ip_network("::1/128"),          # IPv6 loopback
        ipaddress.ip_network("fc00::/7"),         # IPv6 unique local
        ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
    ]

    def __init__(
        self,
        allowed_hosts: List[str],
        denied_paths: Optional[List[str]] = None,
        allowed_methods: Optional[List[str]] = None,
        max_requests: int = 1000,
        rate_limit_rps: float = 2.0,
        allow_private_ips: bool = False  # Only True in explicitly isolated local testing labs
    ):
        self.allowed_hosts = [h.lower().strip() for h in allowed_hosts]
        self.denied_paths = [p.lower().strip() for p in (denied_paths or [])]
        self.allowed_methods = [m.upper().strip() for m in (allowed_methods or ["GET", "HEAD", "OPTIONS"])]
        self.max_requests = max_requests
        self.rate_limit_rps = rate_limit_rps
        self.allow_private_ips = allow_private_ips
        self.request_count = 0

    def validate_url(self, url: str) -> Tuple[bool, Optional[str]]:
        """
        Validate URL against host scope, path deny-list, and IP restrictions.
        Returns: (is_valid, error_reason)
        """
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return False, f"Unsupported URL scheme: {parsed.scheme}"

            hostname = parsed.hostname
            if not hostname:
                return False, "Invalid URL: missing hostname"

            hostname = hostname.lower()

            # 1. Host allowlist check (exact match or subdomain match)
            host_matched = False
            for allowed in self.allowed_hosts:
                if hostname == allowed or hostname.endswith("." + allowed):
                    host_matched = True
                    break

            if not host_matched:
                return False, f"Host '{hostname}' is out of authorized scope ({self.allowed_hosts})"

            # 2. Path deny-list check
            path = parsed.path.lower() or "/"
            for denied in self.denied_paths:
                if path.startswith(denied):
                    return False, f"Path '{path}' is explicitly denied by scope policy"

            # 3. IP and DNS Rebinding check
            if not self.allow_private_ips:
                try:
                    ip_addresses = socket.gethostbyname_ex(hostname)[2]
                    for ip_str in ip_addresses:
                        ip_obj = ipaddress.ip_address(ip_str)
                        for blocked_net in self.BLOCKED_NETWORKS:
                            if ip_obj in blocked_net:
                                return False, f"Security Violation: Host '{hostname}' resolves to blocked IP '{ip_str}'"
                except Exception as dns_err:
                    return False, f"DNS resolution failed for '{hostname}': {str(dns_err)}"

            return True, None

        except Exception as e:
            return False, f"URL validation error: {str(e)}"

    def check_method(self, method: str) -> Tuple[bool, Optional[str]]:
        """Validate HTTP method against policy."""
        method_upper = method.upper()
        if method_upper not in self.allowed_methods:
            return False, f"HTTP method '{method}' is not allowed in safe testing mode"
        return True, None

    def validate_redirect(self, current_url: str, redirect_location: str) -> Tuple[bool, str, Optional[str]]:
        """
        Safely validates a redirect location URL against scope before following it.
        Resolves relative paths against current_url and validates target host.
        Returns: (is_allowed, resolved_url, error_reason)
        """
        from urllib.parse import urljoin
        resolved_url = urljoin(current_url, redirect_location)
        is_valid, error = self.validate_url(resolved_url)
        return is_valid, resolved_url, error

    def record_request(self):
        """Track request count and enforce maximum quota."""
        self.request_count += 1
        if self.request_count > self.max_requests:
            raise ScopeViolationError(f"Maximum request budget exceeded ({self.max_requests} requests)")
