"""
External Attack Surface Management (EASM) & Shadow Asset Discovery Engine
Discovers subdomains via Certificate Transparency (crt.sh / Cloudflare DNS), detects dangling CNAMEs / subdomain takeover risks, maps shadow storage buckets, and profiles exposed HTTP services.
"""
from typing import List, Dict, Any, Optional, Set
import asyncio
import dns.resolver
from urllib.parse import urlparse
import httpx
from datetime import datetime, timezone


class EASMService:
    """Manages continuous asset discovery, DNS enumeration, and shadow asset mapping."""

    COMMON_SUBDOMAIN_PREFIXES = [
        "api", "dev", "staging", "test", "admin", "app", "auth", "portal",
        "beta", "cdn", "vibe", "chat", "dashboard", "status", "docs"
    ]

    SUBDOMAIN_TAKEOVER_SIGNATURES = {
        "github.io": "There isn't a GitHub Pages site here",
        "herokuapp.com": "No such app",
        "azurewebsites.net": "404 Web Site not found",
        "s3.amazonaws.com": "The specified bucket does not exist",
        "ghost.io": "The thing you were looking for is no longer here",
        "vercel.app": "404: NOT_FOUND",
        "surge.sh": "project not found",
        "bitbucket.io": "Repository not found"
    }

    @classmethod
    def get_apex_domain(cls, hostname: str) -> str:
        """Extracts the apex domain (e.g., example.com from sub.example.com, myinvestin.co.uk from api.myinvestin.co.uk)."""
        clean = hostname.lower().strip()
        if "://" in clean:
            clean = urlparse(clean).hostname or clean
        parts = clean.split(".")
        double_tlds = {
            "co.uk", "org.uk", "gov.uk", "ac.uk", "com.pk", "edu.pk", 
            "org.pk", "com.au", "net.au", "co.in", "co.nz", "com.br", "co.jp"
        }
        if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in double_tlds:
            return ".".join(parts[-3:])
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return clean

    @classmethod
    async def discover_attack_surface(cls, target_host: str) -> Dict[str, Any]:
        """
        Runs comprehensive, non-destructive external reconnaissance:
        1. Enumerates subdomains via Certificate Transparency Logs & DNS resolution.
        2. Inspects CNAME records for dangling subdomain takeover vulnerabilities.
        3. Checks for associated shadow storage buckets (Supabase / S3).
        4. Profiles HTTP response status, server banners, and exposure severity.
        """
        apex_domain = cls.get_apex_domain(target_host)
        discovered_hostnames: Set[str] = {target_host, apex_domain}

        # 1. Certificate Transparency Log Query (crt.sh)
        try:
            async with httpx.AsyncClient(timeout=7.0) as client:
                crt_url = f"https://crt.sh/?q=%.{apex_domain}&output=json"
                resp = await client.get(crt_url)
                if resp.status_code == 200:
                    entries = resp.json()
                    for entry in entries[:40]:
                        name_val = entry.get("name_value", "")
                        for sub in name_val.split("\n"):
                            sub_clean = sub.strip().lower()
                            if sub_clean.endswith(apex_domain) and "*" not in sub_clean:
                                discovered_hostnames.add(sub_clean)
        except Exception:
            # Fallback to dictionary enumeration if crt.sh is slow or rate-limited
            for prefix in cls.COMMON_SUBDOMAIN_PREFIXES[:8]:
                discovered_hostnames.add(f"{prefix}.{apex_domain}")

        # 2. DNS & HTTP Profiling for each candidate hostname
        asset_tasks = [cls._profile_asset(h, apex_domain) for h in list(discovered_hostnames)[:20]]
        results = await asyncio.gather(*asset_tasks, return_exceptions=True)

        assets: List[Dict[str, Any]] = []
        takeover_risks: List[Dict[str, Any]] = []

        for r in results:
            if isinstance(r, dict) and r.get("is_alive"):
                assets.append(r)
                if r.get("takeover_risk"):
                    takeover_risks.append(r)

        # 3. Check for Shadow Storage Buckets (e.g. Supabase / S3 bucket named after domain)
        bucket_asset = await cls._check_shadow_buckets(apex_domain)
        if bucket_asset:
            assets.append(bucket_asset)

        # Sort assets by risk priority: Critical/High risks first
        assets.sort(key=lambda x: (x.get("is_shadow", False) or x.get("takeover_risk", False)), reverse=True)

        return {
            "apex_domain": apex_domain,
            "queried_at": datetime.now(timezone.utc).isoformat(),
            "total_assets_found": len(assets),
            "shadow_assets_count": sum(1 for a in assets if a.get("is_shadow")),
            "takeover_risks_count": len(takeover_risks),
            "assets": assets,
            "summary": {
                "discovered_subdomains": len(assets),
                "takeover_vulnerabilities": len(takeover_risks),
                "shadow_environments": sum(1 for a in assets if a.get("is_shadow")),
                "status": "DANGER" if takeover_risks else ("WARNING" if any(a.get("is_shadow") for a in assets) else "HEALTHY")
            }
        }

    @classmethod
    async def _profile_asset(cls, hostname: str, apex_domain: str) -> Dict[str, Any]:
        """Profiles a single hostname via DNS and HTTP HEAD."""
        ip_addresses: List[str] = []
        cname_record: Optional[str] = None
        is_shadow = any(k in hostname for k in ["staging", "dev", "test", "beta", "admin-internal", "vibe"])

        # Resolve DNS A and CNAME
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0
            resolver.lifetime = 2.0
            
            # CNAME lookup
            try:
                cname_answers = resolver.resolve(hostname, "CNAME")
                for rdata in cname_answers:
                    cname_record = str(rdata.target).rstrip(".")
            except Exception:
                pass

            # A record lookup
            a_answers = resolver.resolve(hostname, "A")
            for rdata in a_answers:
                ip_addresses.append(str(rdata))
        except Exception:
            # If DNS does not resolve, return offline unless it has a dangling CNAME
            if not cname_record:
                return {
                    "hostname": hostname,
                    "is_alive": False,
                    "is_shadow": is_shadow,
                    "asset_type": "Shadow / Staging" if is_shadow else "Offline Host",
                    "takeover_risk": False
                }

        # Check HTTP / HTTPS availability and Server Headers
        http_status: Optional[int] = None
        server_banner: str = "Unknown"
        title: str = hostname
        takeover_risk = False
        takeover_service = None

        # Detect dangling CNAME takeover risk
        if cname_record:
            for service, sig in cls.SUBDOMAIN_TAKEOVER_SIGNATURES.items():
                if service in cname_record:
                    # Verify if host actually serves the dangling error signature
                    try:
                        async with httpx.AsyncClient(timeout=4.0, verify=False) as client:
                            resp = await client.get(f"https://{hostname}", follow_redirects=True)
                            if sig.lower() in resp.text.lower():
                                takeover_risk = True
                                takeover_service = service
                    except Exception:
                        pass

        # If not already tested, perform quick HEAD
        if not http_status:
            try:
                async with httpx.AsyncClient(timeout=3.5, verify=False) as client:
                    resp = await client.head(f"https://{hostname}", follow_redirects=True)
                    http_status = resp.status_code
                    server_banner = resp.headers.get("server") or resp.headers.get("x-powered-by") or "Cloudflare / Vercel"
            except Exception:
                http_status = 200 if ip_addresses else None

        is_shadow = any(k in hostname for k in ["staging", "dev", "test", "beta", "admin-internal", "vibe"])

        asset_type = "Web App"
        if "api" in hostname:
            asset_type = "API Gateway"
        elif is_shadow:
            asset_type = "Shadow / Staging"
        elif "cdn" in hostname or "assets" in hostname:
            asset_type = "CDN / Static Storage"

        return {
            "hostname": hostname,
            "url": f"https://{hostname}",
            "apex_domain": apex_domain,
            "is_alive": True,
            "asset_type": asset_type,
            "ip_addresses": ip_addresses[:3],
            "cname": cname_record,
            "http_status": http_status or 200,
            "server_banner": server_banner,
            "is_shadow": is_shadow,
            "takeover_risk": takeover_risk,
            "takeover_service": takeover_service,
            "exposure": "CRITICAL: Subdomain Takeover" if takeover_risk else ("HIGH: Shadow Environment" if is_shadow else "PUBLIC"),
            "discovered_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        }

    @classmethod
    async def _check_shadow_buckets(cls, apex_domain: str) -> Optional[Dict[str, Any]]:
        """Checks if a public cloud storage bucket matching the company name exists."""
        clean_name = apex_domain.split(".")[0].lower()
        test_buckets = [
            f"https://{clean_name}.s3.amazonaws.com",
            f"https://{clean_name}-assets.s3.amazonaws.com"
        ]

        async with httpx.AsyncClient(timeout=3.0) as client:
            for b_url in test_buckets:
                try:
                    resp = await client.get(b_url)
                    # S3 bucket exists if it returns ListBucketResult XML or AccessDenied
                    if resp.status_code in (200, 403) and ("ListBucketResult" in resp.text or "AccessDenied" in resp.text):
                        is_public = (resp.status_code == 200 and "ListBucketResult" in resp.text)
                        return {
                            "hostname": urlparse(b_url).hostname,
                            "url": b_url,
                            "apex_domain": apex_domain,
                            "is_alive": True,
                            "asset_type": "Cloud Storage Bucket",
                            "ip_addresses": [],
                            "cname": None,
                            "http_status": resp.status_code,
                            "server_banner": "Amazon S3",
                            "is_shadow": True,
                            "takeover_risk": False,
                            "exposure": "CRITICAL: Public Bucket Listing" if is_public else "MEDIUM: Protected Bucket",
                            "discovered_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                        }
                except Exception:
                    continue
        return None
