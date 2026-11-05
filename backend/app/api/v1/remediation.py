"""
Remediation API - Autonomous Multi-Artifact Security Packaging
"""
from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import socket
import ssl
import urllib.request
from datetime import datetime, timezone

from app.services.remediation_pack_service import RemediationPackService

router = APIRouter()


class RemediationPackRequest(BaseModel):
    target_domain: str = Field(..., description="Target domain, e.g. elixlumi.com")
    org_name: Optional[str] = Field("Security Audit Client", description="Organization name")
    tech_stack: Optional[str] = Field("node", description="node, express, python, fastapi, etc.")
    findings: List[Dict[str, Any]] = Field(default_factory=list, description="List of findings with id, title, severity, cwe, description")


class QuickScanPackRequest(BaseModel):
    target_domain: str = Field(..., description="Target domain to inspect, e.g. elixlumi.com")
    org_name: Optional[str] = "Automated Client"


@router.post("/pack")
async def generate_pack_manifest(request: RemediationPackRequest):
    """Generate the full remediation bundle manifest (Patch, WAF rule, PR Payload)."""
    scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    git_patch = RemediationPackService.generate_git_patch(request.target_domain, request.tech_stack)
    waf_config = RemediationPackService.generate_virtual_waf_config(request.target_domain)
    pr_payload = RemediationPackService.generate_pr_payload(request.target_domain, request.findings, scan_date)

    return {
        "status": "success",
        "target_domain": request.target_domain,
        "scan_date": scan_date,
        "total_findings": len(request.findings),
        "artifacts": {
            "git_patch": git_patch,
            "virtual_waf_rule": waf_config,
            "github_pr_payload": pr_payload
        },
        "zip_download_url": f"/api/v1/remediation/pack/{request.target_domain}/zip"
    }


@router.post("/pack/zip")
async def download_pack_zip(request: RemediationPackRequest):
    """Generate and directly stream the complete remediation ZIP bundle."""
    try:
        zip_buffer = RemediationPackService.build_remediation_bundle(
            target_domain=request.target_domain,
            org_name=request.org_name or "Security Audit Client",
            findings=request.findings,
            tech_stack=request.tech_stack or "node"
        )
        filename = f"{request.target_domain}_remediation_bundle.zip"
        return Response(
            content=zip_buffer.getvalue(),
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate remediation ZIP bundle: {str(e)}")


@router.post("/quick-scan-pack")
async def quick_scan_and_pack(request: QuickScanPackRequest):
    """Performs passive non-intrusive probe on target domain and returns complete Remediation Bundle."""
    domain = request.target_domain.replace("https://", "").replace("http://", "").split("/")[0].strip()
    findings = []

    # 1. Probe HTTP Headers
    headers = {}
    server_tech = "node"
    try:
        req = urllib.request.Request(
            f"https://{domain}",
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) GrayStrike-Probe/1.0"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            headers = {k.lower(): v for k, v in resp.getheaders()}
    except Exception:
        # Fallback to plain HTTP if HTTPS fails
        try:
            req = urllib.request.Request(
                f"http://{domain}",
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) GrayStrike-Probe/1.0"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                headers = {k.lower(): v for k, v in resp.getheaders()}
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Could not connect to target {domain}: {str(e)}")

    # 2. Analyze Findings from Response Headers
    # CORS
    if headers.get("access-control-allow-origin") == "*":
        findings.append({
            "id": "SEC-001",
            "severity": "HIGH",
            "cwe": "CWE-942: Permissive CORS Policy",
            "title": "Overly Permissive Cross-Origin Resource Sharing (CORS Wildcard)",
            "description": "Server responds with Access-Control-Allow-Origin: * permitting any external website to issue cross-origin requests.",
            "evidence": "access-control-allow-origin: *"
        })

    # Clickjacking (X-Frame-Options)
    if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
        findings.append({
            "id": "SEC-002",
            "severity": "MEDIUM",
            "cwe": "CWE-1021: Missing Clickjacking Defense",
            "title": "Missing Clickjacking Defense (X-Frame-Options)",
            "description": "Neither X-Frame-Options nor CSP frame-ancestors is configured, allowing framing within hidden iframes.",
            "evidence": "Header missing: X-Frame-Options"
        })

    # HSTS
    if "strict-transport-security" not in headers:
        findings.append({
            "id": "SEC-003",
            "severity": "MEDIUM",
            "cwe": "CWE-319: Cleartext Transmission",
            "title": "Missing HTTP Strict Transport Security (HSTS)",
            "description": "Strict-Transport-Security header is missing, enabling SSL stripping attack vectors.",
            "evidence": "Header missing: Strict-Transport-Security"
        })

    # CSP
    csp = headers.get("content-security-policy", "")
    if not csp or "script-src" not in csp:
        findings.append({
            "id": "SEC-004",
            "severity": "MEDIUM",
            "cwe": "CWE-79: Weak Content Security Policy",
            "title": "Inadequate Content Security Policy (Missing script-src)",
            "description": "CSP does not restrict script origins or lacks script-src directives.",
            "evidence": f"CSP value: {csp if csp else 'Not set'}"
        })

    # Fingerprinting
    if "x-powered-by" in headers or "server" in headers:
        server_val = headers.get("x-powered-by", headers.get("server", ""))
        if "express" in server_val.lower():
            server_tech = "node"
        findings.append({
            "id": "SEC-005",
            "severity": "LOW",
            "cwe": "CWE-200: Information Exposure",
            "title": "Server and Runtime Technology Fingerprinting Exposed",
            "description": f"Exposed runtime identification header: {server_val}",
            "evidence": f"Headers: x-powered-by={headers.get('x-powered-by')}, server={headers.get('server')}"
        })

    # Generate complete bundle
    scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    git_patch = RemediationPackService.generate_git_patch(domain, server_tech)
    waf_config = RemediationPackService.generate_virtual_waf_config(domain)
    pr_payload = RemediationPackService.generate_pr_payload(domain, findings, scan_date)

    return {
        "status": "success",
        "target_domain": domain,
        "scan_date": scan_date,
        "detected_tech": server_tech,
        "total_findings": len(findings),
        "findings": findings,
        "remediation_pack": {
            "git_patch": git_patch,
            "virtual_waf_rule": waf_config,
            "github_pr_payload": pr_payload
        }
    }
