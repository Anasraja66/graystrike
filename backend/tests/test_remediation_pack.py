"""
Tests for RemediationPackService and Remediation API
"""
import pytest
import zipfile
from io import BytesIO
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.services.remediation_pack_service import RemediationPackService


@pytest.fixture
def sample_findings():
    return [
        {
            "id": "SEC-001",
            "title": "Permissive CORS Policy",
            "severity": "HIGH",
            "cwe": "CWE-942: Permissive CORS",
            "description": "Wildcard origin allowed",
            "evidence": "access-control-allow-origin: *"
        },
        {
            "id": "SEC-002",
            "title": "Missing HSTS",
            "severity": "MEDIUM",
            "cwe": "CWE-319: Cleartext Transmission",
            "description": "No HSTS header present",
            "evidence": "Missing Strict-Transport-Security"
        }
    ]


def test_remediation_pack_service_git_patch():
    patch_node = RemediationPackService.generate_git_patch("example.com", "node")
    assert "--- a/server.js" in patch_node
    assert "helmet" in patch_node
    assert "example.com" in patch_node

    patch_py = RemediationPackService.generate_git_patch("example.com", "python")
    assert "--- a/main.py" in patch_py
    assert "Strict-Transport-Security" in patch_py


def test_remediation_pack_service_virtual_waf():
    waf = RemediationPackService.generate_virtual_waf_config("example.com")
    assert "Strict-Transport-Security" in waf
    assert "X-Frame-Options" in waf
    assert "example.com" in waf


def test_remediation_pack_service_pr_payload(sample_findings):
    payload = RemediationPackService.generate_pr_payload("example.com", sample_findings, "2026-11-05")
    assert "title" in payload
    assert "branch" in payload
    assert "SEC-001" in payload["body"]
    assert "CWE-942" in payload["body"]


def test_remediation_pack_service_bundle_zip(sample_findings):
    zip_buf = RemediationPackService.build_remediation_bundle(
        target_domain="example.com",
        org_name="Example Org",
        findings=sample_findings,
        tech_stack="node"
    )
    assert isinstance(zip_buf, BytesIO)
    
    # Read back zip contents
    with zipfile.ZipFile(zip_buf, "r") as zf:
        file_list = zf.namelist()
        assert "example.com_audit_report.pdf" in file_list
        assert "security_fix.patch" in file_list
        assert "virtual_patch_headers.conf" in file_list
        assert "github_pr_payload.json" in file_list


@pytest.mark.asyncio
async def test_remediation_api_pack_manifest(sample_findings):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/v1/remediation/pack", json={
            "target_domain": "example.com",
            "org_name": "Test Org",
            "tech_stack": "node",
            "findings": sample_findings
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["total_findings"] == 2
        assert "git_patch" in data["artifacts"]
        assert "virtual_waf_rule" in data["artifacts"]


@pytest.mark.asyncio
async def test_remediation_api_pack_zip_download(sample_findings):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/v1/remediation/pack/zip", json={
            "target_domain": "example.com",
            "org_name": "Test Org",
            "findings": sample_findings
        })
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/zip"
        assert len(resp.content) > 1000
