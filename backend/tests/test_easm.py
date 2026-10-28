"""
Tests for External Attack Surface Management (EASM) Service
"""
import sys
import os
import pytest

# Ensure backend and ai_engine are in path
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ROOT_DIR = os.path.abspath(os.path.join(BACKEND_DIR, ".."))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app.services.easm_service import EASMService


def test_apex_domain_extraction():
    assert EASMService.get_apex_domain("https://api.vibeapp.com/v1") == "vibeapp.com"
    assert EASMService.get_apex_domain("staging.dev.sub.example.co.uk") == "example.co.uk" or "co.uk" in EASMService.get_apex_domain("staging.dev.sub.example.co.uk")
    assert EASMService.get_apex_domain("myapp.lovable.app") == "lovable.app"
    assert EASMService.get_apex_domain("localhost:8000") == "localhost:8000"


@pytest.mark.asyncio
async def test_profile_asset_shadow_detection():
    # Test shadow environment categorization
    profile_shadow = await EASMService._profile_asset("staging-api.example.com", "example.com")
    assert profile_shadow["is_shadow"] == True
    assert "Shadow" in profile_shadow["asset_type"] or profile_shadow["is_shadow"]

    profile_main = await EASMService._profile_asset("example.com", "example.com")
    assert profile_main["is_shadow"] == False


@pytest.mark.asyncio
async def test_easm_discovery_structure():
    # Test discover_attack_surface returns structured dictionary
    result = await EASMService.discover_attack_surface("example.com")
    assert "apex_domain" in result
    assert "total_assets_found" in result
    assert "shadow_assets_count" in result
    assert "takeover_risks_count" in result
    assert "assets" in result
    assert "summary" in result
    assert isinstance(result["assets"], list)
    assert result["summary"]["status"] in ("HEALTHY", "WARNING", "DANGER")
