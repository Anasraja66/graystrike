"""
Unit Test for GrayStrike Local & HuggingFace Model Inference Service
"""
import pytest
from backend.app.services.local_model_service import LocalModelService


def test_local_model_service_initialization():
    service = LocalModelService()
    assert service.hf_token is not None
    assert "hf_" in service.hf_token


def test_local_model_hypothesis_generation():
    service = LocalModelService()
    res = service.synthesize_remediation_hypothesis(
        vulnerable_code="app.use(cors({ origin: '*' }));",
        buggy_statement="origin: '*'",
        cwe_id="CWE-942",
        fault_type="PERMISSIVE_CORS_WILDCARD"
    )
    assert res is not None
    assert "source" in res
    assert "model" in res
    assert "air_gapped" in res
