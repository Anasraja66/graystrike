"""
Unit Tests for GrayStrike Neuro-Symbolic CEGIS Repair & Knowledge Graph Engine
Tests:
- Code Property Graph (CPG) Construction via NetworkX
- Taint-Aware Backward Slicing & Noise Pruning
- Symbolic Unification (Ghost Function Hallucination Blocker)
- MaxSAT Fault Localization & Program Sketch Generation
- Counterexample-Guided Inductive Synthesis (CEGIS) with Z3 SMT Verification
"""
import pytest
from backend.app.services.knowledge_graph_engine import CodePropertyGraphEngine
from backend.app.services.cegis_repair_engine import CEGISRepairEngine


SAMPLE_VULNERABLE_EXPRESS_APP = """
const express = require('express');
const cors = require('cors');
const app = express();

const trustedDB = 'production_db';
const appSecret = 'super_secret_jwt';

// Vulnerability 1: Permissive CORS Wildcard (CWE-942)
app.use(cors({ origin: '*' }));

app.get('/api/data', (req, res) => {
    const userInput = req.query.q;
    res.json({ status: 'ok', query: userInput });
});

app.listen(3000);
"""


def test_cpg_construction():
    """Verify CPG builds AST, CFG, and DATA_FLOW layers in-memory."""
    engine = CodePropertyGraphEngine()
    g = engine.build_cpg_from_code(SAMPLE_VULNERABLE_EXPRESS_APP)

    assert len(g.nodes) > 5
    assert len(g.edges) > 5

    # Check for security policy sink node
    policy_nodes = [n for n, d in g.nodes(data=True) if d.get("node_type") == "SECURITY_POLICY_NODE"]
    assert len(policy_nodes) >= 1


def test_taint_slicing_pruning():
    """Verify backward slicing prunes irrelevant statements while retaining taint path."""
    engine = CodePropertyGraphEngine()
    engine.build_cpg_from_code(SAMPLE_VULNERABLE_EXPRESS_APP)

    slice_result = engine.extract_taint_slice()
    assert "pruning_ratio" in slice_result
    assert slice_result["pruning_ratio"] > 0.0
    assert "cors" in slice_result["sliced_code"]


def test_symbolic_unification_clean():
    """Verify clean patch with declared and standard symbols passes unification."""
    engine = CodePropertyGraphEngine()
    engine.build_cpg_from_code(SAMPLE_VULNERABLE_EXPRESS_APP)

    valid_patch = "origin: process.env.ALLOWED_ORIGIN || 'https://elixlumi.com', credentials: true"
    is_valid, ghost_ids = engine.verify_symbolic_unification(valid_patch)
    assert is_valid is True
    assert len(ghost_ids) == 0


def test_symbolic_unification_catches_ghost():
    """Verify fabricated/hallucinated identifiers are caught and rejected."""
    engine = CodePropertyGraphEngine()
    engine.build_cpg_from_code(SAMPLE_VULNERABLE_EXPRESS_APP)

    hallucinated_patch = "const res = magicPhantomFunction(inventedVar999);"
    is_valid, ghost_ids = engine.verify_symbolic_unification(hallucinated_patch)
    assert is_valid is False
    assert "magicPhantomFunction" in ghost_ids
    assert "inventedVar999" in ghost_ids


def test_cegis_repair_end_to_end():
    """Verify complete CEGIS repair loop (Fault Localization -> Sketching -> SMT Verification -> Diff)."""
    cegis = CEGISRepairEngine()
    result = cegis.run_cegis_repair(SAMPLE_VULNERABLE_EXPRESS_APP)

    assert result["status"] == "repaired"
    assert result["faults_detected"] >= 1
    assert len(result["fixes_applied"]) >= 1

    # Ensure CORS wildcard was repaired
    cors_fix = next((f for f in result["fixes_applied"] if f["fault"] == "PERMISSIVE_CORS_WILDCARD"), None)
    assert cors_fix is not None
    assert "UNSAT" in cors_fix["smt_status"]

    # Ensure minimal unified diff was generated
    assert result["unified_diff"] is not None
    assert "--- a/server.js" in result["unified_diff"]
    assert "+++ b/server.js" in result["unified_diff"]


def test_cegis_repair_api_endpoint():
    """Verify CEGIS Repair API endpoint returns verified SMT patch and diff."""
    from fastapi.testclient import TestClient
    from backend.app.main import app

    client = TestClient(app)
    payload = {
        "source_code": SAMPLE_VULNERABLE_EXPRESS_APP,
        "file_path": "server.js"
    }

    response = client.post("/api/v1/remediation/cegis-repair", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "repaired"
    assert data["faults_detected"] >= 1
    assert len(data["fixes_applied"]) >= 1
    assert "UNSAT" in data["fixes_applied"][0]["smt_status"]
    assert data["unified_diff"] is not None
    assert "--- a/server.js" in data["unified_diff"]


def test_cegis_repair_multi_vulnerability_expansion():
    """
    Verify CEGIS Engine repairs and mathematically verifies (Z3 UNSAT):
    - CWE-89 (SQL Injection)
    - CWE-78 (Command Injection)
    - CWE-22 (Path Traversal)
    - CWE-79 (Reflected XSS)
    - CWE-190 (Integer Overflow)
    """
    code_with_complex_vulns = """
const express = require('express');
const app = express();

// CWE-89: SQL Injection
const query = "SELECT * FROM users WHERE id = " + req.query.id;

// CWE-78: Command Injection
const output = exec("ping -c 4 " + req.query.host);

// CWE-22: Path Traversal
const data = readFile("/var/www/uploads/" + req.query.file);

// CWE-79: Reflected XSS
res.send("<h1>Welcome " + req.query.name + "</h1>");

// CWE-190: Integer Overflow
const totalAlloc = buffer_size + req.query.size;
"""
    cegis = CEGISRepairEngine()
    result = cegis.run_cegis_repair(code_with_complex_vulns)

    assert result["status"] == "repaired"
    assert result["faults_detected"] >= 5
    assert len(result["fixes_applied"]) >= 5

    # Check CWE-89
    sqli_fix = next((f for f in result["fixes_applied"] if f["fault"] == "SQL_INJECTION_SINK"), None)
    assert sqli_fix is not None
    assert sqli_fix["cwe"] == "CWE-89"
    assert "UNSAT" in sqli_fix["smt_status"]

    # Check CWE-78
    cmdi_fix = next((f for f in result["fixes_applied"] if f["fault"] == "COMMAND_INJECTION_SINK"), None)
    assert cmdi_fix is not None
    assert cmdi_fix["cwe"] == "CWE-78"
    assert "UNSAT" in cmdi_fix["smt_status"]

    # Check CWE-22
    trav_fix = next((f for f in result["fixes_applied"] if f["fault"] == "PATH_TRAVERSAL_SINK"), None)
    assert trav_fix is not None
    assert trav_fix["cwe"] == "CWE-22"
    assert "UNSAT" in trav_fix["smt_status"]

    # Check CWE-79
    xss_fix = next((f for f in result["fixes_applied"] if f["fault"] == "REFLECTED_XSS_SINK"), None)
    assert xss_fix is not None
    assert xss_fix["cwe"] == "CWE-79"
    assert "UNSAT" in xss_fix["smt_status"]

    # Check CWE-190
    overflow_fix = next((f for f in result["fixes_applied"] if f["fault"] == "INTEGER_OVERFLOW_SINK"), None)
    assert overflow_fix is not None
    assert overflow_fix["cwe"] == "CWE-190"
    assert "UNSAT" in overflow_fix["smt_status"]


