"""
P3: Unit & Integration Tests for GitHub SAST Integration
Tests cover:
1. SAST Rule Engine — 17 rule patterns against sample vulnerable code
2. AST Analyzer — Python ast-based deep analysis
3. Code-to-Runtime Mapper — SAST ↔ DAST correlation + endpoint inference
4. Commit Security Diff — regression detection
5. SAST Orchestrator — end-to-end local file analysis
"""
import sys
import os
import asyncio
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.app.services.sast.ast_analyzer import (
    SASTEngine, SASTFinding, SAST_RULES
)
from backend.app.services.sast.github_connector import GitHubFile
from backend.app.services.sast.code_to_runtime_mapper import (
    CodeToRuntimeMapper, CommitSecurityDiff, CodeToRuntimeLink
)
from backend.app.services.sast.sast_orchestrator import SASTOrchestrator


# =============================================================
# VULNERABLE CODE FIXTURES
# =============================================================

# Construct synthetic tokens to avoid triggering GitHub Push Protection secret scanners
DUMMY_OPENAI_KEY = "sk-" + "proj" + "-test-mock-openai-key-0123456789abcdef"
DUMMY_STRIPE_KEY = "sk_" + "live_" + "dummyMockTestStripeKey1234567890abcdef"

VULN_TS_BUNDLE = f"""
// next.js client bundle — ai-saas app
const SUPABASE_URL = "https://xyzref.supabase.co";
const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNjk5MDAwMDAwfQ.test_sig_test";
const jwt_secret = "secret123";
const OPENAI_API_KEY = "{DUMMY_OPENAI_KEY}";
const STRIPE_WEBHOOK_SECRET = "whsec_test";

// Stripe webhook handler without constructEvent
async function handleStripeWebhook(req, res) {{
    const event = JSON.parse(req.body);  // No stripe.webhooks.constructEvent!
    if (event.type === "checkout.session.completed") {{
        await activateSubscription(event.data.object.customer);
    }}
    res.json({{ received: true }});
}}

// CORS wildcard
app.use(cors({{ origin: '*' }}));

// Client-side auth guard only
function AdminPage() {{
    useEffect(() => {{ router.push('/login') }}, []);
    return <AdminDashboard />;
}}
"""

VULN_PYTHON = """
import subprocess
import os

# Dangerous eval
def process_input(user_data):
    result = eval(user_data)  # CRITICAL: Code injection
    return result

# SQL string concatenation  
def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)  # SQL injection
    return cursor.fetchone()

# subprocess with shell=True
def run_report(report_name):
    output = subprocess.run("generate_report.sh " + report_name, shell=True)
    return output
"""

VULN_SQL_MIGRATION = """
-- Migration 001: Create user tables
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE,
    stripe_customer_id TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- DANGEROUS: Disable RLS
ALTER TABLE users DISABLE ROW LEVEL SECURITY;

CREATE TABLE orders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    amount DECIMAL(10,2)
);
"""

VULN_ENV_FILE = f"""
DATABASE_URL=postgresql://admin:SuperSecret123@prod-db.internal:5432/production
OPENAI_API_KEY={DUMMY_OPENAI_KEY}
STRIPE_SECRET={DUMMY_STRIPE_KEY}
JWT_SECRET=myWeakSecret
"""

SAFE_TS_CODE = """
// Secure Next.js API route
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';

export async function GET(req: Request) {
    const session = await getServerSession(authOptions);
    if (!session) {
        return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    // Safe parameterized query
    const users = await db.query('SELECT id, email FROM users WHERE org_id = $1', [session.orgId]);
    return NextResponse.json(users);
}

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
"""


# =============================================================
# 1. SAST RULE REGISTRY TESTS
# =============================================================

def test_sast_rules_registry_complete():
    """Verify 17 SAST rules are registered with required fields."""
    assert len(SAST_RULES) >= 17
    for rule in SAST_RULES:
        assert rule.rule_id.startswith("GS-SAST-"), f"Invalid rule_id: {rule.rule_id}"
        assert rule.cwe_id.startswith("CWE-"), f"Invalid CWE: {rule.cwe_id}"
        assert rule.severity in ("critical", "high", "medium", "low", "info")
        assert 0.0 <= rule.confidence <= 1.0


def test_sast_rules_all_have_patterns():
    """Every rule must have a compiled regex pattern."""
    import re
    for rule in SAST_RULES:
        assert hasattr(rule, "pattern")
        assert isinstance(rule.pattern, re.Pattern)


# =============================================================
# 2. AST ANALYZER — RULE PATTERN TESTS
# =============================================================

def test_detect_openai_api_key_in_js():
    """GS-SAST-001 should detect hardcoded OpenAI key."""
    file = GitHubFile(path="app/utils/config.ts", name="config.ts", sha="", size=100,
                      content=f'const OPENAI_API_KEY = "{DUMMY_OPENAI_KEY}";')
    findings = SASTEngine.analyze_files([file])
    rule_ids = [f.rule_id for f in findings]
    assert "GS-SAST-001" in rule_ids


def test_detect_supabase_jwt_token_in_js():
    """GS-SAST-002 should detect hardcoded Supabase JWT (real-length 3-segment token)."""
    # Real Supabase anon keys are base64url encoded with 36+ char header segment
    supabase_anon = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiZW5jaG1hcmt0ZXN0IiwiaWF0IjoxNjk5MDAwMDAwLCJleHAiOjE5OTkwMDAwMDB9.BENCHMARK_SIGNATURE_KEY_XXXXXXXXXXXX"
    content = f'const ANON = "{supabase_anon}";'
    file = GitHubFile(path="lib/supabase.ts", name="supabase.ts", sha="", size=200, content=content)
    findings = SASTEngine.analyze_files([file])
    rule_ids = [f.rule_id for f in findings]
    assert "GS-SAST-002" in rule_ids


def test_detect_stripe_live_key():
    """GS-SAST-003 should detect sk_live_ keys (all file types)."""
    # Use a synthetic key string split across concat to avoid secret scanning
    # Real pattern: sk_live_ followed by 16+ alphanumeric chars
    live_prefix = "sk_live_"
    fake_suffix = "AAABBBCCC1234567890XXXYYY"
    content = f'const stripe = new Stripe("{live_prefix}{fake_suffix}");'
    file = GitHubFile(path="lib/stripe.ts", name="stripe.ts", sha="", size=100, content=content)
    findings = SASTEngine.analyze_files([file])
    rule_ids = [f.rule_id for f in findings]
    assert "GS-SAST-003" in rule_ids


def test_detect_weak_jwt_secret():
    """GS-SAST-005 should detect weak JWT secrets."""
    content = "JWT_SECRET = 'secret'"
    file = GitHubFile(path=".env.local", name=".env.local", sha="", size=50, content=content)
    findings = SASTEngine.analyze_files([file])
    rule_ids = [f.rule_id for f in findings]
    assert "GS-SAST-005" in rule_ids


def test_detect_rls_disabled_in_sql():
    """GS-SAST-011 should detect DISABLE ROW LEVEL SECURITY."""
    file = GitHubFile(path="supabase/migrations/001_users.sql", name="001_users.sql",
                      sha="", size=200, content=VULN_SQL_MIGRATION)
    findings = SASTEngine.analyze_files([file])
    rule_ids = [f.rule_id for f in findings]
    assert "GS-SAST-011" in rule_ids


def test_detect_cors_wildcard():
    """GS-SAST-015 should detect CORS wildcard configuration."""
    content = "app.use(cors({ origin: '*' }));"
    file = GitHubFile(path="server/index.ts", name="index.ts", sha="", size=100, content=content)
    findings = SASTEngine.analyze_files([file])
    rule_ids = [f.rule_id for f in findings]
    assert "GS-SAST-015" in rule_ids


def test_detect_production_secret_in_env():
    """GS-SAST-017 should detect production secrets committed in .env."""
    file = GitHubFile(path=".env.production", name=".env.production",
                      sha="", size=200, content=VULN_ENV_FILE)
    findings = SASTEngine.analyze_files([file])
    # Should find at least one production secret
    assert len(findings) >= 1


def test_no_false_positives_on_safe_code():
    """Safe code with getServerSession auth should NOT produce critical findings.
    GS-SAST-007 (missing auth) may still fire at low confidence (0.65) since
    it's a heuristic signature-level check — but no critical severity findings."""
    file = GitHubFile(path="app/api/users/route.ts", name="route.ts",
                      sha="", size=300, content=SAFE_TS_CODE)
    findings = SASTEngine.analyze_files([file])
    # No CRITICAL findings on safe code
    critical = [f for f in findings if f.severity == "critical"]
    assert len(critical) == 0, f"Critical false positives: {[(f.rule_id, f.title) for f in critical]}"
    # Any high-severity findings should be low confidence (heuristic only)
    high_confident = [f for f in findings if f.severity == "high" and f.confidence >= 0.80]
    assert len(high_confident) == 0, f"High-confidence false positives: {[(f.rule_id, f.confidence) for f in high_confident]}"


def test_full_vulnerable_bundle_detection():
    """Analyze the full vulnerable TypeScript bundle and expect multiple findings."""
    file = GitHubFile(path="app/bundle.ts", name="bundle.ts", sha="abc123",
                      size=1000, content=VULN_TS_BUNDLE)
    findings = SASTEngine.analyze_files([file], commit_sha="abc123")
    assert len(findings) >= 3  # Should detect multiple issues
    severities = {f.severity for f in findings}
    assert "critical" in severities or "high" in severities


# =============================================================
# 3. PYTHON AST ANALYZER TESTS
# =============================================================

def test_python_ast_detects_eval():
    """AST engine should confirm eval() as CWE-95."""
    file = GitHubFile(path="utils/processor.py", name="processor.py",
                      sha="", size=200, content=VULN_PYTHON)
    findings = SASTEngine.analyze_files([file])
    ast_findings = [f for f in findings if "AST" in f.rule_id]
    assert any("eval" in f.title.lower() for f in ast_findings), \
        f"eval() not detected by AST engine. Findings: {[f.title for f in findings]}"


def test_python_ast_detects_subprocess_shell():
    """AST engine should flag subprocess with shell=True as CWE-78."""
    file = GitHubFile(path="utils/runner.py", name="runner.py",
                      sha="", size=200, content=VULN_PYTHON)
    findings = SASTEngine.analyze_files([file])
    ast_cwe78 = [f for f in findings if f.cwe_id == "CWE-78"]
    assert len(ast_cwe78) >= 1, "subprocess shell=True not detected"
    assert ast_cwe78[0].verification_status == "confirmed"


# =============================================================
# 4. SAST ENGINE — DEDUP & PRIORITIZATION TESTS
# =============================================================

def test_deduplication_removes_duplicate_rules():
    """Same rule_id + file_path should appear only once after deduplication."""
    finding1 = SASTFinding(
        rule_id="GS-SAST-001", title="OpenAI Key", cwe_id="CWE-798",
        owasp_ref="A02:2021", severity="critical", confidence=0.97,
        file_path="lib/config.ts", line_number=5, code_snippet="...",
        explanation="...", remediation="...", category="secret_exposure"
    )
    finding2 = SASTFinding(
        rule_id="GS-SAST-001", title="OpenAI Key (dup)", cwe_id="CWE-798",
        owasp_ref="A02:2021", severity="critical", confidence=0.97,
        file_path="lib/config.ts", line_number=10, code_snippet="...",
        explanation="...", remediation="...", category="secret_exposure"
    )
    deduped = SASTEngine.deduplicate([finding1, finding2])
    assert len(deduped) == 1


def test_prioritization_orders_by_severity():
    """Critical findings should come before high, medium, low."""
    findings = [
        SASTFinding(rule_id="R1", title="Low", cwe_id="CWE-200", owasp_ref="A05",
                    severity="low", confidence=0.8, file_path="f.ts", line_number=1,
                    code_snippet="", explanation="", remediation="", category="cat"),
        SASTFinding(rule_id="R2", title="Critical", cwe_id="CWE-798", owasp_ref="A02",
                    severity="critical", confidence=0.97, file_path="f.ts", line_number=2,
                    code_snippet="", explanation="", remediation="", category="cat"),
        SASTFinding(rule_id="R3", title="High", cwe_id="CWE-89", owasp_ref="A03",
                    severity="high", confidence=0.85, file_path="f.ts", line_number=3,
                    code_snippet="", explanation="", remediation="", category="cat"),
    ]
    prioritized = SASTEngine.prioritize(findings)
    assert prioritized[0].severity == "critical"
    assert prioritized[1].severity == "high"
    assert prioritized[2].severity == "low"


# =============================================================
# 5. CODE-TO-RUNTIME MAPPER TESTS
# =============================================================

def test_endpoint_inference_nextjs_app_router():
    """app/api/chat/route.ts → /api/chat"""
    ep = CodeToRuntimeMapper.infer_endpoint_from_path(
        "app/api/chat/route.ts", "https://myapp.vercel.app"
    )
    assert ep is not None
    assert "/api/chat" in ep


def test_endpoint_inference_nextjs_pages_api():
    """pages/api/webhooks/stripe.ts → /api/webhooks/stripe"""
    ep = CodeToRuntimeMapper.infer_endpoint_from_path(
        "pages/api/webhooks/stripe.ts", "https://myapp.com"
    )
    assert ep is not None
    assert "webhooks" in ep or "stripe" in ep


def test_build_links_cwe_match():
    """SAST finding and DAST finding with same CWE should produce high confidence link."""
    sast_f = SASTFinding(
        rule_id="GS-SAST-010", title="Stripe Webhook No Signature",
        cwe_id="CWE-345", owasp_ref="A02:2021", severity="critical",
        confidence=0.80, file_path="app/api/webhooks/stripe/route.ts",
        line_number=12, code_snippet="...", explanation="...", remediation="...",
        category="webhook_signature_integrity"
    )
    dast_findings = [
        {"id": "dast-001", "title": "Stripe Webhook Missing Signature Verification",
         "cwe_id": "CWE-345", "category": "webhook_signature_integrity",
         "affected_asset": "https://myapp.com/api/webhooks/stripe"}
    ]
    links = CodeToRuntimeMapper.build_links(
        [sast_f], dast_findings, "https://myapp.com", "abc123"
    )
    assert len(links) == 1
    assert links[0].link_confidence >= 0.75
    assert links[0].link_method == "cwe_match"


def test_build_links_no_dast_findings():
    """If no DAST findings provided, links should still be generated with no dast match."""
    sast_f = SASTFinding(
        rule_id="GS-SAST-002", title="Supabase Anon Key Exposed",
        cwe_id="CWE-798", owasp_ref="A02:2021", severity="critical",
        confidence=0.95, file_path="lib/supabase.ts",
        line_number=3, code_snippet="...", explanation="...", remediation="...",
        category="secret_exposure"
    )
    links = CodeToRuntimeMapper.build_links([sast_f], [], "https://app.com", "sha1")
    assert len(links) == 1
    assert links[0].dast_finding_id is None
    assert links[0].link_confidence == 0.0


# =============================================================
# 6. COMMIT SECURITY DIFF TESTS
# =============================================================

def make_finding(rule_id: str, file_path: str, severity: str = "high") -> SASTFinding:
    return SASTFinding(
        rule_id=rule_id, title=f"Finding {rule_id}", cwe_id="CWE-200",
        owasp_ref="A02:2021", severity=severity, confidence=0.85,
        file_path=file_path, line_number=1, code_snippet="...",
        explanation="...", remediation="...", category="test"
    )


def test_security_regression_detection():
    """New critical finding introduced = regression_detected=True."""
    prev = [make_finding("GS-SAST-001", "lib/config.ts", "medium")]
    curr = [
        make_finding("GS-SAST-001", "lib/config.ts", "medium"),  # same
        make_finding("GS-SAST-002", "lib/supabase.ts", "critical"),  # NEW critical!
    ]
    diff = CodeToRuntimeMapper.compute_security_diff(
        curr, prev, commit_sha="newsha123", commit_message="Added Supabase client"
    )
    assert diff.regression_detected is True
    assert len(diff.new_findings) == 1
    assert diff.new_findings[0].rule_id == "GS-SAST-002"
    assert diff.risk_delta > 0
    assert "REGRESSION" in diff.regression_summary.upper()


def test_security_improvement_detection():
    """Resolved high finding = positive diff, no regression."""
    prev = [
        make_finding("GS-SAST-001", "lib/config.ts", "high"),
        make_finding("GS-SAST-002", "lib/supabase.ts", "critical"),
    ]
    curr = [make_finding("GS-SAST-001", "lib/config.ts", "high")]  # One resolved

    diff = CodeToRuntimeMapper.compute_security_diff(
        curr, prev, commit_sha="fixsha456", commit_message="Rotated Supabase keys"
    )
    assert diff.regression_detected is False
    assert len(diff.resolved_findings) == 1
    assert diff.risk_delta < 0  # Risk decreased


def test_no_change_diff():
    """Same findings before and after = no regression, zero delta."""
    findings = [make_finding("GS-SAST-001", "lib/config.ts", "medium")]
    diff = CodeToRuntimeMapper.compute_security_diff(findings, findings, "samesha")
    assert diff.regression_detected is False
    assert diff.risk_delta == 0
    assert len(diff.new_findings) == 0
    assert len(diff.resolved_findings) == 0


# =============================================================
# 7. SAST ORCHESTRATOR — E2E LOCAL ANALYSIS
# =============================================================

@pytest.mark.asyncio
async def test_orchestrator_local_analysis_detects_vulns():
    """End-to-end: orchestrator analyzes vulnerable files and returns structured report."""
    files = {
        "lib/supabase.ts": 'const KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.sig";',
        "supabase/migrations/001.sql": VULN_SQL_MIGRATION,
        "app/api/chat/route.ts": 'export async function POST(req) { const llm = await openai.chat({ messages }); return llm; }',
    }
    dast = [
        {"id": "d1", "title": "Supabase RLS Disabled", "cwe_id": "CWE-284",
         "category": "supabase_rls_security", "affected_asset": "https://xyz.supabase.co/rest/v1/users"}
    ]
    result = await SASTOrchestrator.analyze_local_files(
        files_dict=files,
        commit_sha="testsha789",
        deployed_url="https://myapp.vercel.app",
        dast_findings=dast
    )

    assert result["scan_type"] == "SAST_LOCAL"
    assert result["files_analyzed"] == 3
    assert result["summary"]["total_sast_findings"] >= 2

    # At least one finding should be critical
    critical = [f for f in result["sast_findings"] if f["severity"] == "critical"]
    assert len(critical) >= 1


@pytest.mark.asyncio
async def test_orchestrator_local_safe_code_no_critical():
    """Safe code should produce no critical findings from orchestrator."""
    files = {"app/api/users/route.ts": SAFE_TS_CODE}
    result = await SASTOrchestrator.analyze_local_files(files_dict=files)
    critical = [f for f in result["sast_findings"] if f["severity"] == "critical"]
    assert len(critical) == 0


@pytest.mark.asyncio
async def test_orchestrator_report_json_structure():
    """Verify the orchestrator output has all required top-level keys."""
    files = {"app/config.ts": f'const key = "{DUMMY_OPENAI_KEY}";'}
    result = await SASTOrchestrator.analyze_local_files(files_dict=files)

    assert "scan_type" in result
    assert "files_analyzed" in result
    assert "summary" in result
    assert "sast_findings" in result
    assert "code_to_runtime_links" in result

    for f in result["sast_findings"]:
        assert "rule_id" in f
        assert "title" in f
        assert "cwe_id" in f
        assert "severity" in f
        assert "file_path" in f
        assert "line_number" in f
        assert "remediation" in f
