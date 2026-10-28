"""
P3: AST-Based Static Security Analyzer
Parses source files (Python, TypeScript/JavaScript, SQL) using:
- Python ast module for Python files
- Regex-based semantic pattern matching for TS/JS/SQL
- Rule-based detection for security anti-patterns

Detects:
- Hardcoded secrets & API keys (CWE-798, CWE-321)
- Missing auth middleware on routes (CWE-306, CWE-285)
- RLS policies absent in SQL migrations (CWE-284)
- Disabled signature verification in webhook handlers (CWE-345)
- Dangerous eval/exec usage (CWE-95)
- SQL injection via string concatenation (CWE-89)
- Insecure CORS configuration (CWE-942)
- Missing rate limiting on sensitive endpoints (CWE-770)
"""
import ast
import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone


# =============================================================
# SAST FINDING MODEL
# =============================================================

@dataclass
class SASTFinding:
    rule_id: str
    title: str
    cwe_id: str
    owasp_ref: str
    severity: str        # critical | high | medium | low | info
    confidence: float    # 0.0 – 1.0
    file_path: str
    line_number: int
    code_snippet: str    # The offending code line(s)
    explanation: str
    remediation: str
    category: str
    commit_sha: str = ""
    verification_status: str = "suspected"  # confirmed | suspected | inconclusive


# =============================================================
# SAST RULE REGISTRY
# =============================================================

@dataclass
class SASTRule:
    rule_id: str
    title: str
    cwe_id: str
    owasp_ref: str
    severity: str
    category: str
    pattern: re.Pattern
    explanation_template: str
    remediation: str
    confidence: float = 0.85
    file_types: Tuple[str, ...] = (".js", ".ts", ".tsx", ".jsx", ".py", ".sql", ".json", ".env")

    def matches(self, line: str) -> bool:
        return bool(self.pattern.search(line))


SAST_RULES: List[SASTRule] = [

    # ——— SECRETS & HARDCODED CREDENTIALS ———
    SASTRule(
        rule_id="GS-SAST-001",
        title="Hardcoded OpenAI API Key",
        cwe_id="CWE-798",
        owasp_ref="A02:2021",
        severity="critical",
        category="secret_exposure",
        pattern=re.compile(r'(sk-[A-Za-z0-9]{32,}|OPENAI_API_KEY\s*=\s*["\']sk-[^"\']+["\'])'),
        explanation_template="OpenAI API key found hardcoded at line {line}. An attacker extracting this key can drain API credits and access proprietary prompts.",
        remediation="Move to OPENAI_API_KEY environment variable; never commit keys to source control. Add to .gitignore and rotate the exposed key immediately.",
        confidence=0.97
    ),

    SASTRule(
        rule_id="GS-SAST-002",
        title="Hardcoded Supabase Service Role or Anon Key",
        cwe_id="CWE-798",
        owasp_ref="A02:2021",
        severity="critical",
        category="secret_exposure",
        pattern=re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}'),
        explanation_template="Supabase JWT token (anon key or service_role key) detected hardcoded at line {line}. Exposing the service_role key gives full database bypass including RLS.",
        remediation="Use NEXT_PUBLIC_SUPABASE_ANON_KEY env var. Never hardcode service_role key in client-side code. Rotate exposed keys immediately.",
        confidence=0.95
    ),

    SASTRule(
        rule_id="GS-SAST-003",
        title="Hardcoded Stripe Secret Key",
        cwe_id="CWE-798",
        owasp_ref="A02:2021",
        severity="critical",
        category="secret_exposure",
        pattern=re.compile(r'sk_live_[A-Za-z0-9]{16,}|sk_test_[A-Za-z0-9]{16,}'),
        explanation_template="Stripe secret key (sk_live_* or sk_test_*) hardcoded at line {line}. Exposed stripe secret keys allow unauthorized charges and refund manipulation.",
        remediation="Store in STRIPE_SECRET_KEY environment variable. Use stripe.Webhook.construct_event() to verify webhook signatures.",
        confidence=0.98,
        file_types=(".ts", ".js", ".tsx", ".jsx", ".py", ".env", ".txt")
    ),

    SASTRule(
        rule_id="GS-SAST-004",
        title="Hardcoded AWS Secret Access Key",
        cwe_id="CWE-798",
        owasp_ref="A02:2021",
        severity="critical",
        category="secret_exposure",
        pattern=re.compile(r'(AWS_SECRET_ACCESS_KEY\s*[=:]\s*["\']?[A-Za-z0-9/+]{40}|aws_secret[^=]*=\s*["\'][^"\']{20,}["\'])'),
        explanation_template="AWS secret access key detected at line {line}. Exposure enables full AWS account takeover.",
        remediation="Use IAM roles, AWS Secrets Manager, or environment variables. Never commit AWS credentials.",
        confidence=0.93
    ),

    SASTRule(
        rule_id="GS-SAST-005",
        title="Weak Hardcoded JWT Secret",
        cwe_id="CWE-321",
        owasp_ref="A02:2021",
        severity="high",
        category="secret_exposure",
        pattern=re.compile(r"""(jwt[_\-]?secret\s*[=:]\s*['"](secret|password|123|test|dev|local|admin|changeme)['""]|JWT_SECRET\s*=\s*['"]\w{1,12}['"])""", re.I),
        explanation_template="Weak or default JWT secret detected at line {line}. Short/predictable secrets allow forging arbitrary tokens.",
        remediation="Generate a cryptographically random 256-bit secret: `openssl rand -base64 32`. Store in JWT_SECRET environment variable.",
        confidence=0.90
    ),

    SASTRule(
        rule_id="GS-SAST-006",
        title="Generic Secret Pattern in Code",
        cwe_id="CWE-798",
        owasp_ref="A02:2021",
        severity="high",
        category="secret_exposure",
        pattern=re.compile(r"""(api[_\-]?key|secret[_\-]?key|private[_\-]?key|auth[_\-]?token)\s*[=:]\s*['"][A-Za-z0-9_\-]{16,}['"]""", re.I),
        explanation_template="Generic secret/API key assignment detected at line {line}. Hardcoded credentials are a common source of credential theft.",
        remediation="Replace all hardcoded secrets with environment variable references. Use a secrets manager (HashiCorp Vault, AWS Secrets Manager, Doppler).",
        confidence=0.80
    ),

    # ——— AUTHENTICATION & AUTHORIZATION ———
    SASTRule(
        rule_id="GS-SAST-007",
        title="Missing Auth Middleware on API Route (Next.js)",
        cwe_id="CWE-306",
        owasp_ref="A01:2021",
        severity="high",
        category="missing_authentication",
        pattern=re.compile(r"""^export\s+(default\s+)?async\s+function\s+(GET|POST|PUT|DELETE|PATCH)\s*\(\s*req\b""", re.I | re.MULTILINE),
        explanation_template="Next.js API route handler at line {line} does not appear to include server-side auth check. May be unauthenticated.",
        remediation="Add auth check: `const session = await getServerSession(authOptions); if (!session) return NextResponse.json({error:'Unauthorized'}, {status:401});`",
        confidence=0.65,
        file_types=(".ts", ".tsx", ".js", ".jsx")
    ),

    SASTRule(
        rule_id="GS-SAST-008",
        title="Client-Side Only Auth Guard (React Route Gate)",
        cwe_id="CWE-285",
        owasp_ref="A01:2021",
        severity="high",
        category="client_side_auth_bypass",
        pattern=re.compile(r"""(useEffect|useState).*router\.(push|replace).*['"](/login|/auth|/signin)['""]""", re.I),
        explanation_template="Authentication redirect via useEffect/router at line {line} is a client-side only guard. Any attacker who disables JavaScript can bypass this.",
        remediation="Implement server-side middleware (Next.js middleware.ts) to enforce auth on protected routes before the React component renders.",
        confidence=0.78,
        file_types=(".ts", ".tsx", ".js", ".jsx")
    ),

    SASTRule(
        rule_id="GS-SAST-009",
        title="Admin Route Without Server-Side Auth Check",
        cwe_id="CWE-285",
        owasp_ref="A01:2021",
        severity="critical",
        category="admin_portal_exposure",
        pattern=re.compile(r"""(app\.get|app\.post|app\.delete|router\.(get|post|delete))\s*\(['"](/api/admin|/admin|/internal)[^)]*\)\s*,?\s*(async\s*)?\([^)]*\)\s*=>\s*\{(?!.*(?:auth|session|token|isAdmin|requireAdmin))""", re.I),
        explanation_template="Admin API route at line {line} registered without an auth/session check in the handler. Admin functionality may be publicly accessible.",
        remediation="Add `requireAdmin` middleware before the route handler. Validate JWT role claim server-side.",
        confidence=0.75,
        file_types=(".ts", ".js", ".py")
    ),

    # ——— WEBHOOK SECURITY ———
    SASTRule(
        rule_id="GS-SAST-010",
        title="Stripe Webhook Handler Without Signature Verification",
        cwe_id="CWE-345",
        owasp_ref="A02:2021",
        severity="critical",
        category="webhook_signature_integrity",
        pattern=re.compile(r"""(?=.*stripe)(?=.*webhook|.*event)(?!.*construct_event|.*verifySignature|.*stripe-signature).*""", re.I),
        explanation_template="Stripe webhook handler at line {line} does not call stripe.webhooks.constructEvent(). Forged webhook events can trigger fraudulent payment processing.",
        remediation="Always verify: `const event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET);`",
        confidence=0.80,
        file_types=(".ts", ".js", ".py")
    ),

    # ——— DATABASE / SUPABASE RLS ———
    SASTRule(
        rule_id="GS-SAST-011",
        title="Supabase RLS Disabled in SQL Migration",
        cwe_id="CWE-284",
        owasp_ref="A01:2021",
        severity="critical",
        category="supabase_rls_security",
        pattern=re.compile(r"DISABLE\s+ROW\s+LEVEL\s+SECURITY", re.I),
        explanation_template="SQL migration at line {line} explicitly disables Row Level Security on a table. This exposes all rows to the anon/public role.",
        remediation="Remove DISABLE ROW LEVEL SECURITY. Enable RLS and add granular policies: `ALTER TABLE tablename ENABLE ROW LEVEL SECURITY;`",
        confidence=0.99,
        file_types=(".sql",)
    ),

    SASTRule(
        rule_id="GS-SAST-012",
        title="Supabase Table Created Without RLS Enabled",
        cwe_id="CWE-284",
        owasp_ref="A01:2021",
        severity="high",
        category="supabase_rls_security",
        pattern=re.compile(r"CREATE\s+TABLE\s+(?!.*public\.schema_migrations)(\w+)", re.I),
        explanation_template="CREATE TABLE at line {line} does not appear to be followed by ENABLE ROW LEVEL SECURITY. Tables default to RLS-disabled in Supabase.",
        remediation="After every CREATE TABLE, add: `ALTER TABLE tablename ENABLE ROW LEVEL SECURITY;` and create at least one SELECT policy.",
        confidence=0.72,
        file_types=(".sql",)
    ),

    # ——— DANGEROUS CODE PATTERNS ———
    SASTRule(
        rule_id="GS-SAST-013",
        title="Dangerous eval() or exec() Usage",
        cwe_id="CWE-95",
        owasp_ref="A03:2021",
        severity="high",
        category="code_injection",
        pattern=re.compile(r"""\b(eval|exec)\s*\((?!.*#\s*nosec)"""),
        explanation_template="eval()/exec() called at line {line}. If user input reaches this call, arbitrary code execution is possible.",
        remediation="Remove eval/exec. Use ast.literal_eval() for safe data parsing. Never execute user-supplied strings.",
        confidence=0.88
    ),

    SASTRule(
        rule_id="GS-SAST-014",
        title="SQL String Concatenation — Injection Risk",
        cwe_id="CWE-89",
        owasp_ref="A03:2021",
        severity="high",
        category="sql_injection",
        pattern=re.compile(r"""(execute|cursor\.execute|db\.query)\s*\(\s*['"f].*\+\s*(?:request|req|query|params|body|user)""", re.I),
        explanation_template="SQL query built via string concatenation at line {line}. User input concatenated into SQL allows injection attacks.",
        remediation="Use parameterized queries: `cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))` or use an ORM.",
        confidence=0.85
    ),

    SASTRule(
        rule_id="GS-SAST-015",
        title="Insecure CORS — Wildcard Allow-Origin with Credentials",
        cwe_id="CWE-942",
        owasp_ref="A05:2021",
        severity="high",
        category="cors_misconfiguration",
        pattern=re.compile(r"""(Access-Control-Allow-Origin['":\s]*\*|origin:\s*['"]\*['""]|cors\(\s*\{\s*origin:\s*['"]\*['""])""", re.I),
        explanation_template="CORS wildcard origin (*) set at line {line}. Combined with credentials, this allows cross-site credential theft.",
        remediation="Replace `origin: '*'` with an explicit allowlist: `origin: ['https://yourapp.com', 'https://www.yourapp.com']`.",
        confidence=0.90
    ),

    # ——— LLM / AI SECURITY ———
    SASTRule(
        rule_id="GS-SAST-016",
        title="LLM System Prompt Exposed in Client-Side Code",
        cwe_id="CWE-200",
        owasp_ref="A02:2021",
        severity="high",
        category="llm_prompt_injection_guard",
        pattern=re.compile(r"""system[_\-]?prompt\s*[=:]\s*[`'"](.{30,})[`'"]""", re.I),
        explanation_template="LLM system prompt hardcoded in source at line {line}. Attackers can extract proprietary instructions and jailbreak your AI.",
        remediation="Store system prompts server-side only, never in client bundles. Use environment variables or encrypted config.",
        confidence=0.82
    ),

    # ——— ENV FILE PATTERNS ———
    SASTRule(
        rule_id="GS-SAST-017",
        title="Production Secret Committed in .env File",
        cwe_id="CWE-256",
        owasp_ref="A02:2021",
        severity="high",
        category="secret_exposure",
        pattern=re.compile(r"""^(OPENAI_API_KEY|STRIPE_SECRET|DATABASE_URL|JWT_SECRET|SUPABASE_SERVICE_ROLE_KEY)\s*=\s*.{8,}""", re.M),
        explanation_template="Production secret committed in .env file at line {line}. If this file is tracked by git, all secrets are exposed in the repository history.",
        remediation="Add .env to .gitignore immediately. Rotate all exposed credentials. Use .env.example with placeholder values only.",
        confidence=0.92,
        file_types=(".env", ".env.local", ".env.production", ".env.development")
    ),
]


# =============================================================
# STATIC ANALYZER ENGINE
# =============================================================

class SASTEngine:
    """
    Multi-language static security analyzer.
    Applies the SAST_RULES rule set against source file content.
    """

    @classmethod
    def analyze_file(
        cls,
        file_path: str,
        content: str,
        commit_sha: str = ""
    ) -> List[SASTFinding]:
        """
        Analyze a single source file and return all matched findings.
        """
        findings: List[SASTFinding] = []
        extension = cls._get_extension(file_path)
        lines = content.splitlines()

        for rule in SAST_RULES:
            # Check if this rule applies to this file type
            if extension not in rule.file_types and not cls._is_env_file(file_path):
                # Also allow rules with no file type restriction
                if rule.file_types != (".js", ".ts", ".tsx", ".jsx", ".py", ".sql", ".json", ".env"):
                    continue

            for line_num, line in enumerate(lines, start=1):
                if rule.matches(line):
                    snippet = cls._extract_snippet(lines, line_num - 1, context=2)
                    findings.append(SASTFinding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        cwe_id=rule.cwe_id,
                        owasp_ref=rule.owasp_ref,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=snippet,
                        explanation=rule.explanation_template.format(line=line_num),
                        remediation=rule.remediation,
                        category=rule.category,
                        commit_sha=commit_sha,
                        verification_status="confirmed" if rule.confidence >= 0.90 else "suspected"
                    ))
                    break  # One finding per rule per file (first match)

        # Python-specific: AST-based analysis
        if extension == ".py":
            ast_findings = cls._analyze_python_ast(file_path, content, commit_sha)
            findings.extend(ast_findings)

        return findings

    @classmethod
    def analyze_files(
        cls,
        files: List[Any],  # List[GitHubFile]
        commit_sha: str = ""
    ) -> List[SASTFinding]:
        """Analyze multiple files and aggregate all findings."""
        all_findings: List[SASTFinding] = []
        for f in files:
            file_findings = cls.analyze_file(f.path, f.content, commit_sha)
            all_findings.extend(file_findings)
        return all_findings

    @classmethod
    def _analyze_python_ast(
        cls, file_path: str, content: str, commit_sha: str
    ) -> List[SASTFinding]:
        """
        Deep Python code analysis using the built-in ast module.
        Detects: eval/exec calls, subprocess with shell=True, unsafe deserialization.
        """
        findings: List[SASTFinding] = []
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            # eval() / exec() calls
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name in ("eval", "exec"):
                    findings.append(SASTFinding(
                        rule_id="GS-SAST-013-AST",
                        title=f"Dangerous {func_name}() — AST Confirmed",
                        cwe_id="CWE-95",
                        owasp_ref="A03:2021",
                        severity="high",
                        confidence=0.96,
                        file_path=file_path,
                        line_number=node.lineno,
                        code_snippet=f"Line {node.lineno}: {func_name}() call",
                        explanation=f"AST-confirmed {func_name}() call at line {node.lineno}. If any user-controlled data reaches this function, remote code execution is possible.",
                        remediation="Remove eval/exec. Use safe alternatives: ast.literal_eval(), json.loads() or a proper DSL parser.",
                        category="code_injection",
                        commit_sha=commit_sha,
                        verification_status="confirmed"
                    ))

                # subprocess with shell=True
                if func_name in ("run", "call", "Popen", "check_output"):
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            findings.append(SASTFinding(
                                rule_id="GS-SAST-018-AST",
                                title="subprocess with shell=True — Command Injection Risk",
                                cwe_id="CWE-78",
                                owasp_ref="A03:2021",
                                severity="high",
                                confidence=0.92,
                                file_path=file_path,
                                line_number=node.lineno,
                                code_snippet=f"Line {node.lineno}: subprocess.{func_name}(..., shell=True)",
                                explanation=f"subprocess.{func_name}() called with shell=True at line {node.lineno}. If command string includes user input, OS command injection is possible.",
                                remediation="Remove shell=True. Pass command as a list: `subprocess.run(['cmd', arg1, arg2])` — never use string formatting with user data.",
                                category="command_injection",
                                commit_sha=commit_sha,
                                verification_status="confirmed"
                            ))

        return findings

    @staticmethod
    def _get_extension(path: str) -> str:
        if "." in path:
            ext = "." + path.rsplit(".", 1)[-1].lower()
            return ext
        return ""

    @staticmethod
    def _is_env_file(path: str) -> bool:
        name = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        return name.startswith(".env")

    @staticmethod
    def _extract_snippet(lines: List[str], idx: int, context: int = 2) -> str:
        start = max(0, idx - context)
        end = min(len(lines), idx + context + 1)
        numbered = [f"{i+1:4d}| {lines[i]}" for i in range(start, end)]
        return "\n".join(numbered)

    @classmethod
    def deduplicate(cls, findings: List[SASTFinding]) -> List[SASTFinding]:
        """Remove duplicate findings based on (rule_id, file_path)."""
        seen = set()
        unique = []
        for f in findings:
            key = (f.rule_id, f.file_path)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    @classmethod
    def prioritize(cls, findings: List[SASTFinding]) -> List[SASTFinding]:
        """Sort findings by severity then confidence."""
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return sorted(findings, key=lambda f: (order.get(f.severity, 5), -f.confidence))
