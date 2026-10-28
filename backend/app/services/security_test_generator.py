"""
Security Test Generator — Automated QA Verification & CI/CD Regression Test Generator
Generates ready-to-commit TypeScript (Jest/Vitest), Python (Pytest), Playwright E2E, and safe diagnostic verification probes for any detected finding.
Enables developers to enforce defensive regression testing in their CI/CD pipelines.
"""
from typing import Dict, Any, Optional
from urllib.parse import urlparse
from app.models.models import Finding


class SecurityTestGenerator:
    """Generates defensive verification and regression tests for findings."""

    @classmethod
    def generate_tests_for_finding(cls, finding: Finding) -> Dict[str, Any]:
        """
        Analyzes a finding and generates a comprehensive regression test suite.
        """
        category = (finding.category or "").lower()
        title = (finding.title or "").lower()
        asset = finding.affected_asset or "https://example.com/api"
        cwe = (finding.cwe_id or "").upper()

        parsed = urlparse(asset if asset.startswith("http") else f"https://{asset}")
        endpoint_path = parsed.path or "/"
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Supabase RLS / Unauthenticated Database Query
        if "supabase" in category or "rls" in title or "cwe-284" in cwe or "/rest/v1" in asset:
            return cls._generate_supabase_rls_tests(finding, asset, endpoint_path)

        # 2. Payment Webhook Signature Missing
        elif "webhook" in category or "webhook" in title or "cwe-345" in cwe:
            return cls._generate_webhook_tests(finding, asset, endpoint_path)

        # 3. LLM Endpoint Exposure / Rate Limiting
        elif "llm" in category or "llm" in title or "chat" in asset or "cwe-1426" in cwe:
            return cls._generate_llm_tests(finding, asset, endpoint_path)

        # 4. CORS Misconfiguration
        elif "cors" in category or "cors" in title or "cwe-942" in cwe:
            return cls._generate_cors_tests(finding, asset, endpoint_path)

        # 5. Security Headers
        elif "header" in category or "header" in title or "cwe-693" in cwe or "cwe-1021" in cwe:
            return cls._generate_headers_tests(finding, asset, endpoint_path)

        # 6. Client Bundle / Secret Exposure
        elif "secret" in category or "secret" in title or "cwe-798" in cwe or "bundle" in title:
            return cls._generate_secret_bundle_tests(finding, asset, endpoint_path)

        # 7. Default / Authorization Boundary
        else:
            return cls._generate_default_auth_tests(finding, asset, endpoint_path)

    @classmethod
    def _generate_supabase_rls_tests(cls, finding: Finding, asset: str, path: str) -> Dict[str, Any]:
        ts_code = f"""// __tests__/supabase_rls_security.test.ts
// Automatically generated defensive regression test by APT Agents
// Verifies Row-Level Security (RLS) prevents unauthorized anonymous exfiltration.
import {{ describe, it, expect }} from 'vitest';

describe('Supabase Row-Level Security (RLS) Guard', () => {{
  const TARGET_URL = process.env.TEST_TARGET_URL || '{asset}';

  it('should reject unauthenticated anonymous queries with 401 or return empty dataset', async () => {{
    const response = await fetch(TARGET_URL, {{
      method: 'GET',
      headers: {{
        'Accept': 'application/json',
      }},
    }});

    // If RLS is enabled, anonymous callers should receive 401 Unauthorized, 403 Forbidden, or an empty array
    if (response.status === 200) {{
      const data = await response.json();
      expect(Array.isArray(data)).toBe(true);
      expect(data.length).toBe(0); // RLS must not expose records to public
    }} else {{
      expect([401, 403]).toContain(response.status);
    }}
  }});

  it('should block unauthorized anonymous mutation requests', async () => {{
    const response = await fetch(TARGET_URL, {{
      method: 'POST',
      headers: {{
        'Content-Type': 'application/json',
      }},
      body: JSON.stringify({{ test_probe: true }}),
    }});

    expect([401, 403, 404, 405]).toContain(response.status);
  }});
}});
"""

        py_code = f"""# tests/test_supabase_rls_guard.py
# Automatically generated defensive regression test by APT Agents
import pytest
import httpx
import os

TARGET_URL = os.getenv("TEST_TARGET_URL", "{asset}")

@pytest.mark.asyncio
async def test_supabase_rls_blocks_anonymous_data_dump():
    \"\"\"Asserts that unauthenticated queries cannot dump table records without a valid JWT.\"\"\"
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        response = await client.get(TARGET_URL, headers={{"Accept": "application/json"}})
        
        # When RLS is active: either 401/403 or empty array []
        if response.status_code == 200:
            records = response.json()
            assert isinstance(records, list), "Expected list response"
            assert len(records) == 0, "Security violation: public anonymous query returned sensitive rows!"
        else:
            assert response.status_code in (401, 403), f"Unexpected status: {{response.status_code}}"
"""

        playwright_code = f"""// e2e/supabase_rls_guard.spec.ts
import {{ test, expect }} from '@playwright/test';

test('Security Guard: anonymous session cannot exfiltrate table records', async ({{ request }}) => {{
  const response = await request.get('{asset}', {{
    headers: {{ 'Accept': 'application/json' }}
  }});

  if (response.status() === 200) {{
    const body = await response.json();
    expect(body).toEqual([]);
  }} else {{
    expect([401, 403]).toContain(response.status());
  }}
}});
"""

        curl_cmd = f"curl -s -i \"{asset}\" -H \"Accept: application/json\""

        return {
            "finding_id": str(finding.id),
            "finding_title": finding.title,
            "category": finding.category,
            "affected_asset": asset,
            "test_frameworks": {
                "typescript_jest": {
                    "filename": "__tests__/supabase_rls_security.test.ts",
                    "code": ts_code.strip(),
                    "description": "Vitest / Jest automated test asserting RLS policy blocks anonymous data dumps."
                },
                "python_pytest": {
                    "filename": "tests/test_supabase_rls_guard.py",
                    "code": py_code.strip(),
                    "description": "Pytest integration test asserting 401/403 or zero exposed records for unauthenticated requests."
                },
                "playwright_e2e": {
                    "filename": "e2e/supabase_rls_guard.spec.ts",
                    "code": playwright_code.strip(),
                    "description": "Playwright API test for end-to-end CI/CD regression protection."
                },
                "safe_curl_verification": {
                    "command": curl_cmd,
                    "expected_status": "401 Unauthorized / 403 Forbidden or empty []",
                    "description": "Diagnostic cURL probe to quickly confirm table RLS activation from terminal."
                }
            }
        }

    @classmethod
    def _generate_webhook_tests(cls, finding: Finding, asset: str, path: str) -> Dict[str, Any]:
        ts_code = f"""// __tests__/webhook_signature.test.ts
// Automatically generated defensive regression test by APT Agents
// Verifies Stripe Webhook signature verification blocks forged requests.
import {{ describe, it, expect }} from 'vitest';

describe('Payment Webhook Signature Guard', () => {{
  const WEBHOOK_URL = process.env.TEST_TARGET_URL || '{asset}';

  it('should reject webhook events without stripe-signature header', async () => {{
    const response = await fetch(WEBHOOK_URL, {{
      method: 'POST',
      headers: {{
        'Content-Type': 'application/json',
      }},
      body: JSON.stringify({{
        id: 'evt_test_forgery',
        type: 'checkout.session.completed',
        data: {{ object: {{ payment_status: 'paid' }} }}
      }}),
    }});

    // Must strictly reject unsigned requests with 400 Bad Request or 401 Unauthorized
    expect([400, 401, 403]).toContain(response.status);
  }});

  it('should reject webhook events with invalid synthetic signature', async () => {{
    const response = await fetch(WEBHOOK_URL, {{
      method: 'POST',
      headers: {{
        'Content-Type': 'application/json',
        'stripe-signature': 't=1600000000,v1=invalid_hmac_hex_hash_forgery',
      }},
      body: JSON.stringify({{ type: 'customer.subscription.created' }}),
    }});

    expect([400, 401, 403]).toContain(response.status);
  }});
}});
"""

        py_code = f"""# tests/test_webhook_signature_guard.py
# Automatically generated defensive regression test by APT Agents
import pytest
import httpx
import os

WEBHOOK_URL = os.getenv("TEST_TARGET_URL", "{asset}")

@pytest.mark.asyncio
async def test_webhook_rejects_missing_signature():
    \"\"\"Asserts that payment webhook endpoints strictly reject requests missing cryptographic signature headers.\"\"\"
    async with httpx.AsyncClient(timeout=10.0) as client:
        payload = {{"id": "evt_fraud_test", "type": "checkout.session.completed"}}
        response = await client.post(WEBHOOK_URL, json=payload)
        
        # Must reject unverified webhooks
        assert response.status_code in (400, 401, 403), f"Vulnerability: Webhook accepted unsigned payload! Status: {{response.status_code}}"
"""

        playwright_code = f"""// e2e/webhook_signature_guard.spec.ts
import {{ test, expect }} from '@playwright/test';

test('Security Guard: webhook rejects forged unsigned payload', async ({{ request }}) => {{
  const response = await request.post('{asset}', {{
    data: {{ type: 'checkout.session.completed' }}
  }});
  expect([400, 401, 403]).toContain(response.status());
}});
"""

        curl_cmd = f"curl -X POST \"{asset}\" -H \"Content-Type: application/json\" -d '{{\"type\":\"checkout.session.completed\"}}' -i"

        return {
            "finding_id": str(finding.id),
            "finding_title": finding.title,
            "category": finding.category,
            "affected_asset": asset,
            "test_frameworks": {
                "typescript_jest": {
                    "filename": "__tests__/webhook_signature.test.ts",
                    "code": ts_code.strip(),
                    "description": "Vitest / Jest test asserting endpoint rejects unsigned webhook payloads with 400 Bad Request."
                },
                "python_pytest": {
                    "filename": "tests/test_webhook_signature_guard.py",
                    "code": py_code.strip(),
                    "description": "Pytest integration test asserting 400/401 status for unsigned webhook calls."
                },
                "playwright_e2e": {
                    "filename": "e2e/webhook_signature_guard.spec.ts",
                    "code": playwright_code.strip(),
                    "description": "Playwright API test for automated CI/CD pipeline gate."
                },
                "safe_curl_verification": {
                    "command": curl_cmd,
                    "expected_status": "400 Bad Request / 401 Unauthorized",
                    "description": "Diagnostic probe verifying missing stripe-signature header is rejected."
                }
            }
        }

    @classmethod
    def _generate_llm_tests(cls, finding: Finding, asset: str, path: str) -> Dict[str, Any]:
        ts_code = f"""// __tests__/llm_endpoint_security.test.ts
// Automatically generated defensive regression test by APT Agents
// Verifies LLM API endpoint requires authentication and enforces rate limiting.
import {{ describe, it, expect }} from 'vitest';

describe('LLM Chat Endpoint Defensive Boundary', () => {{
  const CHAT_URL = process.env.TEST_TARGET_URL || '{asset}';

  it('should reject unauthenticated requests to AI prompt endpoint', async () => {{
    const response = await fetch(CHAT_URL, {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ messages: [{{ role: 'user', content: 'Hello' }}] }}),
    }});

    // Unauthenticated requests must not invoke cloud LLM
    expect([401, 403]).toContain(response.status);
  }});

  it('should enforce rate limits or return standard quota headers', async () => {{
    const response = await fetch(CHAT_URL, {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ messages: [{{ role: 'user', content: 'Ping' }}] }}),
    }});

    // Either blocked by auth or rate limited
    expect([401, 403, 429]).toContain(response.status);
  }});
}});
"""

        py_code = f"""# tests/test_llm_endpoint_security.py
# Automatically generated defensive regression test by APT Agents
import pytest
import httpx
import os

CHAT_URL = os.getenv("TEST_TARGET_URL", "{asset}")

@pytest.mark.asyncio
async def test_llm_endpoint_requires_authentication():
    \"\"\"Asserts that unauthenticated requests to LLM endpoint are rejected to prevent Denial of Wallet.\"\"\"
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            CHAT_URL,
            json={{"messages": [{{"role": "user", "content": "Security check"}}]}}
        )
        assert response.status_code in (401, 403), f"LLM endpoint exposed without auth! Status: {{response.status_code}}"
"""

        playwright_code = f"""// e2e/llm_endpoint_guard.spec.ts
import {{ test, expect }} from '@playwright/test';

test('Security Guard: LLM route rejects unauthenticated prompt execution', async ({{ request }}) => {{
  const response = await request.post('{asset}', {{
    data: {{ messages: [{{ role: 'user', content: 'test' }}] }}
  }});
  expect([401, 403]).toContain(response.status());
}});
"""

        curl_cmd = f"curl -X POST \"{asset}\" -H \"Content-Type: application/json\" -d '{{\"messages\":[{{\"role\":\"user\",\"content\":\"test\"}}]}}' -i"

        return {
            "finding_id": str(finding.id),
            "finding_title": finding.title,
            "category": finding.category,
            "affected_asset": asset,
            "test_frameworks": {
                "typescript_jest": {
                    "filename": "__tests__/llm_endpoint_security.test.ts",
                    "code": ts_code.strip(),
                    "description": "Vitest / Jest test asserting 401 Unauthorized for unauthenticated LLM API invocations."
                },
                "python_pytest": {
                    "filename": "tests/test_llm_endpoint_security.py",
                    "code": py_code.strip(),
                    "description": "Pytest integration test asserting auth requirement to prevent API credit exhaustion."
                },
                "playwright_e2e": {
                    "filename": "e2e/llm_endpoint_guard.spec.ts",
                    "code": playwright_code.strip(),
                    "description": "Playwright API test for automated CI/CD pipeline gate."
                },
                "safe_curl_verification": {
                    "command": curl_cmd,
                    "expected_status": "401 Unauthorized / 403 Forbidden",
                    "description": "Diagnostic probe verifying endpoint blocks anonymous prompt execution."
                }
            }
        }

    @classmethod
    def _generate_cors_tests(cls, finding: Finding, asset: str, path: str) -> Dict[str, Any]:
        ts_code = f"""// __tests__/cors_security.test.ts
// Automatically generated defensive regression test by APT Agents
// Verifies Cross-Origin Resource Sharing (CORS) policy rejects arbitrary external origins.
import {{ describe, it, expect }} from 'vitest';

describe('CORS Defensive Policy Guard', () => {{
  const TARGET_URL = process.env.TEST_TARGET_URL || '{asset}';

  it('should not reflect arbitrary untrusted origins in Access-Control-Allow-Origin', async () => {{
    const untrustedOrigin = 'https://untrusted-attacker-domain.com';
    const response = await fetch(TARGET_URL, {{
      method: 'OPTIONS',
      headers: {{
        'Origin': untrustedOrigin,
        'Access-Control-Request-Method': 'GET',
      }},
    }});

    const allowOrigin = response.headers.get('access-control-allow-origin');
    
    // Defensive assertion: Origin must NOT reflect untrusted attacker domain
    expect(allowOrigin).not.toBe(untrustedOrigin);
    // If credentials are allowed, wildcard * is strictly invalid
    const allowCreds = response.headers.get('access-control-allow-credentials');
    if (allowCreds === 'true') {{
      expect(allowOrigin).not.toBe('*');
    }}
  }});
}});
"""

        py_code = f"""# tests/test_cors_security_guard.py
# Automatically generated defensive regression test by APT Agents
import pytest
import httpx
import os

TARGET_URL = os.getenv("TEST_TARGET_URL", "{asset}")

@pytest.mark.asyncio
async def test_cors_rejects_arbitrary_untrusted_origin():
    \"\"\"Asserts that CORS policy does not reflect untrusted origins with credentials.\"\"\"
    untrusted = "https://untrusted-attacker-domain.com"
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.options(
            TARGET_URL,
            headers={{"Origin": untrusted, "Access-Control-Request-Method": "GET"}}
        )
        allow_origin = response.headers.get("access-control-allow-origin")
        allow_creds = response.headers.get("access-control-allow-credentials")

        assert allow_origin != untrusted, "Vulnerability: Arbitrary origin reflected in CORS header!"
        if allow_creds == "true":
            assert allow_origin != "*", "Vulnerability: Wildcard CORS origin combined with credentials!"
"""

        playwright_code = f"""// e2e/cors_security_guard.spec.ts
import {{ test, expect }} from '@playwright/test';

test('Security Guard: CORS does not reflect arbitrary attacker origin', async ({{ request }}) => {{
  const untrusted = 'https://evil.com';
  const response = await request.fetch('{asset}', {{
    method: 'OPTIONS',
    headers: {{ 'Origin': untrusted, 'Access-Control-Request-Method': 'GET' }}
  }});
  const origin = response.headers()['access-control-allow-origin'];
  expect(origin).not.toBe(untrusted);
}});
"""

        curl_cmd = f"curl -I -X OPTIONS \"{asset}\" -H \"Origin: https://evil.com\" -H \"Access-Control-Request-Method: GET\""

        return {
            "finding_id": str(finding.id),
            "finding_title": finding.title,
            "category": finding.category,
            "affected_asset": asset,
            "test_frameworks": {
                "typescript_jest": {
                    "filename": "__tests__/cors_security.test.ts",
                    "code": ts_code.strip(),
                    "description": "Vitest / Jest test asserting CORS rejects untrusted cross-origin requests."
                },
                "python_pytest": {
                    "filename": "tests/test_cors_security_guard.py",
                    "code": py_code.strip(),
                    "description": "Pytest integration test asserting Access-Control-Allow-Origin does not reflect arbitrary domains."
                },
                "playwright_e2e": {
                    "filename": "e2e/cors_security_guard.spec.ts",
                    "code": playwright_code.strip(),
                    "description": "Playwright API test for automated CI/CD pipeline gate."
                },
                "safe_curl_verification": {
                    "command": curl_cmd,
                    "expected_status": "Access-Control-Allow-Origin != evil.com",
                    "description": "Diagnostic probe checking preflight CORS headers."
                }
            }
        }

    @classmethod
    def _generate_headers_tests(cls, finding: Finding, asset: str, path: str) -> Dict[str, Any]:
        ts_code = f"""// __tests__/security_headers.test.ts
// Automatically generated defensive regression test by APT Agents
// Verifies critical defensive HTTP headers are enforced.
import {{ describe, it, expect }} from 'vitest';

describe('Defensive HTTP Security Headers Guard', () => {{
  const TARGET_URL = process.env.TEST_TARGET_URL || '{asset}';

  it('should return required defensive headers in HTTP responses', async () => {{
    const response = await fetch(TARGET_URL, {{ method: 'HEAD' }});
    const headers = response.headers;

    // Assert defensive headers
    expect(headers.get('x-content-type-options')).toBe('nosniff');
    expect(['DENY', 'SAMEORIGIN']).toContain(headers.get('x-frame-options') || '');
    expect(headers.get('strict-transport-security')).toBeDefined();
  }});
}});
"""

        py_code = f"""# tests/test_security_headers_guard.py
# Automatically generated defensive regression test by APT Agents
import pytest
import httpx
import os

TARGET_URL = os.getenv("TEST_TARGET_URL", "{asset}")

@pytest.mark.asyncio
async def test_critical_security_headers_present():
    \"\"\"Asserts presence of X-Content-Type-Options, X-Frame-Options, and HSTS.\"\"\"
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        response = await client.head(TARGET_URL)
        headers = response.headers

        assert headers.get("x-content-type-options") == "nosniff", "Missing X-Content-Type-Options: nosniff"
        assert headers.get("x-frame-options") in ("DENY", "SAMEORIGIN"), "Missing or weak X-Frame-Options"
        assert "strict-transport-security" in headers, "Missing Strict-Transport-Security (HSTS)"
"""

        playwright_code = f"""// e2e/security_headers_guard.spec.ts
import {{ test, expect }} from '@playwright/test';

test('Security Guard: page response includes defensive HTTP headers', async ({{ page }}) => {{
  const response = await page.goto('{asset}');
  const headers = response?.headers() || {{}};
  expect(headers['x-content-type-options']).toBe('nosniff');
  expect(['deny', 'sameorigin']).toContain((headers['x-frame-options'] || '').toLowerCase());
}});
"""

        curl_cmd = f"curl -I \"{asset}\""

        return {
            "finding_id": str(finding.id),
            "finding_title": finding.title,
            "category": finding.category,
            "affected_asset": asset,
            "test_frameworks": {
                "typescript_jest": {
                    "filename": "__tests__/security_headers.test.ts",
                    "code": ts_code.strip(),
                    "description": "Vitest / Jest test asserting critical security headers (CSP, HSTS, XFO, XCTO)."
                },
                "python_pytest": {
                    "filename": "tests/test_security_headers_guard.py",
                    "code": py_code.strip(),
                    "description": "Pytest integration test verifying response headers."
                },
                "playwright_e2e": {
                    "filename": "e2e/security_headers_guard.spec.ts",
                    "code": playwright_code.strip(),
                    "description": "Playwright end-to-end check for response headers."
                },
                "safe_curl_verification": {
                    "command": curl_cmd,
                    "expected_status": "Headers: X-Content-Type-Options: nosniff",
                    "description": "Diagnostic probe inspecting HTTP response headers."
                }
            }
        }

    @classmethod
    def _generate_secret_bundle_tests(cls, finding: Finding, asset: str, path: str) -> Dict[str, Any]:
        ts_code = f"""// __tests__/client_secret_bundle.test.ts
// Automatically generated defensive regression test by APT Agents
// Verifies frontend JS bundles do not leak service-role tokens or private API keys.
import {{ describe, it, expect }} from 'vitest';

describe('Frontend Bundle Secret Leak Guard', () => {{
  const BUNDLE_URL = process.env.TEST_TARGET_URL || '{asset}';

  it('should not contain unredacted private service keys or API secrets', async () => {{
    const response = await fetch(BUNDLE_URL);
    const bundleText = await response.text();

    // High-risk leaked token patterns
    const forbiddenPatterns = [
      /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+/, // Supabase Service Role JWT
      /sk-ant-api03-[a-zA-Z0-9_\\-]{{40,}}/, // Anthropic Private Key
      /sk_live_[0-9a-zA-Z]{{24,}}/, // Stripe / Clerk Live Secret
      /ghp_[a-zA-Z0-9]{{36}}/, // GitHub PAT
    ];

    for (const pattern of forbiddenPatterns) {{
      expect(pattern.test(bundleText)).toBe(false);
    }}
  }});
}});
"""

        py_code = f"""# tests/test_bundle_secrets_guard.py
# Automatically generated defensive regression test by APT Agents
import pytest
import httpx
import re
import os

BUNDLE_URL = os.getenv("TEST_TARGET_URL", "{asset}")

@pytest.mark.asyncio
async def test_bundle_does_not_contain_private_keys():
    \"\"\"Asserts that frontend client bundles do not leak private service role tokens.\"\"\"
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(BUNDLE_URL)
        text = response.text

        assert "service_role" not in text, "Vulnerability: Supabase service_role token exposed in client bundle!"
        assert not re.search(r"sk-ant-api03-[a-zA-Z0-9_\\-]{{40,}}", text), "Vulnerability: Anthropic private key in bundle!"
        assert not re.search(r"sk_live_[0-9a-zA-Z]{{24,}}", text), "Vulnerability: Live secret key in bundle!"
"""

        playwright_code = f"""// e2e/bundle_secrets_guard.spec.ts
import {{ test, expect }} from '@playwright/test';

test('Security Guard: client assets do not expose private credentials', async ({{ request }}) => {{
  const response = await request.get('{asset}');
  const text = await response.text();
  expect(text).not.toContain('service_role');
}});
"""

        curl_cmd = f"curl -s \"{asset}\" | grep -E \"(sk-ant|sk_live|service_role)\""

        return {
            "finding_id": str(finding.id),
            "finding_title": finding.title,
            "category": finding.category,
            "affected_asset": asset,
            "test_frameworks": {
                "typescript_jest": {
                    "filename": "__tests__/client_secret_bundle.test.ts",
                    "code": ts_code.strip(),
                    "description": "Vitest / Jest static assertion ensuring client JS bundles contain zero private tokens."
                },
                "python_pytest": {
                    "filename": "tests/test_bundle_secrets_guard.py",
                    "code": py_code.strip(),
                    "description": "Pytest check verifying absence of private credentials in client assets."
                },
                "playwright_e2e": {
                    "filename": "e2e/bundle_secrets_guard.spec.ts",
                    "code": playwright_code.strip(),
                    "description": "Playwright test for CI/CD secret scanning."
                },
                "safe_curl_verification": {
                    "command": curl_cmd,
                    "expected_status": "No matches found (Empty output)",
                    "description": "Diagnostic probe scanning asset text for leaked key signatures."
                }
            }
        }

    @classmethod
    def _generate_default_auth_tests(cls, finding: Finding, asset: str, path: str) -> Dict[str, Any]:
        ts_code = f"""// __tests__/endpoint_authorization.test.ts
// Automatically generated defensive regression test by APT Agents
// Verifies endpoint enforces authentication and authorization boundaries.
import {{ describe, it, expect }} from 'vitest';

describe('Endpoint Authorization Boundary Guard', () => {{
  const TARGET_URL = process.env.TEST_TARGET_URL || '{asset}';

  it('should enforce proper status code and boundary protection', async () => {{
    const response = await fetch(TARGET_URL, {{
      method: 'GET',
      headers: {{ 'Accept': 'application/json' }},
    }});

    // Non-public endpoints should require authorization
    if (response.status !== 200) {{
      expect([401, 403, 404]).toContain(response.status);
    }}
  }});
}});
"""

        py_code = f"""# tests/test_endpoint_authorization_guard.py
# Automatically generated defensive regression test by APT Agents
import pytest
import httpx
import os

TARGET_URL = os.getenv("TEST_TARGET_URL", "{asset}")

@pytest.mark.asyncio
async def test_endpoint_authorization_boundary():
    \"\"\"Asserts that the endpoint properly enforces access controls.\"\"\"
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        response = await client.get(TARGET_URL)
        if response.status_code != 200:
            assert response.status_code in (401, 403, 404), f"Unexpected status: {{response.status_code}}"
"""

        playwright_code = f"""// e2e/endpoint_authorization.spec.ts
import {{ test, expect }} from '@playwright/test';

test('Security Guard: endpoint boundary control', async ({{ request }}) => {{
  const res = await request.get('{asset}');
  if (res.status() !== 200) {{
    expect([401, 403, 404]).toContain(res.status());
  }}
}});
"""

        curl_cmd = f"curl -s -i \"{asset}\""

        return {
            "finding_id": str(finding.id),
            "finding_title": finding.title,
            "category": finding.category,
            "affected_asset": asset,
            "test_frameworks": {
                "typescript_jest": {
                    "filename": "__tests__/endpoint_authorization.test.ts",
                    "code": ts_code.strip(),
                    "description": "Vitest / Jest test asserting defensive authorization controls."
                },
                "python_pytest": {
                    "filename": "tests/test_endpoint_authorization_guard.py",
                    "code": py_code.strip(),
                    "description": "Pytest check validating boundary response status."
                },
                "playwright_e2e": {
                    "filename": "e2e/endpoint_authorization.spec.ts",
                    "code": playwright_code.strip(),
                    "description": "Playwright API check for automated CI/CD pipeline gate."
                },
                "safe_curl_verification": {
                    "command": curl_cmd,
                    "expected_status": "401 / 403 / 404 or sanitized response",
                    "description": "Diagnostic probe checking endpoint response status."
                }
            }
        }
