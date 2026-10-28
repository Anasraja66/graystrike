"""
Enterprise Compliance Mapping Engine
Maps security findings and runtime evidence to regulatory compliance frameworks:
- SOC 2 Type II (Trust Services Criteria)
- ISO/IEC 27001:2022
- PCI-DSS v4.0
- HIPAA Security Rule (§ 164.312)
- GDPR (Article 32)
"""
from typing import List, Dict, Any
from app.models.models import Finding, FindingSeverity


class ComplianceEngine:
    """Evaluates scan findings against standard enterprise compliance controls."""

    FRAMEWORKS = {
        "pci_dss": {
            "name": "PCI-DSS v4.0",
            "full_name": "Payment Card Industry Data Security Standard v4.0",
            "controls": [
                {
                    "id": "PCI-Req-4.1",
                    "title": "Strong Cryptography for In-Transit Cardholder Data",
                    "categories": ["cryptographic_failures", "transport_security"],
                    "keywords": ["hsts", "ssl", "tls", "plaintext", "https"]
                },
                {
                    "id": "PCI-Req-6.4.1",
                    "title": "Public-Facing Web Applications Protected Against Attacks",
                    "categories": ["xss", "sql_injection", "command_injection", "csrf", "ssrf"],
                    "keywords": ["injection", "script", "cross-site"]
                },
                {
                    "id": "PCI-Req-6.4.2",
                    "title": "Security Headers & UI Redressing Defense",
                    "categories": ["security_headers", "security_misconfiguration"],
                    "keywords": ["clickjacking", "x-frame-options", "content-security-policy", "csp"]
                },
                {
                    "id": "PCI-Req-8.3",
                    "title": "Strong Access Control & Authentication Management",
                    "categories": ["broken_authentication", "idor", "jwt_tampering"],
                    "keywords": ["auth", "token", "session", "credential"]
                }
            ]
        },
        "soc_2": {
            "name": "SOC 2 Type II",
            "full_name": "AICPA SOC 2 Type II Trust Services Criteria",
            "controls": [
                {
                    "id": "SOC2-CC6.1",
                    "title": "Logical Access Restrictions to Protect System Boundaries",
                    "categories": ["broken_authentication", "idor", "path_traversal", "supabase_exposure"],
                    "keywords": ["access", "unauthorized", "bypass", "rls"]
                },
                {
                    "id": "SOC2-CC6.6",
                    "title": "Protection Against Injections and Application Vulnerabilities",
                    "categories": ["sql_injection", "xss", "command_injection", "ssrf"],
                    "keywords": ["injection", "malicious", "xss"]
                },
                {
                    "id": "SOC2-CC6.7",
                    "title": "Transmission Data Protection & In-Transit Encryption",
                    "categories": ["cryptographic_failures", "security_headers"],
                    "keywords": ["hsts", "encryption", "transport", "ssl"]
                },
                {
                    "id": "SOC2-CC7.1",
                    "title": "Vulnerability Detection & Continuous Security Monitoring",
                    "categories": ["easm", "git_leakage", "shadow_api", "subdomain_takeover"],
                    "keywords": ["leak", "exposure", "shadow", "dns"]
                }
            ]
        },
        "iso_27001": {
            "name": "ISO/IEC 27001:2022",
            "full_name": "Information Security Management System (ISO 27001)",
            "controls": [
                {
                    "id": "ISO-A.8.20",
                    "title": "Network Security & External Attack Surface Protection",
                    "categories": ["subdomain_takeover", "dns_caa", "dns_dmarc", "origin_leak"],
                    "keywords": ["dns", "subdomain", "origin", "caa"]
                },
                {
                    "id": "ISO-A.8.24",
                    "title": "Use of Cryptography & Secure Transport Policies",
                    "categories": ["cryptographic_failures", "security_headers"],
                    "keywords": ["hsts", "tls", "ssl", "cipher"]
                },
                {
                    "id": "ISO-A.8.26",
                    "title": "Application Security Requirements & Input Sanitization",
                    "categories": ["xss", "sql_injection", "command_injection", "xxe"],
                    "keywords": ["injection", "sanitization", "xss", "input"]
                },
                {
                    "id": "ISO-A.8.28",
                    "title": "Secure Coding Principles & Sensitive Data Protection",
                    "categories": ["git_leakage", "cors_misconfiguration", "pii_leak"],
                    "keywords": [".git", ".env", "cors", "pii", "secret"]
                }
            ]
        },
        "hipaa": {
            "name": "HIPAA Security Rule",
            "full_name": "Health Insurance Portability and Accountability Act (45 CFR § 164.312)",
            "controls": [
                {
                    "id": "HIPAA-164.312(a)",
                    "title": "Access Control & Technical Safeguards for ePHI",
                    "categories": ["broken_authentication", "idor", "supabase_exposure"],
                    "keywords": ["auth", "unauthorized", "rls", "phi"]
                },
                {
                    "id": "HIPAA-164.312(e)",
                    "title": "Transmission Security for Electronic Protected Health Info",
                    "categories": ["cryptographic_failures", "security_headers"],
                    "keywords": ["hsts", "tls", "plaintext", "encryption"]
                }
            ]
        },
        "gdpr": {
            "name": "GDPR (Article 32)",
            "full_name": "General Data Protection Regulation — Security of Processing",
            "controls": [
                {
                    "id": "GDPR-Art-32.1.a",
                    "title": "Pseudonymisation and Encryption of Personal Data",
                    "categories": ["cryptographic_failures", "git_leakage", "pii_leak"],
                    "keywords": ["hsts", "leak", ".env", "pii", "encryption"]
                },
                {
                    "id": "GDPR-Art-32.1.b",
                    "title": "Ongoing Confidentiality, Integrity, and Resilience of Systems",
                    "categories": ["xss", "sql_injection", "broken_authentication", "idor"],
                    "keywords": ["injection", "bypass", "auth"]
                }
            ]
        }
    }

    @classmethod
    def evaluate_compliance(cls, findings: List[Finding]) -> Dict[str, Any]:
        """
        Evaluates scan findings against each compliance framework and calculates audit scores.
        """
        results: Dict[str, Any] = {}

        for fw_key, fw in cls.FRAMEWORKS.items():
            total_controls = len(fw["controls"])
            passing_controls = 0
            controls_detail = []

            for ctrl in fw["controls"]:
                # Check which findings violate this control
                violating = []
                for f in findings:
                    cat = (f.category or "").lower()
                    title = (f.title or "").lower()
                    cwe = (f.cwe_id or "").lower()

                    matches_cat = any(c in cat for c in ctrl["categories"])
                    matches_kw = any(k in title or k in cat or k in cwe for k in ctrl["keywords"])

                    if matches_cat or matches_kw:
                        violating.append({
                            "finding_id": str(f.id),
                            "title": f.title,
                            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                            "affected_asset": f.affected_asset,
                            "status": f.status.value if hasattr(f.status, "value") else str(f.status)
                        })

                is_compliant = len(violating) == 0
                if is_compliant:
                    passing_controls += 1

                controls_detail.append({
                    "control_id": ctrl["id"],
                    "title": ctrl["title"],
                    "status": "COMPLIANT" if is_compliant else "NON_COMPLIANT",
                    "violations_count": len(violating),
                    "violating_findings": violating[:5]
                })

            score_pct = int((passing_controls / total_controls) * 100) if total_controls > 0 else 100

            results[fw_key] = {
                "framework_id": fw_key,
                "framework_name": fw["name"],
                "full_name": fw["full_name"],
                "compliance_score": score_pct,
                "status": "PASSED" if score_pct == 100 else "NEEDS_REMEDIATION" if score_pct >= 70 else "NON_COMPLIANT",
                "total_controls": total_controls,
                "passing_controls": passing_controls,
                "failing_controls": total_controls - passing_controls,
                "controls": controls_detail
            }

        return results
