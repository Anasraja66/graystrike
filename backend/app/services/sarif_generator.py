"""
SARIF 2.1.0 Generator — OASIS Standard Format for GitHub Code Scanning
Converts APT Agents findings into standardized SARIF v2.1.0 JSON format for GitHub Security Alerts.
"""
from typing import List, Dict, Any
from app.models.models import Scan, Finding, FindingSeverity


class SarifGenerator:
    """Generates OASIS SARIF 2.1.0 JSON documents from security scan findings."""

    SEVERITY_LEVEL_MAP = {
        FindingSeverity.CRITICAL: "error",
        FindingSeverity.HIGH: "error",
        FindingSeverity.MEDIUM: "warning",
        FindingSeverity.LOW: "note",
        FindingSeverity.INFO: "note",
    }

    @classmethod
    def generate_sarif(cls, scan: Scan, findings: List[Finding]) -> Dict[str, Any]:
        """Convert findings into a valid SARIF 2.1.0 structure."""
        rules_dict: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []

        for f in findings:
            rule_id = f.cwe_id or f.category or "SEC-001"
            sev = f.severity if isinstance(f.severity, FindingSeverity) else FindingSeverity(f.severity)
            level = cls.SEVERITY_LEVEL_MAP.get(sev, "warning")

            # Register rule if not already added
            if rule_id not in rules_dict:
                rule_name = (f.title or "SecurityVulnerability").replace(" ", "").replace("(", "").replace(")", "").replace("-", "")
                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": rule_name[:50],
                    "shortDescription": {
                        "text": f.title
                    },
                    "fullDescription": {
                        "text": f.technical_explanation or f.evidence_summary or f.title
                    },
                    "defaultConfiguration": {
                        "level": level
                    },
                    "help": {
                        "text": f"Remediation Steps:\n{f.remediation_steps or 'Review finding in APT Agents dashboard.'}\n\nAI Fix Prompt:\n{f.ai_fix_prompt or 'N/A'}",
                        "markdown": f"### Remediation\n{f.remediation_steps or 'Review finding in APT Agents dashboard.'}\n\n```ai-fix-prompt\n{f.ai_fix_prompt or 'N/A'}\n```"
                    },
                    "properties": {
                        "tags": ["security", "owasp", f.owasp_ref or "A00:2021", f.category or "general"],
                        "precision": "high" if f.confidence >= 0.8 else "medium",
                        "security-severity": "9.0" if sev == FindingSeverity.CRITICAL else "7.5" if sev == FindingSeverity.HIGH else "5.0" if sev == FindingSeverity.MEDIUM else "2.5"
                    }
                }

            # Build result object
            result_obj = {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"{f.title}: {f.evidence_summary or 'Vulnerability detected.'}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.affected_asset or scan.target_url or "https://example.com",
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": {
                                "startLine": 1,
                                "startColumn": 1
                            }
                        }
                    }
                ],
                "properties": {
                    "fingerprint": f.fingerprint,
                    "confidence": f.confidence,
                    "riskScore": f.risk_score,
                    "retestStatus": f.retest_status or "untested"
                }
            }
            results.append(result_obj)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "APT Agents",
                            "version": "1.0.0",
                            "semanticVersion": "1.0.0",
                            "informationUri": "https://aptagents.io",
                            "rules": list(rules_dict.values())
                        }
                    },
                    "results": results
                }
            ]
        }
