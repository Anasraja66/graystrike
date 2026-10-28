"""
P3: SAST Orchestrator — Master Service
Coordinates GitHub connector → AST analyzer → Code-to-Runtime mapper
to produce a complete static + dynamic security posture report.

Exposed as FastAPI endpoints:
  POST /api/v1/sast/analyze-repo   (full SAST scan of a GitHub repo)
  GET  /api/v1/sast/scan/{scan_id} (retrieve SAST results)
"""
import asyncio
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from dataclasses import asdict

from backend.app.services.sast.github_connector import GitHubConnector, GitHubRepoMeta
from backend.app.services.sast.ast_analyzer import SASTEngine, SASTFinding
from backend.app.services.sast.code_to_runtime_mapper import (
    CodeToRuntimeMapper, SecurityPostureReport
)


class SASTOrchestrator:
    """
    Top-level service that runs the full P3 SAST pipeline:
    1. Connect to GitHub → fetch security-relevant files
    2. Run AST + regex analysis → SAST findings
    3. Correlate with DAST findings → Code-to-Runtime links
    4. Return unified SecurityPostureReport
    """

    @classmethod
    async def analyze_repository(
        cls,
        owner: str,
        repo: str,
        github_token: Optional[str] = None,
        deployed_url: Optional[str] = None,
        dast_findings: Optional[List[Dict[str, Any]]] = None,
        branch: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Full SAST pipeline for a GitHub repository.

        Args:
            owner: GitHub repo owner (e.g. 'Anasraja66')
            repo: GitHub repo name (e.g. 'graystrike')
            github_token: Personal access token (optional but recommended)
            deployed_url: Live URL of the deployed app (for Code-to-Runtime mapping)
            dast_findings: Optional list of DAST findings to correlate with
            branch: Target branch (defaults to repo default branch)

        Returns:
            Serialized SecurityPostureReport as dict
        """
        connector = GitHubConnector(token=github_token)
        start_time = datetime.now(timezone.utc).isoformat()

        # Step 1: Fetch repository metadata
        meta = await connector.get_repo_meta(owner, repo)
        if not meta:
            return {
                "error": f"Repository {owner}/{repo} not accessible or not found.",
                "owner": owner,
                "repo": repo,
                "timestamp": start_time
            }

        target_branch = branch or meta.default_branch
        commit_sha = meta.latest_commit_sha

        # Step 2: Fetch security-relevant source files
        source_files = await connector.get_security_relevant_files(owner, repo, target_branch)

        # Step 3: Run SAST analysis
        raw_findings = SASTEngine.analyze_files(source_files, commit_sha=commit_sha)
        deduped_findings = SASTEngine.deduplicate(raw_findings)
        prioritized_findings = SASTEngine.prioritize(deduped_findings)

        # Step 4: Code-to-Runtime correlation
        base_url = deployed_url or f"https://{repo}.vercel.app"
        dast = dast_findings or []
        report = CodeToRuntimeMapper.build_posture_report(
            repo_url=meta.repo_url,
            commit_sha=commit_sha,
            sast_findings=prioritized_findings,
            dast_findings=dast,
            base_url=base_url
        )

        # Step 5: Serialize to JSON-compatible dict
        return cls._serialize_report(report, meta, source_files, start_time)

    @classmethod
    def _serialize_report(
        cls,
        report: SecurityPostureReport,
        meta: GitHubRepoMeta,
        source_files: List[Any],
        start_time: str
    ) -> Dict[str, Any]:
        """Convert SecurityPostureReport to fully serializable dict."""

        sast_findings_list = []
        for f in report.sast_findings:
            sast_findings_list.append({
                "rule_id": f.rule_id,
                "title": f.title,
                "cwe_id": f.cwe_id,
                "owasp_ref": f.owasp_ref,
                "severity": f.severity,
                "confidence": f.confidence,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "code_snippet": f.code_snippet,
                "explanation": f.explanation,
                "remediation": f.remediation,
                "category": f.category,
                "commit_sha": f.commit_sha,
                "verification_status": f.verification_status,
            })

        links_list = []
        for lnk in report.code_to_runtime_links:
            sf = lnk.sast_finding
            links_list.append({
                "sast_rule_id": sf.rule_id,
                "sast_title": sf.title,
                "sast_file": sf.file_path,
                "sast_line": sf.line_number,
                "dast_finding_id": lnk.dast_finding_id,
                "dast_title": lnk.dast_finding_title,
                "dast_url": lnk.dast_scan_url,
                "link_confidence": lnk.link_confidence,
                "link_method": lnk.link_method,
                "deployed_endpoint": lnk.deployed_endpoint,
                "commit_sha": lnk.commit_sha,
            })

        return {
            "scan_type": "SAST_P3",
            "repository": {
                "owner": meta.owner,
                "repo": meta.repo,
                "url": meta.repo_url,
                "branch": meta.default_branch,
                "commit_sha": meta.latest_commit_sha,
                "language": meta.language,
                "stars": meta.stars,
                "topics": meta.topics,
            },
            "analysis_meta": {
                "start_time": start_time,
                "end_time": datetime.now(timezone.utc).isoformat(),
                "files_analyzed": len(source_files),
                "rules_applied": 17,
            },
            "summary": report.summary,
            "sast_findings": sast_findings_list,
            "code_to_runtime_links": links_list,
            "severity_breakdown": report.summary.get("sast_severity_breakdown", {}),
            "dast_findings_count": len(report.dast_findings_raw),
        }

    @classmethod
    async def analyze_local_files(
        cls,
        files_dict: Dict[str, str],
        commit_sha: str = "local",
        deployed_url: str = "http://localhost:3000",
        dast_findings: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Analyze a dict of {filepath: content} pairs (for testing without GitHub API).
        Used in unit tests and local development.
        """
        from backend.app.services.sast.github_connector import GitHubFile

        files = [
            GitHubFile(
                path=path,
                name=path.rsplit("/", 1)[-1],
                sha="",
                size=len(content),
                content=content
            )
            for path, content in files_dict.items()
        ]

        raw_findings = SASTEngine.analyze_files(files, commit_sha=commit_sha)
        deduped = SASTEngine.deduplicate(raw_findings)
        prioritized = SASTEngine.prioritize(deduped)

        dast = dast_findings or []
        report = CodeToRuntimeMapper.build_posture_report(
            repo_url="local://test",
            commit_sha=commit_sha,
            sast_findings=prioritized,
            dast_findings=dast,
            base_url=deployed_url
        )

        return {
            "scan_type": "SAST_LOCAL",
            "commit_sha": commit_sha,
            "files_analyzed": len(files),
            "summary": report.summary,
            "sast_findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "cwe_id": f.cwe_id,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "code_snippet": f.code_snippet,
                    "explanation": f.explanation,
                    "remediation": f.remediation,
                    "category": f.category,
                    "verification_status": f.verification_status,
                }
                for f in prioritized
            ],
            "code_to_runtime_links": [
                {
                    "sast_rule_id": lnk.sast_finding.rule_id,
                    "sast_file": lnk.sast_finding.file_path,
                    "sast_line": lnk.sast_finding.line_number,
                    "dast_title": lnk.dast_finding_title,
                    "link_confidence": lnk.link_confidence,
                    "deployed_endpoint": lnk.deployed_endpoint,
                }
                for lnk in report.code_to_runtime_links
            ]
        }
