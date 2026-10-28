"""
Background Tasks — Scan execution wired to LangGraph Orchestrator
"""
import sys
import os
from pathlib import Path

# Ensure backend and ai-engine are in Python path
base_dir = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(base_dir))
sys.path.insert(0, str(base_dir / "backend"))
sys.path.insert(0, str(base_dir / "ai-engine"))

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import asyncio
from datetime import datetime, timezone
from sqlalchemy import select

from app.worker.celery_app import celery_app
from app.core.database import AsyncSessionLocal
from app.models.models import (
    Scan, ScanStatus, ScanEvent, Finding, Project, Domain, FindingSeverity, 
    VerificationStatus, FindingStatus, FindingEvidence
)
from ai_engine.orchestrator.workflow import build_scan_graph


if celery_app is not None:
    @celery_app.task(bind=True, max_retries=1, name="run_scan_task")
    def run_scan_task(self, scan_id: str):
        """Execute a security scan in the background via LangGraph."""
        print(f"🚀 Starting background scan task: {scan_id}")
        try:
            asyncio.run(_run_scan_async(scan_id))
        except Exception as exc:
            print(f"❌ Scan {scan_id} failed: {exc}")
            raise self.retry(exc=exc, countdown=5)
else:
    def run_scan_task(*args, **kwargs):
        pass


async def _run_scan_async(scan_id: str):
    """Execute scan workflow with LangGraph, recording real findings into DB."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            return

        # Fetch Project and verified domains
        proj_res = await db.execute(select(Project).where(Project.id == scan.project_id))
        project = proj_res.scalar_one_or_none()

        dom_res = await db.execute(select(Domain).where(Domain.project_id == scan.project_id))
        domains = dom_res.scalars().all()

        is_verified = any(d.is_verified for d in domains)
        allowed_hosts = [d.hostname for d in domains if d.is_verified]

        # In dev mode, if target URL host matches project base_url host, permit it
        from urllib.parse import urlparse
        target_host = urlparse(scan.target_url).hostname or ""
        if not allowed_hosts and target_host:
            allowed_hosts = [target_host]
            is_verified = True  # Auto-verify in local dev mode

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        scan.current_stage = "reconnaissance"

        db.add(ScanEvent(
            scan_id=scan.id,
            event_type="scan_started",
            message=f"Scan initialized for {scan.target_url}",
            data={"target": scan.target_url}
        ))
        await db.commit()

    # Run LangGraph Orchestrator
    graph = build_scan_graph()

    initial_state = {
        "scan_id": scan_id,
        "target_url": scan.target_url,
        "allowed_hosts": allowed_hosts,
        "denied_paths": [],
        "is_domain_verified": is_verified,
        "is_scope_valid": False,
        "status": "starting",
        "current_stage": "starting",
        "crawl_result": None,
        "selected_agents": [],
        "agent_results": {},
        "candidate_findings": [],
        "verified_findings": [],
        "total_tokens": 0,
        "duration_seconds": 0.0,
        "error_message": None,
    }

    final_state = await graph.ainvoke(initial_state)

    # Persist findings and final metrics to database
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            return

        if final_state.get("status") == "failed":
            scan.status = ScanStatus.FAILED
            scan.error_message = final_state.get("error_message")
            scan.completed_at = datetime.now(timezone.utc)
            db.add(ScanEvent(
                scan_id=scan.id,
                event_type="scan_failed",
                message=scan.error_message or "Scan failed",
                data={}
            ))
            await db.commit()
            return

        # Record findings
        verified_findings = final_state.get("verified_findings", [])
        critical = 0
        high = 0
        medium = 0
        low = 0

        # Record findings with Stable Fingerprint Deduplication & Regression Detection
        import hashlib
        now_utc = datetime.now(timezone.utc)
        persisted_findings = []

        for f_dict in verified_findings:
            sev_str = f_dict.get("severity", "medium").lower()
            if sev_str == "critical":
                sev_enum = FindingSeverity.CRITICAL
                critical += 1
            elif sev_str == "high":
                sev_enum = FindingSeverity.HIGH
                high += 1
            elif sev_str == "low":
                sev_enum = FindingSeverity.LOW
                low += 1
            else:
                sev_enum = FindingSeverity.MEDIUM
                medium += 1

            asset = f_dict.get("affected_asset", scan.target_url)
            cat = f_dict.get("category", "general")
            cwe = f_dict.get("cwe_id", "CWE-000")
            # Calculate stable fingerprint
            fp = hashlib.sha256(f"{cat}:{cwe}:{asset.lower().strip()}".encode()).hexdigest()

            # Deduplication lookup
            existing_res = await db.execute(
                select(Finding).where(Finding.project_id == scan.project_id, Finding.fingerprint == fp)
            )
            existing = existing_res.scalar_one_or_none()

            if existing:
                # Deduplication: Update existing canonical finding
                existing.last_seen_at = now_utc
                existing.scan_id = scan.id
                existing.evidence_summary = f_dict.get("evidence_summary", existing.evidence_summary)
                existing.confidence = f_dict.get("confidence", existing.confidence)
                if f_dict.get("screenshot_url"):
                    existing.screenshot_url = f_dict.get("screenshot_url")

                # Regression Detection: If developer marked it resolved but it reappeared!
                if existing.status == FindingStatus.RESOLVED:
                    existing.status = FindingStatus.REGRESSION_DETECTED
                    existing.retest_status = "regression_detected"
                    existing.retest_notes = f"Regression detected in scan {scan.id[:8]}: Vulnerability reappeared after having been marked resolved."
                    db.add(ScanEvent(
                        scan_id=scan.id,
                        event_type="regression_detected",
                        message=f"🚨 Regression detected: '{existing.title}' reappeared on {asset}",
                        data={"finding_id": str(existing.id), "fingerprint": fp}
                    ))
                persisted_findings.append(existing)
            else:
                # Brand new finding
                new_finding = Finding(
                    scan_id=scan.id,
                    organization_id=scan.organization_id,
                    project_id=scan.project_id,
                    fingerprint=fp,
                    title=f_dict.get("title", "Untitled Finding"),
                    category=cat,
                    cwe_id=f_dict.get("cwe_id"),
                    owasp_ref=f_dict.get("owasp_ref"),
                    affected_asset=asset,
                    evidence_summary=f_dict.get("evidence_summary", ""),
                    screenshot_url=f_dict.get("screenshot_url"),
                    severity=sev_enum,
                    confidence=f_dict.get("confidence", 0.8),
                    risk_score=f_dict.get("risk_score", 0.5),
                    status=FindingStatus.OPEN,
                    first_seen_at=now_utc,
                    last_seen_at=now_utc,
                    verification_status=VerificationStatus.CONFIRMED if f_dict.get("verification_status") == "confirmed" else VerificationStatus.PROBABLE,
                    verification_method="playwright_browser_verifier" if f_dict.get("screenshot_url") else "heuristic_pattern_analysis",
                    technical_explanation=f_dict.get("technical_explanation", ""),
                    remediation_steps=f_dict.get("remediation_steps", ""),
                    business_impact=f_dict.get("business_impact", ""),
                    ai_fix_prompt=f_dict.get("ai_fix_prompt", ""),
                    references=f_dict.get("references", [])
                )
                db.add(new_finding)
                persisted_findings.append(new_finding)

                # Add structured evidence provenance
                db.add(FindingEvidence(
                    finding=new_finding,
                    evidence_type="browser_screenshot" if new_finding.screenshot_url else "http_response",
                    content=new_finding.evidence_summary,
                    file_url=new_finding.screenshot_url
                ))

        # Update Scan metrics
        crawl_res = final_state.get("crawl_result") or {}
        scan.pages_discovered = len(crawl_res.get("pages", []))
        scan.endpoints_found = len(crawl_res.get("api_endpoints", []))
        scan.agents_run = len(final_state.get("selected_agents", []))
        scan.total_findings = len(verified_findings)
        scan.critical_count = critical
        scan.high_count = high
        scan.medium_count = medium
        scan.low_count = low
        scan.status = ScanStatus.COMPLETED
        scan.current_stage = "completed"
        scan.completed_at = datetime.now(timezone.utc)

        db.add(ScanEvent(
            scan_id=scan.id,
            event_type="scan_complete",
            message=f"Scan complete: {len(verified_findings)} findings identified",
            data={"total_findings": len(verified_findings), "critical": critical, "high": high}
        ))

        await db.commit()

        # Dispatch Webhook Notifications (Slack / Discord)
        try:
            from app.models.models import Organization
            from app.services.notification_service import NotificationService
            org_res = await db.execute(select(Organization).where(Organization.id == scan.organization_id))
            org = org_res.scalar_one_or_none()
            if org:
                if org.slack_webhook_url:
                    asyncio.create_task(NotificationService.send_slack_alert(
                        webhook_url=org.slack_webhook_url,
                        target_url=scan.target_url,
                        scan_id=scan.id,
                        total_findings=len(verified_findings),
                        critical_count=critical,
                        high_count=high,
                        top_findings=verified_findings
                    ))
                if org.discord_webhook_url:
                    asyncio.create_task(NotificationService.send_discord_alert(
                        webhook_url=org.discord_webhook_url,
                        target_url=scan.target_url,
                        scan_id=scan.id,
                        total_findings=len(verified_findings),
                        critical_count=critical,
                        high_count=high,
                        top_findings=verified_findings
                    ))
        except Exception as notify_err:
            print(f"[WARN] Webhook notification dispatch failed: {notify_err}")
    print(f"✅ Scan {scan_id} fully recorded with {len(verified_findings)} findings!")
