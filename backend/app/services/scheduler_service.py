"""
Scheduled / Continuous Scanning Engine
Manages periodic automated scans for targets configured with recurring schedules (daily / weekly).
"""
import asyncio
from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from app.core.database import AsyncSessionLocal
from app.models.models import Project, Scan, ScanStatus, Domain, OrganizationMember
from app.worker.tasks import _run_scan_async


class ScanScheduler:
    @staticmethod
    async def run_due_scans() -> int:
        """Find all projects due for a scheduled security scan and dispatch them."""
        now = datetime.now(timezone.utc)
        dispatched_count = 0

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Project).where(
                    Project.is_active == True,
                    Project.scan_schedule.in_(["daily", "weekly"])
                )
            )
            projects = result.scalars().all()

            for proj in projects:
                is_due = False
                if not proj.last_scanned_at:
                    is_due = True
                elif proj.next_scan_at:
                    next_at = proj.next_scan_at if proj.next_scan_at.tzinfo else proj.next_scan_at.replace(tzinfo=timezone.utc)
                    if next_at <= now:
                        is_due = True

                if is_due:
                    # Create new scheduled scan
                    scan = Scan(
                        project_id=proj.id,
                        organization_id=proj.organization_id,
                        target_url=proj.base_url,
                        status=ScanStatus.QUEUED,
                        current_stage="queued"
                    )
                    db.add(scan)
                    await db.commit()
                    await db.refresh(scan)

                    # Update project schedule dates
                    interval = timedelta(days=1) if proj.scan_schedule == "daily" else timedelta(weeks=1)
                    proj.last_scanned_at = now
                    proj.next_scan_at = now + interval
                    await db.commit()

                    # Dispatch scan asynchronously
                    asyncio.create_task(_run_scan_async(scan.id))
                    dispatched_count += 1
                    print(f"⏰ [Scheduler] Dispatched recurring {proj.scan_schedule} scan for '{proj.name}' (ID: {scan.id})")

        return dispatched_count


async def start_scheduler_background_loop():
    """Background loop that checks for due recurring scans every 60 seconds."""
    while True:
        try:
            await ScanScheduler.run_due_scans()
        except Exception as e:
            print(f"[Scheduler Loop Error] {e}")
        await asyncio.sleep(60)
