"""
Notification Service — Slack & Discord Webhook Alerting
Sends rich security alert cards when scans identify critical or high vulnerabilities.
"""
from typing import Dict, Any, List, Optional
import httpx


class NotificationService:
    @staticmethod
    async def send_slack_alert(
        webhook_url: str,
        target_url: str,
        scan_id: str,
        total_findings: int,
        critical_count: int,
        high_count: int,
        top_findings: List[Dict[str, Any]]
    ) -> bool:
        """Send rich formatted alert to Slack incoming webhook."""
        if not webhook_url:
            return False

        sev_emoji = "🚨" if critical_count > 0 else "⚠️" if high_count > 0 else "✅"
        header_text = f"{sev_emoji} APT Agents Security Alert: {target_url}"

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": header_text, "emoji": True}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:* `{target_url}`"},
                    {"type": "mrkdwn", "text": f"*Total Findings:* *{total_findings}*"},
                    {"type": "mrkdwn", "text": f"*Critical:* *{critical_count}*"},
                    {"type": "mrkdwn", "text": f"*High:* *{high_count}*"}
                ]
            }
        ]

        if top_findings:
            findings_bullets = ""
            for f in top_findings[:3]:
                sev = f.get("severity", "MEDIUM").upper()
                findings_bullets += f"• *[{sev}]* {f.get('title')}\n"
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Top Critical Vulnerabilities:*\n{findings_bullets}"}
            })

        payload = {"blocks": blocks}

        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                res = await client.post(webhook_url, json=payload)
                return res.status_code == 200
        except Exception:
            return False

    @staticmethod
    async def send_discord_alert(
        webhook_url: str,
        target_url: str,
        scan_id: str,
        total_findings: int,
        critical_count: int,
        high_count: int,
        top_findings: List[Dict[str, Any]]
    ) -> bool:
        """Send rich embed alert to Discord incoming webhook."""
        if not webhook_url:
            return False

        color = 14427670 if critical_count > 0 else 15105570 if high_count > 0 else 3066993

        fields = [
            {"name": "Target", "value": f"`{target_url}`", "inline": True},
            {"name": "Total Findings", "value": str(total_findings), "inline": True},
            {"name": "Critical / High", "value": f"🔴 {critical_count} | 🟠 {high_count}", "inline": True}
        ]

        if top_findings:
            bullets = "\n".join([f"• **[{f.get('severity', 'MEDIUM').upper()}]** {f.get('title')}" for f in top_findings[:3]])
            fields.append({"name": "Top Findings", "value": bullets, "inline": False})

        embed = {
            "title": f"🛡️ APT Agents Scan Complete: {target_url}",
            "description": f"Automated 41-agent security assessment completed for `{target_url}`.",
            "color": color,
            "fields": fields,
            "footer": {"text": f"Scan ID: {scan_id[:8]} • Autonomous AI Pentesting"}
        }

        payload = {"embeds": [embed]}

        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                res = await client.post(webhook_url, json=payload)
                return res.status_code in (200, 204)
        except Exception:
            return False
