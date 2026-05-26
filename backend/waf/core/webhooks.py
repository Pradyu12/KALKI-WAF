import os
from typing import Any

import httpx

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")


async def send_alert(event: dict[str, Any]) -> None:
    if SLACK_WEBHOOK_URL:
        await _send_slack(event)
    if DISCORD_WEBHOOK_URL:
        await _send_discord(event)


async def _send_slack(event: dict[str, Any]) -> None:
    color = "#ff003c" if event.get("action") == "Blocked" else "#ffcc00"
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"KALKI WAF Alert: {event.get('threat_category', 'Unknown')}"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Incident ID:*\n{event.get('incident_id', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Source IP:*\n{event.get('source_ip', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Category:*\n{event.get('threat_category', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Action:*\n{event.get('action', 'N/A')}"},
            ],
        },
        {
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"Timestamp: {event.get('timestamp', 'N/A')}"},
            ],
        },
    ]
    payload = {"attachments": [{"color": color, "blocks": blocks}]}
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(SLACK_WEBHOOK_URL, json=payload)
    except Exception as e:
        print(f"[WEBHOOK] Slack notification failed: {e}")


async def _send_discord(event: dict[str, Any]) -> None:
    color = 0xFF003C if event.get("action") == "Blocked" else 0xFFCC00
    embed = {
        "title": f"KALKI WAF Alert: {event.get('threat_category', 'Unknown')}",
        "color": color,
        "fields": [
            {"name": "Incident ID", "value": event.get("incident_id", "N/A"), "inline": True},
            {"name": "Source IP", "value": event.get("source_ip", "N/A"), "inline": True},
            {"name": "Category", "value": event.get("threat_category", "N/A"), "inline": True},
            {"name": "Action", "value": event.get("action", "N/A"), "inline": True},
        ],
        "footer": {"text": f"Timestamp: {event.get('timestamp', 'N/A')}"},
    }
    payload = {"embeds": [embed]}
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(DISCORD_WEBHOOK_URL, json=payload)
    except Exception as e:
        print(f"[WEBHOOK] Discord notification failed: {e}")
