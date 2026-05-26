from datetime import UTC, datetime


def generate_block_page(incident_id: str, client_ip: str, category: str) -> str:
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>403 Forbidden - KALKI Security Mitigation Active</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #010103; color: #e4e1e9; padding: 10% 5%; text-align: center; }}
            .container {{ max-width: 600px; margin: 0 auto; background: rgba(15, 23, 42, 0.45); backdrop-filter: blur(12px); padding: 40px; border-radius: 8px; border: 1px solid rgba(255, 0, 60, 0.3); border-top: 4px solid #ff003c; box-shadow: 0 4px 20px rgba(255, 0, 60, 0.15); }}
            h1 {{ color: #ff003c; font-size: 24px; margin-bottom: 10px; font-weight: 700; letter-spacing: -0.02em; }}
            p {{ color: #b9cacb; font-size: 14px; line-height: 1.6; }}
            .details {{ background: #0e0e13; padding: 18px; border-radius: 4px; font-family: monospace; font-size: 12px; text-align: left; margin-top: 25px; border: 1px solid rgba(255,255,255,0.05); }}
            .uuid {{ color: #00f2fe; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>KALKI SECURITY MITIGATION BLOCK ACTIVE</h1>
            <p>Your request was intercepted and dropped because it matched active threat signature profiles for <strong>{category}</strong>.</p>
            <div class="details">
                <div>Incident Reference ID: <span class="uuid">{incident_id}</span></div>
                <div>Origin Node IP: {client_ip}</div>
                <div>Scrubbing Posture: ACTIVE_BLOCK</div>
                <div>Timestamp Context: {datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")} UTC</div>
            </div>
        </div>
    </body>
    </html>
    """  # noqa: E501
