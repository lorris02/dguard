from datetime import datetime, timezone

import httpx

from agent.config import DGUARD_SERVER, SERVER_API_KEY


async def report_event(
    device_id: str,
    destination: str,
    content: str,
    flagged: bool,
    flag_reasons: str,
    blocked: bool,
) -> None:
    headers = {}
    if SERVER_API_KEY:
        headers["X-DGuard-Key"] = SERVER_API_KEY

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(
                f"{DGUARD_SERVER}/agent/report",
                json={
                    "device_id": device_id,
                    "destination": destination,
                    "content": content,
                    "flagged": flagged,
                    "flag_reasons": flag_reasons,
                    "blocked": blocked,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
                headers=headers,
            )
    except Exception:
        pass  # reporting failure must never break the proxy
