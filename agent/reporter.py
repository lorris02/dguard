from datetime import datetime, timezone

import httpx

from agent.config import DGUARD_SERVER


def report_event(
    device_id: str,
    destination: str,
    content: str,
    flagged: bool,
    flag_reasons: str,
    blocked: bool,
) -> None:
    try:
        httpx.post(
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
            timeout=5.0,
        )
    except Exception:
        pass  # reporting failure must never break the proxy
