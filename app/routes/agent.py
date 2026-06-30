from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.auth import require_api_key
from app.config import LOG_FULL_CONTENT
from app.db.models import get_connection

router = APIRouter(dependencies=[Depends(require_api_key)])


class AgentReport(BaseModel):
    device_id: str
    destination: str
    content: str
    flagged: bool
    flag_reasons: str
    blocked: bool
    timestamp: str


@router.post("/agent/report", status_code=201)
def receive_report(report: AgentReport):
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO agent_events
                (timestamp, device_id, destination, content, flagged, flag_reasons, blocked)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report.timestamp,
                report.device_id,
                report.destination,
                report.content if LOG_FULL_CONTENT else None,
                int(report.flagged),
                report.flag_reasons,
                int(report.blocked),
            ),
        )
        conn.commit()
    return {"status": "recorded"}


@router.get("/agent/logs")
def list_agent_logs(
    limit: int = Query(default=50, le=500),
    flagged_only: bool = Query(default=False),
    blocked_only: bool = Query(default=False),
    device_id: str | None = Query(default=None),
):
    query = "SELECT id, timestamp, device_id, destination, flagged, flag_reasons, blocked FROM agent_events"
    conditions = []
    params: list = []

    if flagged_only:
        conditions.append("flagged = 1")
    if blocked_only:
        conditions.append("blocked = 1")
    if device_id:
        conditions.append("device_id = ?")
        params.append(device_id)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()

    return {
        "count": len(rows),
        "results": [
            {
                "id": r["id"],
                "timestamp": r["timestamp"],
                "device_id": r["device_id"],
                "destination": r["destination"],
                "flagged": bool(r["flagged"]),
                "flag_reasons": r["flag_reasons"],
                "blocked": bool(r["blocked"]),
            }
            for r in rows
        ],
    }


@router.get("/agent/logs/{event_id}")
def get_agent_log(event_id: int):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM agent_events WHERE id = ?", (event_id,)
        ).fetchone()

    if row is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Agent event not found")

    detail = dict(row)
    detail["flagged"] = bool(detail["flagged"])
    detail["blocked"] = bool(detail["blocked"])
    return detail
