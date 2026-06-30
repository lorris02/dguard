from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from app.config import ANTHROPIC_API_KEY, LOG_FULL_CONTENT
from app.db.models import get_connection
from app.scanner import scan_text

router = APIRouter()

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"


def _extract_prompt(body: dict) -> str:
    """Pull all text content from the messages array into one string for scanning."""
    parts = []
    for msg in body.get("messages", []):
        content = msg.get("content", "")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    parts.append(block.get("text", ""))
    return "\n".join(parts)


def _log_request(
    user_id: str | None,
    model: str | None,
    prompt_text: str,
    response_text: str,
    flagged: bool,
    flag_reasons: str,
    blocked: bool,
    status: str,
) -> int:
    with get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO requests
                (timestamp, user_id, model, prompt_text, response_text,
                 flagged, flag_reasons, blocked, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                user_id,
                model,
                prompt_text if LOG_FULL_CONTENT else None,
                response_text if LOG_FULL_CONTENT else None,
                int(flagged),
                flag_reasons,
                int(blocked),
                status,
            ),
        )
        conn.commit()
        return cur.lastrowid


@router.post("/v1/messages")
async def proxy_messages(
    request: Request,
    x_user_id: str | None = Header(default=None),
    x_dguard_confirm: str | None = Header(default=None),
):
    body: dict = await request.json()
    model: str | None = body.get("model")
    prompt_text = _extract_prompt(body)

    scan = scan_text(prompt_text)

    if scan.blocked:
        _log_request(
            user_id=x_user_id,
            model=model,
            prompt_text=prompt_text,
            response_text="",
            flagged=True,
            flag_reasons=scan.flag_reasons,
            blocked=True,
            status="blocked",
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Request blocked by DGuard",
                "reasons": scan.findings,
            },
        )

    # Soft findings: require explicit confirmation before forwarding
    if scan.flagged and x_dguard_confirm != "yes":
        _log_request(
            user_id=x_user_id,
            model=model,
            prompt_text=prompt_text,
            response_text="",
            flagged=True,
            flag_reasons=scan.flag_reasons,
            blocked=False,
            status="pending_confirmation",
        )
        raise HTTPException(
            status_code=451,
            detail={
                "error": "Sensitive data detected — resend with header X-DGuard-Confirm: yes to proceed",
                "findings": scan.findings,
            },
        )

    # Forward to Anthropic
    headers = {
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            upstream = await client.post(ANTHROPIC_URL, json=body, headers=headers)
        upstream.raise_for_status()
        response_body = upstream.json()
        response_text = response_body.get("content", [{}])[0].get("text", "")
        status = "confirmed" if scan.flagged else "success"
    except httpx.HTTPStatusError as exc:
        response_text = exc.response.text
        status = f"upstream_error_{exc.response.status_code}"
        _log_request(
            user_id=x_user_id,
            model=model,
            prompt_text=prompt_text,
            response_text=response_text,
            flagged=scan.flagged,
            flag_reasons=scan.flag_reasons,
            blocked=False,
            status=status,
        )
        return JSONResponse(status_code=exc.response.status_code, content=exc.response.json())

    _log_request(
        user_id=x_user_id,
        model=model,
        prompt_text=prompt_text,
        response_text=response_text,
        flagged=scan.flagged,
        flag_reasons=scan.flag_reasons,
        blocked=False,
        status=status,
    )

    return JSONResponse(status_code=200, content=response_body)
