"""
mitmproxy addon — loaded via: mitmdump -s agent/interceptor.py
Scans outbound requests to AI services and blocks or reports them.
"""
import asyncio
import json
import re

from mitmproxy import http

from agent.ai_targets import is_ai_target
from agent.config import BLOCK_ENABLED, DEVICE_ID
from agent.reporter import report_event

_confirm_lock = asyncio.Lock()

# --- inline scanner so agent is self-contained and deployable independently ---

_PATTERNS: dict[str, re.Pattern] = {
    "ssn":         re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
    "api_key":     re.compile(r"\b(?:sk|pk|api|secret)[-_][a-zA-Z0-9]{16,}\b", re.IGNORECASE),
    "aws_key":     re.compile(r"\b(?:AKIA|AGPA|AROA|ASCA|ASIA)[A-Z0-9]{16}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "email":       re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
    "ip_address":  re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
    "phone":       re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b"),
}

_BLOCK_TYPES: set[str] = {"api_key", "aws_key", "private_key"}


def _scan(text: str) -> tuple[list[str], bool, bool]:
    findings = [name for name, pat in _PATTERNS.items() if pat.search(text)]
    flagged = bool(findings)
    blocked = any(f in _BLOCK_TYPES for f in findings)
    return findings, flagged, blocked


class DGuardInterceptor:
    async def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        if not is_ai_target(host):
            return

        try:
            body = flow.request.get_text(strict=False) or ""
        except Exception:
            body = ""

        findings, flagged, blocked = _scan(body)
        flag_reasons = ", ".join(findings)
        destination = f"{flow.request.scheme}://{host}{flow.request.path}"

        # Hard block: api keys, aws keys, private keys — no prompt
        if blocked and BLOCK_ENABLED:
            await report_event(
                device_id=DEVICE_ID,
                destination=destination,
                content=body,
                flagged=True,
                flag_reasons=flag_reasons,
                blocked=True,
            )
            flow.response = http.Response.make(
                400,
                json.dumps({"error": "Blocked by DGuard agent", "reasons": findings}),
                {"Content-Type": "application/json"},
            )
            return

        # Soft findings: ask the user before forwarding
        if flagged and BLOCK_ENABLED:
            loop = asyncio.get_event_loop()
            async with _confirm_lock:
                answer = await loop.run_in_executor(
                    None,
                    input,
                    f"\n[DGuard] Sensitive data detected in request to {destination}\n"
                    f"  Found: {flag_reasons}\n"
                    f"  Do you want to send this? [yes/no]: ",
                )
            confirmed = answer.strip().lower() == "yes"
            await report_event(
                device_id=DEVICE_ID,
                destination=destination,
                content=body,
                flagged=True,
                flag_reasons=flag_reasons,
                blocked=not confirmed,
            )
            if not confirmed:
                flow.response = http.Response.make(
                    400,
                    json.dumps({"error": "Blocked by DGuard agent — user declined", "reasons": findings}),
                    {"Content-Type": "application/json"},
                )
            return

        await report_event(
            device_id=DEVICE_ID,
            destination=destination,
            content=body,
            flagged=False,
            flag_reasons="",
            blocked=False,
        )


addons = [DGuardInterceptor()]
