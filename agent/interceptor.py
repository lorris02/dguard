"""
mitmproxy addon — loaded via: mitmdump -s agent/interceptor.py
Scans outbound requests to AI services and blocks or reports them.
"""
import json
import re

from mitmproxy import http

from agent.ai_targets import is_ai_target
from agent.config import BLOCK_ENABLED, DEVICE_ID
from agent.reporter import report_event

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

        await report_event(
            device_id=DEVICE_ID,
            destination=destination,
            content=body,
            flagged=flagged,
            flag_reasons=flag_reasons,
            blocked=blocked and BLOCK_ENABLED,
        )

        if blocked and BLOCK_ENABLED:
            flow.response = http.Response.make(
                400,
                json.dumps({
                    "error": "Blocked by DGuard agent",
                    "reasons": findings,
                }),
                {"Content-Type": "application/json"},
            )


addons = [DGuardInterceptor()]
