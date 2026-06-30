import re
from dataclasses import dataclass, field

PATTERNS: dict[str, re.Pattern] = {
    "ssn":         re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
    "api_key":     re.compile(r"\b(?:sk|pk|api|secret)[-_][a-zA-Z0-9]{16,}\b", re.IGNORECASE),
    "aws_key":     re.compile(r"\b(?:AKIA|AGPA|AROA|ASCA|ASIA)[A-Z0-9]{16}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "email":       re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
    "ip_address":  re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
    "phone":       re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b"),
}

# Findings with these types cause an immediate block
BLOCK_TYPES: set[str] = {"api_key", "aws_key", "private_key"}


@dataclass
class ScanResult:
    findings: list[str] = field(default_factory=list)

    @property
    def flagged(self) -> bool:
        return bool(self.findings)

    @property
    def blocked(self) -> bool:
        return any(f in BLOCK_TYPES for f in self.findings)

    @property
    def flag_reasons(self) -> str:
        return ", ".join(self.findings)


def scan_text(text: str) -> ScanResult:
    result = ScanResult()
    for name, pattern in PATTERNS.items():
        if pattern.search(text):
            result.findings.append(name)
    return result
