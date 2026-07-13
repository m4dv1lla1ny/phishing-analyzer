from dataclasses import dataclass
from enum import Enum

from phishing_analyzer.headers import EmailHeaders

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

@dataclass
class Finding:
    id: str
    description: str
    severity: Severity
    evidence: str = ""


def check_from_return_path(headers: EmailHeaders)-> list[Finding]:
    """Flag when the visible From domain that differs from the Return-Path
    (envelop sender) domain. On its own this is suspicious, not damning:
    some legitimate bulk mail does it, which is why it's MEDIUM."""
    if not headers.from_addrs or not headers.return_path:
        return []
    
    from_domain = headers.from_addrs[0].domain.lower()
    rp_domain = headers.return_path[0].domain.lower()

    if from_domain and rp_domain and from_domain != rp_domain:
        return [
            Finding(
                id="header.from_return_path_mismatch",
                description="From domain does not match Return-Path (envelope sender) domain",
                severity=Severity.MEDIUM,
                evidence=f"From={from_domain}, Return-Path={rp_domain}",
                )
        ]
    return []

HEADER_CHECKS = [
    check_from_return_path
]

def analyze_headers(headers: EmailHeaders) -> list[Finding]:
    findings = []
    for check in HEADER_CHECKS:
        findings.extend(check(headers))
    return findings
