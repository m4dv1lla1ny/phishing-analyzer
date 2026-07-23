"""Week 3 Day 1: parse the Authentication Results header.

The receiving mail server records the verdicts it computed for SPF, DKIM, and
DMARC in an Authentication Results (also known as A-R) header. Reading it is the easy path;
no DNS, no crypto. That's because someone already did the work. Theres only one catch:
an A-R header is only trustworthy when it was added by a server YOU trust. An attacker
can forge their own A-R line, so we surface it as reported evidence, not proof.
"""

import re
from dataclasses import dataclass, field

from phishing_analyzer.findings import Finding, Severity


_METHOD_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)")


@dataclass
class AuthResults:
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None
    authserv: str | None = None
    present: bool = False
    raw: list = field(default_factory=list)


def parse_auth_results(msg) -> AuthResults:
    headers = msg.get_all("authentication-results", [])
    if not headers:
        return AuthResults(present=False)
    
    result = AuthResults(present=True, raw=[str(h) for h in headers])

    # The reporting server id is the first token before the first ";"

    first = str(headers[0]).strip()
    result.authserv = first.split(";", 1)[0].strip() or None

    # Take the first verdict seen per method across all A-R headers

    for raw in result.raw:
        for method, verdict in _METHOD_RE.findall(raw):
            method = method.lower()
            verdict = verdict.lower()
            if getattr(result,method) is None:
                setattr(result, method, verdict)
    return result


def check_auth_results(msg) -> list[Finding]:
    ar = parse_auth_results(msg)
    if not ar.present:
        return []
    
    findings = []
    for method in ("spf", "dkim", "dmarc"):
        verdict = getattr(ar, method)
        if verdict in ("fail", "softfail", "permerror", "temperror"):
            sev = Severity.MEDIUM if verdict in ("fail", "permerror") else Severity.LOW
            findings.append(
                Finding(
                    id=f"auth.{method}_reported_{verdict}",
                    description=f"Receiving server reported {method.upper()}={verdict}",
                    severity=sev,
                    evidence=f"Authentication-Results from {ar.authserv or 'unknown server'}",
                )
            )
    return findings
    