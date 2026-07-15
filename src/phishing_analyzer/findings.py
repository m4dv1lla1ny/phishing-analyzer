from dataclasses import dataclass
from enum import Enum
import re
from phishing_analyzer import headers
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

def analyze_headers(headers: EmailHeaders) -> list[Finding]:
    findings = []
    for check in HEADER_CHECKS:
        findings.extend(check(headers))
    return findings

_EMAIL_IN_NAME_RE = re.compile(r"[\w.+-]+@([\w.-]+\.\w+)")

BRAND_DOMAINS = {
    "paypal": {"paypal.com", "paypal.co.uk"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "live.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amaonzses.com"},
    "google": {"google.com", "gmail.com", "accounts.google.com"},
    "netflix": {"netflix.com"},
    "chase": {"chase.com"},
    "wells fargo": {"wellsfargo.com"},
    "bank of america": {"bankofamerica.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
}

FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "mail.com", "gmx.com", "yandex.com", "protonmail.com", "icloud.com", 
    "live.com", "msn.com",
}



def _registrable(domain: str) -> str:
    """Crude eTLD+1. Week 4 replaces this with tldextract, which handles multi-part
    suffixes like .co.uk properly."""
    parts = domain.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()


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

def check_reply_to(headers: EmailHeaders) -> list[Finding]:
    """Flag a Reply-To pointing at a different organization than From.

    Replies going somewhere unexpected is how an attacker keeps a
    conversation alive. But a Reply-To on a *subdomain* (support@example.com
    -> no-reply@mail.example.com) is routine, so compare registrable domains
    and only flag a genuinely different organization. LOW: common in
    legitimate mail too.
    """
    if not headers.from_addrs or not headers.reply_to:
        return []

    from_domain = headers.from_addrs[0].domain.lower()
    reply_domain = headers.reply_to[0].domain.lower()
    if not from_domain or not reply_domain:
        return []

    if _registrable(from_domain) != _registrable(reply_domain):
        return [
            Finding(
                id="header.reply_to_mismatch",
                description="Reply-To points to a different organization than From",
                severity=Severity.LOW,
                evidence=f"From={from_domain}, Reply-To={reply_domain}",
            )
        ]
    return []


def check_display_name_spoofing(headers: EmailHeaders) -> list[Finding]:
    """Detect a display name that impersonates someone the address doesn't match.
    
    Mail clients show the display name, not the address, so this is the
    deception that actually fools people. Three distinct signals:
    1. The display name contains an email address whose domain differs 
    from the real sending domain.
    2. The display name claims a known brand, but the address is on a 
    free mail provider.
    3. The display name claims a known brand sent from a domain that
    isn't one of that brand's real domains.
    """

    if not headers.from_addrs:
        return []
    
    addr = headers.from_addrs[0]
    display = (addr.display_name or "").strip()
    if not display:
        return[]
    
    from_domain  = addr.domain.lower()
    if not from_domain:
        return []
    
    findings = [] 
    display_lower = display.lower()

    embedded = _EMAIL_IN_NAME_RE.search(display)
    if embedded:
        embedded_domain = embedded.group(1).lower()
        if _registrable(embedded_domain) != _registrable(from_domain):
            findings.append(
                Finding(
                    id="header.display_name_address_mismatch",
                    description="Display name contains an email address",
                    severity=Severity.HIGH,
                    evidence=f"display name shows {embedded_domain}, actual sender is {from_domain}",
                )
            )

    for brand, legit_domains in BRAND_DOMAINS.items():
        if not re.search(rf"\b{re.escape(brand)}\b", display_lower):
            continue

        if from_domain in FREEMAIL_DOMAINS:
            findings.append(
                Finding(
                    id="header.brand_from_freemail",
                    description=f"Display name claims '{brand}' but sends from a free mail provider",
                    severity=Severity.HIGH,
                    evidence=f"display name={display!r}, sender domain={from_domain}",
                )
            )

        elif _registrable(from_domain) not in {_registrable(d) for d in legit_domains}:
            findings.append(
                Finding(
                    id="header.brand_domain_mismatch",
                    description=f"Display name claims '{brand}' but the sending domain is not one of its known domains",
                    severity=Severity.HIGH,
                    evidence=f"display name={display!r}, sender domain={from_domain}",
                )
            )
        break

    return findings

HEADER_CHECKS = [
    check_from_return_path,
    check_reply_to,
    check_display_name_spoofing,
]







