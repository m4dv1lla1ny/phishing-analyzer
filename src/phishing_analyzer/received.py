import re
from dataclasses import dataclass
from datetime import datetime
from email.message import EmailMessage
from email.utils import parsedate_to_datetime

_FROM_RE = re.compile(r"\bfrom\s+(\S+)", re.IGNORECASE)
_BY_RE = re.compile(r"\bby\s+(\S+)", re.IGNORECASE)
_IP_RE = re.compile(r"\[([0-9A-Fa-f:.]+)\]")


@dataclass
class ReceivedHop:
    index: int
    from_host: str | None
    by_host: str | None
    ip: str | None
    timestamp: datetime | None
    raw: str

def _parse_timestamp(value: str) -> datetime | None:
    if";" not in value:
        return None
    candidate = value.rsplit(";", 1)[1].strip()
    try:
        return parsedate_to_datetime(candidate)
    except (TypeError, ValueError):
        return None


def _parse_one(raw: str) -> ReceivedHop:
    collapsed = " ".join(raw.split())
    from_match = _FROM_RE.search(collapsed)
    by_match = _BY_RE.search(collapsed)
    ip_match = _IP_RE.search(collapsed)
    
    return ReceivedHop(
        index=-1,
        from_host=from_match.group(1) if from_match else None,
        by_host=by_match.group(1) if by_match else None,
        ip=ip_match.group(1) if ip_match else None,
        timestamp=_parse_timestamp(collapsed),
        raw=collapsed,
    )


def parse_received_chain(msg: EmailMessage) -> list[ReceivedHop]:
    """Return Received hops in chronological order (earliest sender hop first).
    
    Mail servers PREPEND their Received line, so the header list runs newest ->
    oldest. We reserve it so index 0 is the earliest hop.
    """
    raw_headers = msg.get_all("received", [])
    hops = [_parse_one(str(h)) for h in reversed(raw_headers)]
    for i, hop in enumerate(hops):
        hop.index = i
    return hops



    