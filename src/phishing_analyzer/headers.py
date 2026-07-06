from dataclasses import dataclass
from datetime import datetime
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import getaddresses

@dataclass
class ParsedAddress:
    display_name : str
    address : str       #full address (e.g. support@example.com)
    domain : str        #domain part of the address (e.g. example.com)

    @classmethod
    def from_address(cls, addr: Address)->"ParsedAddress":
        return cls(
            display_name=addr.display_name,
            address=addr.addr_spec,
            domain=addr.domain
        )
    
@dataclass
class EmailHeaders:
    from_addrs: list[ParsedAddress]
    to_addrs: list[ParsedAddress]
    reply_to: list[ParsedAddress]
    return_path: list[ParsedAddress]
    subject: str | None
    date: datetime | None  
    #date becomes a real timezone-aware datetime object, 
    # not a string, so later checks can do actual date math on it.
    message_id: str | None

def _extract_addresses(msg: EmailMessage, name: str) -> list[ParsedAddress]:
    header = msg[name]
    if header is None:
        return []
    
    # Address headers (From/To/Reply-To) expose structured .addresses
    # under the default policy.
    # Code detects if the header is a structured address header and extracts the addresses if so. 
    # If not, it falls back to parsing the header as plain text using getaddresses.
    # This is a sort of "fallback" mechanism to handle headers that may not be registered as structured address 
    # headers in the email library, such as the Return-Path header. 
    addresses = getattr(header, "addresses", None)
    if addresses is not None:
        return [ParsedAddress.from_address(a) for a in addresses]
    
    # Return-Path isn't registered as an address header, so it arrives
    # as plain text like "<bounce@example.com>". Parse it manually.
    result = []
    for display, addr in getaddresses([str(header)]):
        if addr:
            domain = addr.split("@", 1)[1] if "@" in addr else ""
            result.append(ParsedAddress(display_name=display, address=addr, domain=domain))
            return result


def _extract_str(msg: EmailMessage, name: str) -> str | None:
    header = msg[name]
    return str(header) if header is not None else None


def extract_headers(msg: EmailMessage) -> EmailHeaders: 
    date_header = msg["date"]
    date = getattr(date_header, "datetime", None) if date_header is not None else None

    return EmailHeaders(
        from_addrs=_extract_addresses(msg, "from"),
        to_addrs=_extract_addresses(msg, "to"),
        reply_to=_extract_addresses(msg, "reply-to"),
        return_path=_extract_addresses(msg, "return-path"),
        subject=_extract_str(msg, "subject"),
        date=date,
        message_id=_extract_str(msg, "message-id")
    )
