from email import policy 
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path

def load_email(path: Path) -> EmailMessage:
    """Read and parse an .eml file into an EmailMessage.

    Reads bytes (not text) so the parser can honor the message's own 
    declared encodings and decode RFC 2047 encoded-word headers
    (e.g. =?utf-8?B?...?=) into clean Unicode automatically.
    """ 
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)
    
    