from pathlib import Path

from phishing_analyzer.parser import load_email
from phishing_analyzer.headers import extract_headers

SAMPLES = Path(__file__).parent / "samples"


def test_from_address_and_domain():
    headers = extract_headers(load_email(SAMPLES / "sample.eml"))
    assert headers.from_addrs[0].address == "support@example.com"
    assert headers.from_addrs[0].domain == "example.com"


def test_display_name_parsed():
    headers = extract_headers(load_email(SAMPLES / "sample.eml"))
    assert headers.from_addrs[0].display_name == "Example Support"

def test_date_is_timezone_aware():
    headers = extract_headers(load_email(SAMPLES / "sample.eml"))
    assert headers.date is not None
    assert headers.date.tzinfo is not None
    