from pathlib import Path

from phishing_analyzer.parser import load_email
from phishing_analyzer.headers import extract_headers
from phishing_analyzer.findings import analyze_headers

SAMPLES  = Path(__file__).parent / "samples"


def _ids(path):
    findings = analyze_headers(extract_headers(load_email(path)))
    return {f.id for f in findings}


def test_clean_email_has_no_mismatch():
    assert "header.from_return_path_mismatch" not in _ids(SAMPLES / "sample.eml")


def test_spoofed_email_flags_mismatch():
    assert "header.from_return_path_mismatch" in _ids(SAMPLES / "spoofed.eml")
