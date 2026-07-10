from pathlib import Path

from phishing_analyzer.corpus import scan_file

def test_clean_email_parses(tmp_path: Path):
    p = tmp_path / "good"
    p.write_text("From: a@b.com/nSubject: hi\n\nobody\n")
    assert scan_file(p).status == "parsed"


def test_empty_file_is_empty(tmp_path: Path):
    p = tmp_path / "empty"
    p.write_bytes(b"")
    assert scan_file(p).status == "empty"


def test_garbage_is_empty_not_error(tmp_path: Path):
    p = tmp_path / "garbage"
    p.write_bytes(b"\x00\x01\x02 not an email at all \xff\xfe")
    assert scan_file(p).status == "empty"


def test_parsed_but_no_from_is_flagged(tmp_path: Path):
    p = tmp_path / "nofrom"
    p.write_text("To: a@b.com\nSubject: hi\n\nobody\n")
    result = scan_file(p)
    assert result.status == "parsed"
    assert "no From" in result.detail

