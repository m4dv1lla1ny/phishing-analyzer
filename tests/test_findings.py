from pathlib import Path

from phishing_analyzer.parser import load_email
from phishing_analyzer.headers import extract_headers
from phishing_analyzer.findings import analyze_headers

SAMPLES  = Path(__file__).parent / "samples"

def ids_for(name):
    return {f.id for f in analyze_headers(extract_headers(load_email(SAMPLES / name)))}

# From/Return-Path ----------------------------------------------------------------

def test_clean_email_has_no_mismatch():
    assert "header.from_return_path_mismatch" not in ids_for(SAMPLES / "sample.eml")


def test_spoofed_email_flags_mismatch():
    assert "header.from_return_path_mismatch" in ids_for(SAMPLES / "spoofed.eml")

# Reply-To--------------------------------------------------------------------------

def test_subdomain_reply_to_is_not_flagged():
    assert "header.brand_domain_mismatch" not in ids_for("legit_subdomain_replyto.eml")

def test_foreign_reply_to_is_flagged():
    assert "header.brand_domain_mismatch" in ids_for("spoofed.eml")


# Display-name spoofing-------------------------------------------------------------

def test_legit_brand_from_own_domain_is_clean():
    assert ids_for("legit_paypal.eml") == set()

def test_brand_claim_from_freemail_is_flagged():
    assert "header.brand_from_freemail" in ids_for("freemail_brand.eml")

def test_brand_claim_from_wrong_domain_is_flagged():
    assert "header.brand_domain_mismatch" in ids_for("spoofed.eml")

def test_address_in_display_name_mismatch_is_flagged():
    assert "header.display_name_address_mismatch" in ids_for("name_shows_other_domain.eml")

def test_no_display_name_produces_no_spoofing_finding(tmp_path: Path):
    p = tmp_path / "plain.eml"
    p.write_text("From a@example.com\nTo: b@example.com\nSubject: hi\n\nbody\n")
    found = {f.id for f in analyze_headers(extract_headers(load_email(p)))}
    assert not any(i.startswith("headerbrand")for i in found )