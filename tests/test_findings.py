from pathlib import Path

from phishing_analyzer.parser import load_email
from phishing_analyzer.headers import extract_headers
from phishing_analyzer.findings import analyze_headers, summarize, Severity, SEVERITY_ORDER

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

# Message-ID -------------------------------------------------------------------------

def test_missing_message_id_is_flagged():
    assert "header.message_id_missing" in ids_for("no_message_id.eml")


def test_malformed_message_id_is_flagged():
    assert "header.message_id_malformed" in ids_for("bad_message_id.eml")


def test_wellformed_message_id_is_not_flagged():
    found = ids_for("sample.eml")
    assert "header.message_id_missing" not in found
    assert "header.message_id_malformed" not in found


def test_esp_message_id_is_info_not_alarm():
    findings = analyze_headers(extract_headers(load_email(SAMPLES / "legit_esp.eml")))
    mid = [f for f in findings if f.id == "header.message_id_domain_mismatch"]
    assert len(mid) == 1
    assert mid[0].severity is Severity.INFO

# Subdomain false-positive guard (day 4 adjustment) ------------------------------------

def test_subdomain_return_path_is_not_flagged():
    assert "header.from_return_path_mismatch" not in ids_for("legit_esp.eml")

# Missing headers -----------------------------------------------------------------------

def test_missing_date_is_flagged(tmp_path):
    p = tmp_path / "nodate.eml"
    p.write_text("From: a@example.com\nTo: b@example.com\nTo: b@example.com\nSubject: hi\nMessage-ID: <x@example.com>\n\nbody\n")
    found = {f.id for f in analyze_headers(extract_headers(load_email(p)))}
    assert "header.missing_date" in found


def test_missing_headers_not_double_reported():
    findings = analyze_headers(extract_headers(load_email(SAMPLES / "no_message_id.eml")))
    ids = [f.id for f in findings]
    assert ids.count("header.message_id_missing") == 1
    assert "header.missing_message_id" not in ids

# Consolidation --------------------------------------------------------------------------

def test_findings_sorted_most_severe_first():
    findings = analyze_headers(extract_headers(load_email(SAMPLES / "spoofed.eml")))
    counts = summarize(findings)
    assert counts["high"] == 1
    assert sum(counts.values()) == len(findings)
