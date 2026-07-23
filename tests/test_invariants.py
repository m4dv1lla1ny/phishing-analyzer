"""Week 2 Day 5: structural invariants that must hold for every check,
and a sweep proving no check raises on any sample."""
from pathlib import Path

import pytest

from phishing_analyzer.parser import load_email
from phishing_analyzer.headers import extract_headers
from phishing_analyzer.findings import analyze_headers, Finding, Severity

SAMPLES = Path(__file__).parent / "samples"
SAMPLE_FILES = sorted(SAMPLES.glob("*.eml"))


def test_samples_exist():
    assert SAMPLE_FILES, "no sample .eml files found"



@pytest.mark.parametrize("path", SAMPLE_FILES, ids=lambda p: p.name)
def test_analyze_never_raises_and_returns_list(path):
    findings = analyze_headers(extract_headers(load_email(path)))
    assert isinstance(findings, list)
    assert all(isinstance(f, Finding) for f in findings)


@pytest.mark.parametrize("path", SAMPLE_FILES, ids=lambda p: p.name)
def test_every_finding_is_well_formed(path):
    for f in analyze_headers(extract_headers(load_email(path))):
        assert f.id and isinstance(f.id, str)
        assert f.description and isinstance(f.description, str)
        assert isinstance(f.severity, Severity)



def test_clean_sample_is_completely_clean():
    assert analyze_headers(extract_headers(load_email(SAMPLES / "sample.eml"))) == []

