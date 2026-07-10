from pathlib import Path

from phishing_analyzer.parser import load_email

SAMPLES = Path(__file__).parent/"samples"

def test_loads_sample_without_error():
    msg = load_email(SAMPLES / "sample.eml")
    assert msg is not None


def test_sample_has_expected_subject():
    msg = load_email(SAMPLES / "sample.eml")
    assert len(msg.get_all("received", [])) == 2

    