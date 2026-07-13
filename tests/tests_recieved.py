from pathlib import Path

from phishing_analyzer.parser import load_email
from phishing_analyzer.received import parse_received_chain

SAMPLES = Path(__file__).parent / "samples"

def test_two_hops_parsed():
    hops = parse_received_chain(load_email(SAMPLES / "sample.eml"))
    assert len(hops) == 2

def test_chain_is_chronological():
    hops = parse_received_chain(load_email(SAMPLES / "sample.eml"))
    assert hops[0].index == 0
    assert hops[1].index <= hops[1].timestamp

def test_hop_extracts_by_host():
    hops = parse_received_chain(load_email(SAMPLES / "sample.eml"))
    assert any(h.by_host for h in hops)

    