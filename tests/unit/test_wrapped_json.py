from aisast.verifier.client import VerifierClient

def test_client_accepts_local_channel_wrapper_around_json():
    parsed = VerifierClient._parse_json('<|channel>thought\n<channel|>{"candidate_id":"c","verdict":"VULNERABLE"}')
    assert parsed["candidate_id"] == "c"
