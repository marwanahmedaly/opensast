import json
import httpx
from aisast.models import Candidate, EvidenceBlock, EvidencePacket, Location
from aisast.verifier.client import VerifierClient

def test_client_parses_json_without_turning_transport_into_verdict():
    def handler(request):
        body = {"choices": [{"message": {"content": json.dumps({"candidate_id": "C1", "verdict": "VULNERABLE", "source_evidence": ["E1"], "sink_evidence": ["E1"], "sanitizer_evidence": [], "explanation": "bound", "missing_symbols": []})}}]}
        return httpx.Response(200, json=body)
    c = Candidate(candidate_id="C1", repository_sha="r", rule_id="r", cwe=89, title="t", primary_location=Location(file="x.py", line=1))
    packet = EvidencePacket(candidate=c, profile="CWE-89", prompt_version="v1", evidence=[EvidenceBlock(id="E1", file="x.py", start_line=1, end_line=1, code="x")])
    result, log = VerifierClient("http://test/v1", "gemma", transport=httpx.MockTransport(handler)).verify(packet)
    assert result.candidate_id == "C1" and result.verdict.value == "VULNERABLE" and log["attempt"] == 1

def test_client_uses_reasoning_content_when_content_is_empty():
    def handler(request):
        body = {"choices": [{"message": {"content": "", "reasoning_content": json.dumps({"candidate_id": "C1", "verdict": "NOT_VULNERABLE", "source_evidence": [], "sink_evidence": [], "sanitizer_evidence": [], "explanation": "safe", "missing_symbols": []})}}]}
        return httpx.Response(200, json=body)
    c = Candidate(candidate_id="C1", repository_sha="r", rule_id="r", cwe=89, title="t", primary_location=Location(file="x.py", line=1))
    packet = EvidencePacket(candidate=c, profile="CWE-89", prompt_version="v1", evidence=[EvidenceBlock(id="E1", file="x.py", start_line=1, end_line=1, code="x")])
    result, _ = VerifierClient("http://test/v1", "gemma", transport=httpx.MockTransport(handler)).verify(packet)
    assert result.verdict.value == "NOT_VULNERABLE"
