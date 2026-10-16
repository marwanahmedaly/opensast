import httpx
import base64
from pathlib import Path
from aisast.models import Candidate, EvidenceBlock, EvidencePacket, Location
from aisast.verifier.client import VerifierClient
from aisast.verifier.schemas import VerificationError

def test_invalid_json_is_retried_once_then_is_system_error():
    calls = {"count": 0}
    wire_events = []
    def handler(request):
        calls["count"] += 1
        return httpx.Response(200, json={"choices": [{"message": {"content": "not json"}}]})
    c = Candidate(candidate_id="C", repository_sha="r", rule_id="r", cwe=89, title="t", primary_location=Location(file="x.py", line=1))
    packet = EvidencePacket(candidate=c, profile="CWE-89", prompt_version="v1", evidence=[EvidenceBlock(id="E1", file="x.py", start_line=1, end_line=1, code="x")])
    client = VerifierClient("http://test/v1", "gemma", max_retries=99, transport=httpx.MockTransport(handler), attempt_sink=wire_events.append)
    try:
        client.verify(packet)
    except VerificationError as exc:
        assert len(exc.attempt_log) == 2
        assert all(item["status"] == "error" for item in exc.attempt_log)
        assert exc.prompt and exc.prompt_hash
        assert all(item["raw_response"] for item in exc.attempt_log)
    else:
        raise AssertionError("malformed output unexpectedly produced a result")
    assert calls["count"] == 2
    phases = [item["phase"] for item in wire_events]
    assert phases == [
        "request_started", "response_received", "attempt_failed",
        "request_started", "response_received", "attempt_failed",
    ]
    raw_response = base64.b64decode(wire_events[1]["raw_response_base64"])
    assert b"not json" in raw_response


def test_missing_verdict_is_retried_and_schema_requested():
    calls = {"count": 0}
    def handler(request):
        calls["count"] += 1
        payload = __import__("json").loads(request.content)
        assert payload["response_format"]["type"] == "json_object"
        assert payload["response_format"]["schema"]["properties"]["verdict"]["enum"]
        assert payload["response_format"]["schema"]["properties"]["candidate_id"]["const"] == "C"
        assert payload["response_format"]["schema"]["properties"]["cwe"]["const"] == 89
        for field in ("source_evidence", "sink_evidence", "sanitizer_evidence"):
            assert payload["response_format"]["schema"]["properties"][field]["items"]["enum"] == ["E1"]
        content = {"candidate_id": "C"} if calls["count"] == 1 else {"candidate_id": "C", "verdict": "UNRESOLVED"}
        return httpx.Response(200, json={"choices": [{"message": {"content": __import__("json").dumps(content)}}]})
    c = Candidate(candidate_id="C", repository_sha="r", rule_id="r", cwe=89, title="t", primary_location=Location(file="x.py", line=1))
    packet = EvidencePacket(candidate=c, profile="CWE-89", prompt_version="v1", evidence=[EvidenceBlock(id="E1", file="x.py", start_line=1, end_line=1, code="x")])
    result, log = VerifierClient("http://test/v1", "gemma", transport=httpx.MockTransport(handler)).verify(packet)
    assert calls["count"] == 2 and log["attempt"] == 2 and result.verdict.value == "UNRESOLVED"
    assert [item["status"] for item in log["attempt_log"]] == ["error", "success"]


def test_timeout_is_logged_as_operational_failure_and_prompt_is_preserved():
    events = []
    def handler(request):
        raise httpx.ReadTimeout("synthetic timeout")

    c = Candidate(candidate_id="C", repository_sha="r", rule_id="r", cwe=78,
                  title="t", primary_location=Location(file="x.py", line=1))
    packet = EvidencePacket(
        candidate=c, profile="CWE-78", prompt_version="v1",
        evidence=[EvidenceBlock(id="E1", file="x.py", start_line=1,
                                end_line=1, code="x")],
    )
    client = VerifierClient(
        "http://test/v1", "gemma", max_retries=0,
        transport=httpx.MockTransport(handler), attempt_sink=events.append,
    )
    try:
        client.verify(packet)
    except VerificationError as exc:
        assert exc.prompt and exc.prompt_hash
        assert exc.attempt_log[0]["timeout"] is True
        assert exc.attempt_log[0]["error_type"] == "ReadTimeout"
    else:
        raise AssertionError("timeout unexpectedly produced a model result")
    assert [item["phase"] for item in events] == [
        "request_started", "attempt_failed",
    ]
