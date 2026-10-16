import json
import hashlib
from pathlib import Path
from aisast.evaluation.experiment import run_experiment, run_repeated_experiments
from aisast.models import Candidate, Location, VerificationResult, Verdict
from aisast.evaluation.error_analysis import classify_owasp_misses

def test_experiment_a_writes_reproducible_artifacts(tmp_path: Path):
    candidate = Candidate(candidate_id="C", repository_sha="r", rule_id="r", cwe=89, title="t", primary_location=Location(file="vulnerable.py", line=4))
    result = run_experiment("A", Path("tests/fixtures/cwe89"), [candidate], tmp_path, repository_sha="r")
    assert result["experiment"] == "A"
    assert (tmp_path / "manifest.json").exists() and (tmp_path / "metrics.json").exists()
    assert json.loads((tmp_path / "final_findings.jsonl").read_text())["verdict"] == "VULNERABLE"


def test_repeated_experiment_writes_aggregate_summary(tmp_path: Path):
    candidate = Candidate(candidate_id="C", repository_sha="r", rule_id="r", cwe=89, title="t", primary_location=Location(file="vulnerable.py", line=4))
    result = run_repeated_experiments("G1", Path("tests/fixtures/cwe89"), [candidate], tmp_path, 2, labels={"C": "vulnerable"})
    assert result["repetitions"] == 2
    assert result["mean"]["recall"] == 1.0
    assert (tmp_path / "repeated-summary.json").exists()


def test_owasp_false_negative_origin_separates_generation_and_verification():
    candidate = {"candidate_id": "C", "cwe": 22, "primary_location": {"file": "BenchmarkTest00001.py"}}
    findings = [{**candidate, "location": candidate["primary_location"], "verdict": "NOT_VULNERABLE"}]
    expected = [{"test_name": "BenchmarkTest00001", "cwe": 22, "vulnerable": True}]
    result = classify_owasp_misses([candidate], findings, expected)
    assert result["counts"] == {"NO_SCANNER_CANDIDATE": 0, "GEMMA_REJECTED_TRUE_CANDIDATE": 1}


def test_plan3_requires_frozen_candidates_and_conservative_policy(tmp_path: Path):
    class Client:
        model, temperature, top_p, max_tokens, max_retries = "fake", 0.0, 1.0, 100, 1
        def verify(self, packet, guided=True):
            return VerificationResult(candidate_id=packet.candidate.candidate_id,
                                      verdict=Verdict.NOT_VULNERABLE, explanation="looks safe"), {}
        @staticmethod
        def system_error(candidate_id, explanation):
            return VerificationResult(candidate_id=candidate_id, verdict=Verdict.SYSTEM_ERROR, explanation=explanation)

    candidate = Candidate(candidate_id="C", repository_sha="r", rule_id="r", cwe=89, title="t", primary_location=Location(file="vulnerable.py", line=4))
    serialized = json.dumps(candidate.model_dump(), sort_keys=True) + "\n"
    frozen = {"stage_gate_passed": True, "candidate_sha256": hashlib.sha256(serialized.encode()).hexdigest()}
    result = run_experiment("P3", Path("tests/fixtures/cwe89"), [candidate], tmp_path, client=Client(), scan_manifest=frozen)
    assert result["experiment"] == "P3"
    assert json.loads((tmp_path / "final_findings.jsonl").read_text())["verdict"] == "UNRESOLVED"


def test_plan3_resume_preserves_completed_calls(tmp_path: Path):
    class Client:
        model, temperature, top_p, max_tokens, max_retries = "fake", 0.0, 1.0, 100, 1
        def __init__(self):
            self.calls = []
        def verify(self, packet, guided=True):
            self.calls.append(packet.candidate.candidate_id)
            return VerificationResult(candidate_id=packet.candidate.candidate_id, cwe=89,
                                      verdict=Verdict.NOT_VULNERABLE), {}
        @staticmethod
        def system_error(candidate_id, explanation):
            return VerificationResult(candidate_id=candidate_id, verdict=Verdict.SYSTEM_ERROR, explanation=explanation)

    candidates = [Candidate(candidate_id=name, repository_sha="r", rule_id="r", cwe=89, title="t",
                            primary_location=Location(file="vulnerable.py", line=line))
                  for name, line in (("A", 4), ("B", 5))]
    serialized = "\n".join(json.dumps(candidate.model_dump(), sort_keys=True) for candidate in candidates) + "\n"
    frozen = {"stage_gate_passed": True, "candidate_sha256": hashlib.sha256(serialized.encode()).hexdigest()}
    client = Client()
    run_experiment("P3", Path("tests/fixtures/cwe89"), candidates, tmp_path, client=client, scan_manifest=frozen)
    for name in ("final_findings.jsonl", "responses.jsonl", "prompts.jsonl"):
        path = tmp_path / name
        lines = [line for line in path.read_text().splitlines() if json.loads(line)["candidate_id"] == "A"]
        path.write_text("\n".join(lines) + "\n")
    client.calls.clear()
    result = run_experiment("P3", Path("tests/fixtures/cwe89"), candidates, tmp_path,
                            client=client, scan_manifest=frozen, resume=True)
    assert client.calls == ["B"]
    assert result["findings"] == 2
    assert len((tmp_path / "responses.jsonl").read_text().splitlines()) == 2
