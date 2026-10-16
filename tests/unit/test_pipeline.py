from pathlib import Path
from aisast.context.context_builder import ContextBuilder
from aisast.models import Candidate, Location, VerificationResult, Verdict
from aisast.verifier.pipeline import VerificationPipeline

class FakeClient:
    def __init__(self, first_verdict=Verdict.NEEDS_MORE_CONTEXT): self.calls = 0; self.first_verdict = first_verdict
    def verify(self, packet, guided=True):
        self.calls += 1
        result = VerificationResult(candidate_id=packet.candidate.candidate_id, verdict=self.first_verdict if self.calls == 1 else Verdict.VULNERABLE, source_evidence=[packet.evidence[0].id] if self.calls > 1 else [], sink_evidence=[packet.evidence[0].id] if self.calls > 1 else [], missing_symbols=["helper"] if self.calls == 1 else [], explanation="bound")
        return result, {}
    @staticmethod
    def system_error(candidate_id, explanation): return VerificationResult(candidate_id=candidate_id, verdict=Verdict.SYSTEM_ERROR, explanation=explanation)

def test_only_one_bounded_expansion(tmp_path):
    (tmp_path / "vulnerable.py").write_text((Path("tests/fixtures/cwe89/vulnerable.py")).read_text() + "\ndef helper(value):\n    return value\n")
    c = Candidate(candidate_id="C1", repository_sha="r", rule_id="r", cwe=89, title="t", primary_location=Location(file="vulnerable.py", line=4), source=Location(file="vulnerable.py", line=2), sink=Location(file="vulnerable.py", line=4))
    client = FakeClient(); result = VerificationPipeline(ContextBuilder(tmp_path), client).run(c)
    assert client.calls == 2 and result.finding.verdict == Verdict.VULNERABLE


def test_unresolved_with_requested_symbol_expands_once(tmp_path):
    # Direct callees are now collected automatically. Use a symbol absent from
    # the initial route so this still exercises a genuine expansion.
    (tmp_path / "app.py").write_text("def route():\n    return 'x'\n\ndef helper(value):\n    return value\n")
    candidate = Candidate(candidate_id="C", repository_sha="r", rule_id="r", cwe=79, title="t", primary_location=Location(file="app.py", line=2))
    client = FakeClient(Verdict.UNRESOLVED)
    result = VerificationPipeline(ContextBuilder(tmp_path), client).run(candidate)
    assert client.calls == 2 and result.finding.verdict == Verdict.VULNERABLE


class UnsupportedPositiveClient:
    def __init__(self, invalid_id=False): self.invalid_id = invalid_id
    def verify(self, packet, guided=True):
        return VerificationResult(candidate_id=packet.candidate.candidate_id,
                                  verdict=Verdict.VULNERABLE, source_evidence=[],
                                  sink_evidence=['invented' if self.invalid_id else packet.evidence[0].id],
                                  explanation='Unsafe operation only'), {}


def test_unsupported_positive_becomes_unknown_with_audit_errors(tmp_path):
    (tmp_path / 'app.py').write_text('def render(value):\n    return value\n')
    c = Candidate(candidate_id='C', repository_sha='r', rule_id='r', cwe=79, title='t',
                  primary_location=Location(file='app.py', line=2))
    result = VerificationPipeline(ContextBuilder(tmp_path), UnsupportedPositiveClient()).run(c)
    assert result.finding.verdict == Verdict.UNRESOLVED
    assert result.responses[0].verdict == Verdict.VULNERABLE
    assert result.finding.validation_errors == ['confirmed flow finding must cite source evidence']


def test_invalid_id_remains_operational_error(tmp_path):
    (tmp_path / 'app.py').write_text('def render(value):\n    return value\n')
    c = Candidate(candidate_id='C', repository_sha='r', rule_id='r', cwe=79, title='t',
                  primary_location=Location(file='app.py', line=2))
    result = VerificationPipeline(ContextBuilder(tmp_path), UnsupportedPositiveClient(True)).run(c)
    assert result.finding.verdict == Verdict.SYSTEM_ERROR
    assert any('unknown evidence id' in e for e in result.finding.validation_errors)
