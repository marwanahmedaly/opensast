from aisast.context.evidence import EvidenceGate
from aisast.models import Candidate, EvidencePacket, EvidenceBlock, Location, VerificationResult, Verdict

def packet():
    c = Candidate(candidate_id="C1", repository_sha="r", rule_id="r", cwe=89, title="t", primary_location=Location(file="x.py", line=4), source=Location(file="x.py", line=1), sink=Location(file="x.py", line=4))
    return EvidencePacket(candidate=c, profile="CWE-89", prompt_version="v1", evidence=[EvidenceBlock(id="E1", file="x.py", start_line=1, end_line=4, code="x", kind="source")])

def test_gate_rejects_model_cwe_mismatch():
    result = VerificationResult(candidate_id="C1", cwe=78, verdict=Verdict.NOT_VULNERABLE)
    validation = EvidenceGate().validate(packet(), result)
    assert not validation.valid and any("CWE" in error for error in validation.errors)
