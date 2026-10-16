from aisast.context.evidence import EvidenceGate
from aisast.models import Candidate, EvidenceBlock, EvidencePacket, Location, VerificationResult, Verdict

def packet():
    c = Candidate(candidate_id="C1", repository_sha="r", rule_id="r", cwe=89, title="t", primary_location=Location(file="x.py", line=4), source=Location(file="x.py", line=1), sink=Location(file="x.py", line=4))
    return EvidencePacket(candidate=c, profile="CWE-89", prompt_version="v1", evidence=[EvidenceBlock(id="E1", file="x.py", start_line=1, end_line=4, code="x", kind="source")])

def test_gate_rejects_cross_candidate_evidence_and_missing_flow_source():
    result = VerificationResult(candidate_id="C2", verdict=Verdict.VULNERABLE, source_evidence=["E99"], sink_evidence=[])
    validation = EvidenceGate().validate(packet(), result)
    assert not validation.valid
    assert any("candidate_id" in error for error in validation.errors)
    assert any("unknown evidence" in error for error in validation.errors)
    assert any("sink evidence" in error for error in validation.errors)

def test_gate_accepts_bound_result():
    result = VerificationResult(candidate_id="C1", verdict=Verdict.VULNERABLE, source_evidence=["E1"], sink_evidence=["E1"], explanation="input flows to sink [E1]")
    assert EvidenceGate().validate(packet(), result).valid


def test_gate_accepts_only_bound_prose_locations():
    result = VerificationResult(candidate_id='C1', cwe=89, verdict=Verdict.VULNERABLE,
                                source_evidence=['E1'], sink_evidence=['E1'], explanation='Input reaches x.py:4')
    assert EvidenceGate().validate(packet(), result).valid
    for citation in ('missing.py:4', 'x.py:99'):
        assert not EvidenceGate().validate(packet(), result.model_copy(update={'explanation':citation})).valid


def test_gate_rejects_ambiguous_basename_and_truncated_reference():
    p = packet().model_copy(update={'evidence':[
        EvidenceBlock(id='E1',file='a/x.py',start_line=1,end_line=4,code='x'),
        EvidenceBlock(id='E2',file='b/x.py',start_line=1,end_line=4,code='x'),
    ]})
    result = VerificationResult(candidate_id='C1',verdict=Verdict.VULNERABLE,
                                source_evidence=['E1'],sink_evidence=['E1'],explanation='x.py:4')
    assert not EvidenceGate().validate(p,result).valid
    assert EvidenceGate().validate(p,result.model_copy(update={'explanation':'a/x.py:4'})).valid
    p.evidence[0] = p.evidence[0].model_copy(update={'truncated':True,'source_end_line':50})
    assert not EvidenceGate().validate(p,result.model_copy(update={'explanation':'a/x.py:20'})).valid


def test_positive_requires_input_even_without_scanner_source():
    for cwe in (22, 78, 79, 89):
        p = packet()
        p.candidate = p.candidate.model_copy(update={'source':None, 'cwe':cwe})
        result = VerificationResult(candidate_id='C1', cwe=cwe, verdict=Verdict.VULNERABLE,
                                    sink_evidence=['E1'])
        validation = EvidenceGate().validate(p, result)
        assert validation.errors == ['confirmed flow finding must cite source evidence']
        assert EvidenceGate().validate(p, result.model_copy(update={'source_evidence':['E1']})).valid
