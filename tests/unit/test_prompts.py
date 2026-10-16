from aisast.models import Candidate, EvidencePacket, EvidenceBlock, Location
from aisast.verifier.prompts import render_prompt


def test_prompt_schema_uses_candidate_cwe():
    for cwe in (22, 78, 79, 89):
        candidate = Candidate(candidate_id="C", repository_sha="r", rule_id="rule", cwe=cwe, title="title", primary_location=Location(file="x.py", line=1))
        packet = EvidencePacket(candidate=candidate, profile=f"CWE-{cwe}", prompt_version="v1", evidence=[EvidenceBlock(id="E1", file="x.py", start_line=1, end_line=1, code="x")])
        prompt = render_prompt(packet, guided=False)
        assert f'"cwe":{cwe}' in prompt
