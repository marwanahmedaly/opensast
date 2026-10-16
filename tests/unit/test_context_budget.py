from pathlib import Path
from aisast.context.context_builder import ContextBuilder
from aisast.models import Candidate, Location

def test_context_budget_is_enforced_without_losing_source_lines():
    candidate = Candidate(candidate_id="c", repository_sha="r", rule_id="r", cwe=89, title="t", primary_location=Location(file="vulnerable.py", line=4), source=Location(file="vulnerable.py", line=2), sink=Location(file="vulnerable.py", line=4))
    packet = ContextBuilder(Path("tests/fixtures/cwe89"), max_chars=35).packet(candidate)
    assert sum(len(e.code) for e in packet.evidence) <= 35
    assert all(e.start_line >= 1 and e.end_line >= e.start_line for e in packet.evidence)
