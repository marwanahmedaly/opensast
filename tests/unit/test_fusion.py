from aisast.fusion import fuse_candidates
from aisast.models import Candidate, Location


def _candidate(identifier: str, engine: str, line: int, cwe: int = 89) -> Candidate:
    return Candidate(
        candidate_id=identifier,
        repository_sha="repo",
        rule_id=f"{engine}-rule",
        cwe=cwe,
        title="candidate",
        primary_location=Location(file="app.py", line=line),
        sink=Location(file="app.py", line=line),
        engines=[engine],
        rules=[f"{engine}-rule"],
        properties={"engine": engine},
    )


def test_fusion_preserves_provenance_and_deduplicates_nearby_sinks():
    result = fuse_candidates([_candidate("c1", "codeql", 10), _candidate("c2", "semgrep", 11)])
    assert len(result) == 1
    assert result[0].engines == ["codeql", "semgrep"]
    assert result[0].rules == ["codeql-rule", "semgrep-rule"]
    assert result[0].aliases == ["c1", "c2"]


def test_fusion_keeps_distant_or_different_cwe_findings_separate():
    result = fuse_candidates([_candidate("c1", "codeql", 10), _candidate("c2", "semgrep", 20), _candidate("c3", "semgrep", 10, 78)])
    assert len(result) == 3
