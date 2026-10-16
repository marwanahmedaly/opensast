from pathlib import Path
import pytest
from aisast.evaluation.realvuln import score_realvuln, score_realvuln_generators, score_realvuln_findings
from aisast.models import Candidate, FinalFinding, Location, Verdict

def test_realvuln_baseline_command_scores_supported_cwes(tmp_path: Path):
    repo = tmp_path / "repo"; runs = tmp_path / "runs"; gt = tmp_path / "gt"; repo.mkdir(); (runs / "sample").mkdir(parents=True); (gt / "sample").mkdir(parents=True)
    (repo / "v.py").write_text("x = 1\n")
    (runs / "sample" / "codeql.sarif").write_text('{"runs":[{"tool":{"driver":{"rules":[{"id":"r","properties":{"tags":["cwe-89"]}}]}},"results":[{"ruleId":"r","message":{"text":"x"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"v.py"},"region":{"startLine":1}}}]}]}]}')
    (gt / "sample" / "ground-truth.json").write_text('{"findings":[{"id":"f","is_vulnerable":true,"primary_cwe":"CWE-89","acceptable_cwes":["CWE-89"],"file":"v.py","location":{"start_line":1}}]}')
    manifest = tmp_path / "manifest.json"; manifest.write_text('{"repos":{"sample":{"language":"python","authorship":"human_authored","commit_sha":"r"}}}')
    result = score_realvuln(manifest, runs, repo, gt)
    assert result["overall"]["TP"] == 1


def test_union_counts_repositories_with_no_scanner_candidates(tmp_path: Path):
    repositories = tmp_path / "repos"
    runs = tmp_path / "runs"
    ground_truth = tmp_path / "ground-truth"
    for slug in ("detected", "missed"):
        (repositories / slug).mkdir(parents=True)
        (repositories / slug / "v.py").write_text("x = 1\n")
        (ground_truth / slug).mkdir(parents=True)
        (ground_truth / slug / "ground-truth.json").write_text(
            '{"findings":[{"id":"v","is_vulnerable":true,"primary_cwe":"CWE-89",'
            '"acceptable_cwes":["CWE-89"],"file":"v.py",'
            '"location":{"start_line":1}}]}'
        )
    (runs / "codeql" / "detected").mkdir(parents=True)
    (runs / "codeql" / "detected" / "raw.sarif").write_text(
        '{"runs":[{"tool":{"driver":{"rules":[{"id":"r",'
        '"properties":{"tags":["cwe-89"]}}]}},"results":[{"ruleId":"r",'
        '"message":{"text":"x"},"locations":[{"physicalLocation":{'
        '"artifactLocation":{"uri":"v.py"},"region":{"startLine":1}}}]}]}]}'
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"repos":{"detected":{"language":"python",'
                        '"authorship":"human_authored","commit_sha":"r"},'
                        '"missed":{"language":"python",'
                        '"authorship":"human_authored","commit_sha":"r"}}}')

    with pytest.raises(FileNotFoundError, match="codeql/missed"):
        score_realvuln_generators(manifest, runs, repositories, ground_truth, ("codeql",))
    (runs / "codeql" / "missed").mkdir(parents=True)
    (runs / "codeql" / "missed" / "raw.sarif").write_text(
        '{"runs":[{"tool":{"driver":{"rules":[]}},"results":[]}]}'
    )

    result = score_realvuln_generators(manifest, runs, repositories, ground_truth, ("codeql",))

    assert result["engines"]["union"]["repositories"] == 2
    assert result["engines"]["union"]["overall"]["TP"] == 1
    assert result["engines"]["union"]["overall"]["FN"] == 1


def test_rejected_duplicate_is_not_counted_as_verifier_false_negative(tmp_path: Path):
    slug = "sample"
    ground_truth = tmp_path / "ground-truth" / slug
    ground_truth.mkdir(parents=True)
    (ground_truth / "ground-truth.json").write_text(
        '{"findings":[{"id":"v","is_vulnerable":true,"primary_cwe":"CWE-79",'
        '"acceptable_cwes":["CWE-79"],"file":"app.py",'
        '"location":{"start_line":4}}]}'
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"repos":{"sample":{"language":"python","authorship":"human_authored"}}}')
    location = Location(file=f"{slug}/app.py", line=4)
    candidates = [Candidate(candidate_id=name, repository_sha="r", rule_id="xss", cwe=79,
                            title="xss", primary_location=location, properties={"repository": slug})
                  for name in ("rejected", "accepted")]
    findings = [FinalFinding(candidate_id=name, cwe=79, rule_id="xss", verdict=verdict,
                             location=location) for name, verdict in
                (("rejected", Verdict.UNRESOLVED), ("accepted", Verdict.VULNERABLE))]
    result = score_realvuln_findings(manifest, candidates, findings, tmp_path / "ground-truth")
    assert result["overall"]["TP"] == 1
    assert result["overall"]["FN"] == 0
    assert sum(result["false_negative_origin"].values()) == 0


def test_one_candidate_for_two_labels_is_a_match_conflict(tmp_path: Path):
    slug = "sample"
    truth = tmp_path / "ground-truth" / slug
    truth.mkdir(parents=True)
    (truth / "ground-truth.json").write_text('{"findings":['
        '{"id":"a","is_vulnerable":true,"primary_cwe":"CWE-79","acceptable_cwes":["CWE-79"],'
        '"file":"app.py","location":{"start_line":4}},'
        '{"id":"b","is_vulnerable":true,"primary_cwe":"CWE-79","acceptable_cwes":["CWE-79"],'
        '"file":"app.py","location":{"start_line":4}}]}')
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"repos":{"sample":{"language":"python","authorship":"human_authored"}}}')
    location = Location(file=f"{slug}/app.py", line=4)
    candidate = Candidate(candidate_id="one", repository_sha="r", rule_id="xss", cwe=79,
                          title="xss", primary_location=location, properties={"repository": slug})
    finding = FinalFinding(candidate_id="one", cwe=79, rule_id="xss", verdict=Verdict.VULNERABLE,
                           location=location)
    result = score_realvuln_findings(manifest, [candidate], [finding], tmp_path / "ground-truth")
    assert result["overall"]["TP"] == 1 and result["overall"]["FN"] == 1
    assert result["false_negative_origin"] == {"ONE_TO_ONE_MATCH_CONFLICT": 1}
