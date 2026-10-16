from aisast.evaluation.owasp import labels_for_candidates, score_codeql_candidates

def test_owasp_test_level_scoring_uses_official_labels():
    result = score_codeql_candidates(
        [{"cwe": 22, "primary_location": {"file": "testcode/BenchmarkTest00001.py"}}],
        [{"test_name": "BenchmarkTest00001", "vulnerable": True, "cwe": 22}, {"test_name": "BenchmarkTest00002", "vulnerable": False, "cwe": 22}],
    )
    assert result["overall"]["TP"] == 1 and result["overall"]["TN"] == 1

def test_labels_are_evaluation_only_and_keyed_by_candidate_id():
    labels = labels_for_candidates(
        [{"candidate_id": "C1", "cwe": 89, "primary_location": {"file": "testcode/BenchmarkTest00011.py"}}],
        [{"test_name": "BenchmarkTest00011", "vulnerable": False, "cwe": 89}],
    )
    assert labels == {"C1": "safe"}
