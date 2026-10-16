from aisast.evaluation.owasp import score_candidate_generators


def test_generator_report_scores_union_once_per_benchmark_test():
    expected = [
        {"test_name": "BenchmarkTest00001", "cwe": 89, "vulnerable": True},
        {"test_name": "BenchmarkTest00002", "cwe": 89, "vulnerable": False},
    ]
    candidates = [
        {"candidate_id": "a", "cwe": 89, "primary_location": {"file": "BenchmarkTest00001.py"}, "engines": ["codeql"]},
        {"candidate_id": "b", "cwe": 89, "primary_location": {"file": "BenchmarkTest00001.py"}, "engines": ["semgrep"]},
        {"candidate_id": "c", "cwe": 89, "primary_location": {"file": "BenchmarkTest00002.py"}, "engines": ["semgrep"]},
    ]
    result = score_candidate_generators(candidates, expected)
    assert result["generators"]["union"]["TP"] == 1
    assert result["generators"]["union"]["FP"] == 1
    assert result["generators"]["union"]["candidate_recall"] == 1.0
