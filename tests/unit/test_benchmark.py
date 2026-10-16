from aisast.evaluation.benchmark import score_predictions

def test_benchmark_scoring_keeps_truth_outside_prediction_inputs():
    result = score_predictions(
        [{"candidate_id": "a", "cwe": 89, "verdict": "VULNERABLE"}, {"candidate_id": "b", "cwe": 89, "verdict": "NOT_VULNERABLE"}],
        [{"candidate_id": "a", "cwe": 89, "vulnerable": True}, {"candidate_id": "b", "cwe": 89, "vulnerable": False}],
    )
    assert result["overall"]["precision"] == 1.0 and result["per_cwe"]["89"]["f1"] == 1.0
