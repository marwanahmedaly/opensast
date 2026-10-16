from aisast.evaluation.metrics import calculate_metrics

def test_metrics_and_filtering_metrics():
    result = calculate_metrics([("VULNERABLE", "vulnerable"), ("NOT_VULNERABLE", "safe"), ("VULNERABLE", "safe")], {"TP": 1, "FP": 2})
    assert result["TP"] == 1 and result["FP"] == 1 and result["FN"] == 0
    assert result["false_positive_reduction"] == 0.5
    assert result["true_positive_preservation"] == 1.0
