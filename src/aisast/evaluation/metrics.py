from __future__ import annotations

from collections import defaultdict
from typing import Iterable

def _score(pred: str, label: str) -> tuple[int, int, int, int]:
    vulnerable = label.lower() in {"1", "true", "vulnerable", "tp"}
    detected = pred.upper() == "VULNERABLE"
    return int(detected and vulnerable), int(detected and not vulnerable), int(not detected and vulnerable), int(not detected and not vulnerable)

def calculate_metrics(predictions: Iterable[tuple[str, str]], baseline: dict[str, int] | None = None) -> dict[str, float | int]:
    tp = fp = fn = tn = 0
    for pred, label in predictions:
        a, b, c, d = _score(pred, label); tp += a; fp += b; fn += c; tn += d
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    f2 = 5 * precision * recall / (4 * precision + recall) if 4 * precision + recall else 0.0
    result: dict[str, float | int] = {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "precision": precision, "recall": recall, "f1": f1, "f2": f2, "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0}
    if baseline:
        result["false_positive_reduction"] = (baseline.get("FP", 0) - fp) / baseline["FP"] if baseline.get("FP", 0) else 0.0
        result["true_positive_preservation"] = tp / baseline["TP"] if baseline.get("TP", 0) else 0.0
    return result
