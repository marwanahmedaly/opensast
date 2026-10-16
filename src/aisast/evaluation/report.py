from __future__ import annotations

from collections import defaultdict

from aisast.evaluation.metrics import calculate_metrics

def per_cwe(rows: list[tuple[int, str, str]]) -> dict[str, dict[str, float | int]]:
    grouped: dict[int, list[tuple[str, str]]] = defaultdict(list)
    for cwe, pred, label in rows: grouped[cwe].append((pred, label))
    return {str(cwe): calculate_metrics(values) for cwe, values in sorted(grouped.items())}
