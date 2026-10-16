"""Small benchmark adapter shared by OWASP-style and RealVuln-style exports.

The adapter deliberately expects labels to be supplied separately from model
inputs, so benchmark truth can never enter an evidence packet.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .metrics import calculate_metrics
from .report import per_cwe


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def score_predictions(predictions: list[dict[str, Any]], labels: list[dict[str, Any]]) -> dict[str, Any]:
    truth = {str(item["candidate_id"]): item for item in labels}
    rows: list[tuple[str, str]] = []
    by_cwe: list[tuple[int, str, str]] = []
    for prediction in predictions:
        item = truth.get(str(prediction["candidate_id"]))
        if item is None:
            continue
        label = "vulnerable" if item.get("vulnerable", item.get("label", False)) in (True, 1, "true", "vulnerable", "VULNERABLE") else "safe"
        verdict = str(prediction.get("verdict", "SYSTEM_ERROR"))
        rows.append((verdict, label)); by_cwe.append((int(item.get("cwe", prediction.get("cwe", -1))), verdict, label))
    return {"overall": calculate_metrics(rows), "per_cwe": per_cwe(by_cwe), "matched": len(rows), "unmatched_predictions": len(predictions) - len(rows)}
