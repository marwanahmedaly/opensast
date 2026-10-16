from __future__ import annotations

from collections import Counter
from typing import Any, Iterable
from pathlib import Path


def classify_findings(findings: Iterable[dict[str, Any]], labels: dict[str, str]) -> dict[str, Any]:
    """Assign every scored finding to a simple, reproducible error taxonomy."""
    counts: Counter[str] = Counter()
    rows: list[dict[str, Any]] = []
    for finding in findings:
        candidate_id = str(finding["candidate_id"])
        if candidate_id not in labels:
            continue
        verdict = str(finding.get("verdict", "SYSTEM_ERROR"))
        label = labels[candidate_id]
        if verdict == "SYSTEM_ERROR":
            category = "SYSTEM_ERROR"
        elif verdict == "VULNERABLE" and label == "safe":
            category = "STATIC_ANALYSIS_FALSE_POSITIVE"
        elif verdict == "UNRESOLVED":
            category = "INSUFFICIENT_CONTEXT"
        elif verdict != "VULNERABLE" and label == "vulnerable":
            category = "LLM_REASONING_ERROR"
        else:
            category = "CORRECT_CLASSIFICATION"
        counts[category] += 1
        rows.append({"candidate_id": candidate_id, "cwe": finding.get("cwe"), "category": category, "verdict": verdict, "label": label})
    return {"counts": dict(sorted(counts.items())), "rows": rows}


def classify_owasp_misses(candidates: Iterable[dict[str, Any]], findings: Iterable[dict[str, Any]], expected: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Separate vulnerable tests missed before verification from verifier misses."""
    truth = {(str(row["test_name"]), int(row["cwe"])): bool(row["vulnerable"]) for row in expected if int(row["cwe"]) in {22, 78, 79, 89}}
    def key(item: dict[str, Any]) -> tuple[str, int]:
        location = item.get("primary_location") or item.get("location") or {}
        return Path(str(location.get("file", ""))).stem, int(item.get("cwe", -1))
    candidate_keys = {key(item) for item in candidates}
    detected_keys = {key(item) for item in findings if str(item.get("verdict")) == "VULNERABLE"}
    vulnerable = {item for item, is_vulnerable in truth.items() if is_vulnerable}
    no_scanner = sorted(vulnerable - candidate_keys)
    rejected = sorted((vulnerable & candidate_keys) - detected_keys)
    return {"NO_SCANNER_CANDIDATE": no_scanner, "GEMMA_REJECTED_TRUE_CANDIDATE": rejected, "counts": {"NO_SCANNER_CANDIDATE": len(no_scanner), "GEMMA_REJECTED_TRUE_CANDIDATE": len(rejected)}}
