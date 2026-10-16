from __future__ import annotations

import csv
from itertools import combinations
from collections import defaultdict
from pathlib import Path
from typing import Iterable

from aisast.models import FinalFinding
from aisast.evaluation.metrics import calculate_metrics

OWASP_2025 = {22: "A01 Broken Access Control", 78: "A05 Injection", 79: "A05 Injection", 89: "A05 Injection"}

def map_cwe(cwe: int) -> str | None:
    return OWASP_2025.get(cwe)

def supported(finding: FinalFinding) -> bool:
    return finding.cwe in OWASP_2025

def load_expected_results(path: Path) -> list[dict[str, object]]:
    rows = []
    with path.open(newline="") as stream:
        for row in csv.reader(line for line in stream if not line.lstrip().startswith("#")):
            if len(row) < 4: continue
            rows.append({"test_name": row[0], "category": row[1], "vulnerable": row[2].strip().lower() == "true", "cwe": int(row[3])})
    return rows


def labels_for_candidates(candidates: Iterable[dict], expected_results: Iterable[dict[str, object]]) -> dict[str, str]:
    """Build evaluation-only labels keyed by candidate ID.

    The returned labels are consumed after verification and are never included
    in evidence packets or prompts.
    """
    truth = {(str(row["test_name"]), int(row["cwe"])): bool(row["vulnerable"]) for row in expected_results}
    labels: dict[str, str] = {}
    for candidate in candidates:
        location = candidate.get("primary_location", {})
        test_name = Path(str(location.get("file", ""))).stem
        cwe = int(candidate.get("cwe", -1))
        if (test_name, cwe) in truth:
            labels[str(candidate["candidate_id"])] = "vulnerable" if truth[(test_name, cwe)] else "safe"
    return labels

def score_codeql_candidates(candidates: list[dict], expected_results: list[dict[str, object]]) -> dict[str, object]:
    """Score CodeQL as a test-level detector using official expectedresults CSV labels."""
    detected: set[tuple[str, int]] = set()
    for candidate in candidates:
        file = candidate.get("primary_location", {}).get("file", "")
        test_name = Path(file).stem
        detected.add((test_name, int(candidate.get("cwe", -1))))
    rows: list[tuple[str, str]] = []
    per_cwe: dict[str, dict[str, object]] = {}
    for cwe in sorted({int(row["cwe"]) for row in expected_results if int(row["cwe"]) in {22, 78, 79, 89}}):
        scoped = [row for row in expected_results if int(row["cwe"]) == cwe]
        scoped_rows = [("VULNERABLE" if (str(row["test_name"]), cwe) in detected else "NOT_VULNERABLE", "vulnerable" if row["vulnerable"] else "safe") for row in scoped]
        rows.extend(scoped_rows); per_cwe[str(cwe)] = calculate_metrics(scoped_rows)
    return {"scope": "CWE-22/78/79/89", "overall": calculate_metrics(rows), "per_cwe": per_cwe, "candidate_count": len(candidates), "label_count": len(rows)}


def _test_key(candidate: dict) -> tuple[str, int]:
    location = candidate.get("primary_location", {})
    return Path(str(location.get("file", ""))).stem, int(candidate.get("cwe", -1))


def score_candidate_generators(candidates: Iterable[dict], expected_results: list[dict[str, object]]) -> dict[str, object]:
    """Score independent generators and their unions at benchmark-test level.

    A test is detected once per CWE, regardless of how many rules or engines
    reported it. This is the headline candidate-recall evaluation required for
    multi-SAST experiments.
    """
    grouped: dict[str, set[tuple[str, int]]] = {}
    candidate_counts: dict[str, int] = defaultdict(int)
    all_candidates = list(candidates)
    for candidate in all_candidates:
        engines = candidate.get("engines") or candidate.get("properties", {}).get("engine") or ["unknown"]
        if isinstance(engines, str):
            engines = [engines]
        key = _test_key(candidate)
        for engine in engines:
            grouped.setdefault(str(engine), set()).add(key)
            candidate_counts[str(engine)] += 1
    engine_names = sorted(grouped)
    grouped["union"] = set().union(*grouped.values()) if grouped else set()
    candidate_counts["union"] = len(all_candidates)
    for left, right in combinations(engine_names, 2):
        grouped[f"{left}+{right}"] = grouped[left] | grouped[right]
        candidate_counts[f"{left}+{right}"] = sum(1 for candidate in all_candidates if set(candidate.get("engines") or [candidate.get("properties", {}).get("engine", "unknown")]) & {left, right})
    valid = [row for row in expected_results if int(row["cwe"]) in {22, 78, 79, 89}]
    names = sorted(grouped)
    result: dict[str, object] = {"scope": "CWE-22/78/79/89", "generators": {}, "candidate_count": len(all_candidates), "label_count": len(valid), "unique_true_positive_tests": {}}
    vulnerable_keys = {(str(row["test_name"]), int(row["cwe"])) for row in valid if row["vulnerable"]}
    tp_sets = {engine: values & vulnerable_keys for engine, values in grouped.items() if engine in engine_names}
    result["pairwise_jaccard"] = {
        f"{left}+{right}": len(tp_sets[left] & tp_sets[right]) / len(tp_sets[left] | tp_sets[right]) if tp_sets[left] | tp_sets[right] else 1.0
        for left, right in combinations(engine_names, 2)
    }
    truth = {(str(row["test_name"]), int(row["cwe"])): bool(row["vulnerable"]) for row in valid}
    observed: dict[tuple[str, int], set[str]] = defaultdict(set)
    for candidate in all_candidates:
        engines = candidate.get("engines") or candidate.get("properties", {}).get("engine") or ["unknown"]
        if isinstance(engines, str): engines = [engines]
        for engine in engines: observed[_test_key(candidate)].add(str(engine))
    agreement: dict[str, dict[str, int | float]] = {}
    for count in sorted({len(engines) for key, engines in observed.items() if key in truth}):
        keys = [key for key, engines in observed.items() if key in truth and len(engines) == count]
        tp = sum(truth[key] for key in keys)
        agreement[str(count)] = {"detected_tests": len(keys), "true_positive_tests": tp, "precision": tp / len(keys) if keys else 0.0}
    result["agreement"] = agreement
    for name in names:
        detected = grouped[name]
        rows = [("VULNERABLE" if (str(row["test_name"]), int(row["cwe"])) in detected else "NOT_VULNERABLE", "vulnerable" if row["vulnerable"] else "safe") for row in valid]
        by_cwe: dict[str, dict[str, float | int]] = {}
        for cwe in (22, 78, 79, 89):
            scoped = [row for index, row in enumerate(rows) if int(valid[index]["cwe"]) == cwe]
            if scoped:
                by_cwe[str(cwe)] = calculate_metrics(scoped)
        metrics = calculate_metrics(rows)
        vulnerable = sum(1 for row in valid if row["vulnerable"])
        result["generators"][name] = {**metrics, "candidate_count": candidate_counts.get(name, len(detected)), "candidate_recall": metrics["TP"] / vulnerable if vulnerable else 0.0, "per_cwe": by_cwe}
    for engine in engine_names:
        result["unique_true_positive_tests"][engine] = sorted(grouped[engine] & vulnerable_keys - set().union(*(grouped[other] for other in engine_names if other != engine)))
    return result


def score_verifier_tests(findings: Iterable[dict], candidates: Iterable[dict], expected_results: list[dict[str, object]]) -> dict[str, object]:
    """Score all official tests; multiple alerts for one test count once.

    A test is called vulnerable when any associated candidate is verified
    vulnerable. Unresolved and system errors remain explicit in the report.
    """
    by_id = {str(item['candidate_id']): _test_key(item) for item in candidates}
    verdicts: dict[tuple[str, int], list[str]] = defaultdict(list)
    for finding in findings:
        candidate_id = str(finding['candidate_id'])
        if candidate_id not in by_id:
            raise ValueError(f'finding has unknown candidate: {candidate_id}')
        verdicts[by_id[candidate_id]].append(str(finding['verdict']))
    scoped = [row for row in expected_results if int(row['cwe']) in OWASP_2025]
    if not scoped:
        raise ValueError('no scoped ground truth')
    rows = []
    failures = {'SYSTEM_ERROR': 0, 'UNRESOLVED': 0, 'NEEDS_MORE_CONTEXT': 0}
    for row in scoped:
        key = (str(row['test_name']), int(row['cwe']))
        observed = verdicts.get(key, [])
        for failure in failures:
            failures[failure] += failure in observed
        predicted = 'VULNERABLE' if 'VULNERABLE' in observed else 'NOT_VULNERABLE'
        rows.append((predicted, 'vulnerable' if row['vulnerable'] else 'safe'))
    per_cwe = {str(cwe): calculate_metrics([prediction for label, prediction in zip(scoped, rows) if int(label['cwe']) == cwe])
               for cwe in sorted({int(label['cwe']) for label in scoped})}
    return {'scope': 'CWE-22/78/79/89', 'overall': calculate_metrics(rows), 'per_cwe': per_cwe,
            'label_count': len(rows), 'candidate_count': len(by_id), 'test_error_counts': failures}
