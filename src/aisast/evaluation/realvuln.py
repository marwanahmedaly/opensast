from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from aisast.codeql.normalizer import load_and_normalize
from aisast.evaluation.metrics import calculate_metrics
from aisast.fusion import fuse_candidates
from aisast.models import Candidate, FinalFinding, Location, Verdict

SUPPORTED_CWES = {22, 78, 79, 89}


def _macro_metrics(rows: list[dict]) -> dict[str, float]:
    metrics = [calculate_metrics([("VULNERABLE", "vulnerable")] * row.get("TP", 0) + [("VULNERABLE", "safe")] * row.get("FP", 0) + [("NOT_VULNERABLE", "vulnerable")] * row.get("FN", 0) + [("NOT_VULNERABLE", "safe")] * row.get("TN", 0)) for row in rows]
    return {name: sum(float(item[name]) for item in metrics) / len(metrics) for name in ("precision", "recall", "f1", "f2")} if metrics else {name: 0.0 for name in ("precision", "recall", "f1", "f2")}

def in_primary_scope(cwe: int) -> bool:
    return cwe in SUPPORTED_CWES

def filter_labels(labels: list[dict]) -> list[dict]:
    """Keep the primary evaluation scope without pretending unsupported CWEs were missed."""
    return [label for label in labels if int(label.get("cwe", -1)) in SUPPORTED_CWES]

def _cwe_number(value: object) -> int | None:
    text = str(value)
    if text.upper().startswith("CWE-"):
        try: return int(text.split("-", 1)[1])
        except ValueError: return None
    return None

def _in_range(line: int, location: dict) -> bool:
    start = location.get("start_line"); end = location.get("end_line", start)
    return start is None or line is None or int(start) - 10 <= line <= int(end) + 10

def _matches_truth(candidate: Candidate, entry: dict) -> bool:
    accepted = {_cwe_number(cwe) for cwe in entry.get("acceptable_cwes", [])}
    accepted.discard(None)
    return (
        candidate.cwe in accepted
        and candidate.primary_location.file == entry.get("file")
        and _in_range(candidate.primary_location.line, entry.get("location", {}))
    )

def _score_repo(candidates: list, ground_truth: dict) -> tuple[Counter, dict[int, Counter]]:
    entries = []
    for entry in ground_truth.get("findings", []):
        accepted = {_cwe_number(cwe) for cwe in entry.get("acceptable_cwes", [])}
        accepted.discard(None)
        accepted &= SUPPORTED_CWES
        if accepted:
            copy = dict(entry); copy["_accepted"] = accepted; entries.append(copy)
    matched: set[str] = set(); counts = Counter(); per_cwe: dict[int, Counter] = defaultdict(Counter)
    for candidate in candidates:
        hits = [entry for entry in entries if entry["id"] not in matched and candidate.cwe in entry["_accepted"] and candidate.primary_location.file == entry.get("file") and _in_range(candidate.primary_location.line, entry.get("location", {}))]
        if hits:
            entry = sorted(hits, key=lambda item: not item.get("is_vulnerable", False))[0]; classification = "TP" if entry.get("is_vulnerable") else "FP"; matched.add(entry["id"])
        else:
            classification = "FP"
        counts[classification] += 1
        primary = _cwe_number(entry.get("primary_cwe")) if hits else candidate.cwe
        if primary in SUPPORTED_CWES: per_cwe[primary][classification] += 1
    for entry in entries:
        if entry["id"] not in matched:
            classification = "FN" if entry.get("is_vulnerable") else "TN"; counts[classification] += 1
            primary = _cwe_number(entry.get("primary_cwe"))
            if primary in SUPPORTED_CWES: per_cwe[primary][classification] += 1
    return counts, per_cwe

def score_realvuln(manifest_path: Path, runs_dir: Path, repositories_dir: Path, ground_truth_dir: Path, authorship: str = "human_authored") -> dict:
    manifest = json.loads(manifest_path.read_text()); overall = Counter(); all_cwe: dict[int, Counter] = defaultdict(Counter); per_repository = []
    for slug, metadata in manifest["repos"].items():
        if metadata.get("language") != "python" or metadata.get("authorship") != authorship: continue
        sarif = runs_dir / slug / "codeql.sarif"; repository = repositories_dir / slug; gt_path = ground_truth_dir / slug / "ground-truth.json"
        if not sarif.exists() or not gt_path.exists(): continue
        candidates = [candidate for candidate in load_and_normalize(sarif, metadata.get("commit_sha", "unknown"), repository) if candidate.cwe in SUPPORTED_CWES]
        counts, per_cwe = _score_repo(candidates, json.loads(gt_path.read_text())); overall.update(counts)
        for cwe, values in per_cwe.items(): all_cwe[cwe].update(values)
        per_repository.append({"repo": slug, "commit": metadata.get("commit_sha"), "candidate_count": len(candidates), **{key: counts.get(key, 0) for key in ["TP", "FP", "FN", "TN"]}})
    rows = [("VULNERABLE", "vulnerable")] * overall["TP"] + [("VULNERABLE", "safe")] * overall["FP"] + [("NOT_VULNERABLE", "vulnerable")] * overall["FN"] + [("NOT_VULNERABLE", "safe")] * overall["TN"]
    result = {"benchmark": "RealVuln", "scope": f"{authorship.replace('_', '-')} Python repositories; CWE-22/78/79/89", "generated_at": datetime.now(timezone.utc).isoformat(), "repositories": len(per_repository), "overall": calculate_metrics(rows), "macro_average": _macro_metrics(per_repository), "per_cwe": {}, "per_repository": per_repository}
    for cwe, values in sorted(all_cwe.items()):
        cwe_rows = [("VULNERABLE", "vulnerable")] * values["TP"] + [("VULNERABLE", "safe")] * values["FP"] + [("NOT_VULNERABLE", "vulnerable")] * values["FN"] + [("NOT_VULNERABLE", "safe")] * values["TN"]
        result["per_cwe"][str(cwe)] = calculate_metrics(cwe_rows)
    return result


def _sarif_for_engine(runs_dir: Path, engine: str, slug: str) -> Path | None:
    """Accept both the documented engine/ repository layout and legacy runs."""
    candidates = [
        runs_dir / engine / slug / "raw.sarif",
        runs_dir / engine / slug / f"{engine}.sarif",
        runs_dir / slug / f"{engine}.sarif",
        runs_dir / slug / "codeql.sarif" if engine == "codeql" else runs_dir / slug / f"{engine}.sarif",
    ]
    if engine == "codeql":
        candidates.append(runs_dir.parent / "realvuln-codeql" / slug / "codeql.sarif")
    return next((path for path in candidates if path.exists()), None)


def score_realvuln_generators(manifest_path: Path, runs_dir: Path, repositories_dir: Path, ground_truth_dir: Path, engines: tuple[str, ...] = ("codeql", "semgrep", "opengrep"), require_complete: bool = True, authorship: str = "human_authored") -> dict:
    """Score per-engine and fused RealVuln candidate generation.

    Results are benchmark-test/finding matches against the existing RealVuln
    ground truth. Fused candidates are deduplicated before matching, so a
    finding reported by multiple engines cannot inflate true positives.
    """
    manifest = json.loads(manifest_path.read_text())
    raw_by_engine: dict[str, list] = defaultdict(list)
    candidates_by_engine_repo: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    per_repo: dict[str, dict[str, dict]] = defaultdict(dict)
    for slug, metadata in manifest["repos"].items():
        if metadata.get("language") != "python" or metadata.get("authorship") != authorship:
            continue
        gt_path = ground_truth_dir / slug / "ground-truth.json"
        repository = repositories_dir / slug
        if not gt_path.is_file() or not repository.is_dir():
            if require_complete:
                raise FileNotFoundError(f"RealVuln repository or ground truth missing: {slug}")
            continue
        for engine in engines:
            sarif = _sarif_for_engine(runs_dir, engine, slug)
            if not sarif:
                if require_complete:
                    raise FileNotFoundError(f"RealVuln raw SARIF missing: {engine}/{slug}")
                continue
            candidates = [candidate for candidate in load_and_normalize(sarif, metadata.get("commit_sha", "unknown"), repository, engine) if candidate.cwe in SUPPORTED_CWES]
            raw_by_engine[engine].extend(candidates)
            candidates_by_engine_repo[engine][slug].extend(candidates)
            counts, per_cwe = _score_repo(candidates, json.loads(gt_path.read_text()))
            per_repo[engine][slug] = {"repo": slug, "candidate_count": len(candidates), "commit": metadata.get("commit_sha"), **{key: counts.get(key, 0) for key in ("TP", "FP", "FN", "TN")}, "per_cwe": {str(cwe): dict(values) for cwe, values in per_cwe.items()}}

    raw_by_engine["union"] = fuse_candidates([candidate for values in raw_by_engine.values() for candidate in values])
    for slug, metadata in manifest["repos"].items():
        if metadata.get("language") != "python" or metadata.get("authorship") != authorship:
            continue
        gt_path = ground_truth_dir / slug / "ground-truth.json"
        if not gt_path.exists():
            continue
        members = [candidate for engine in engines for candidate in candidates_by_engine_repo[engine].get(slug, [])]
        fused = fuse_candidates(members)
        counts, per_cwe = _score_repo(fused, json.loads(gt_path.read_text()))
        per_repo["union"][slug] = {"repo": slug, "candidate_count": len(fused), "commit": metadata.get("commit_sha"), **{key: counts.get(key, 0) for key in ("TP", "FP", "FN", "TN")}, "per_cwe": {str(cwe): dict(values) for cwe, values in per_cwe.items()}}
    result: dict[str, object] = {"benchmark": "RealVuln", "scope": f"{authorship.replace('_', '-')} Python repositories; CWE-22/78/79/89", "engines": {}, "candidate_counts": {engine: len(values) for engine, values in raw_by_engine.items()}}
    for engine, candidates in raw_by_engine.items():
        grouped = per_repo.get(engine, {})
        overall = Counter()
        all_cwe: dict[int, Counter] = defaultdict(Counter)
        for row in grouped.values():
            overall.update({key: row[key] for key in ("TP", "FP", "FN", "TN")})
            for cwe, values in row.get("per_cwe", {}).items():
                all_cwe[int(cwe)].update(values)
        rows = [("VULNERABLE", "vulnerable")] * overall["TP"] + [("VULNERABLE", "safe")] * overall["FP"] + [("NOT_VULNERABLE", "vulnerable")] * overall["FN"] + [("NOT_VULNERABLE", "safe")] * overall["TN"]
        result["engines"][engine] = {"overall": calculate_metrics(rows), "macro_average": _macro_metrics(list(grouped.values())), "repositories": len(grouped), "per_repository": list(grouped.values()), "per_cwe": {str(cwe): calculate_metrics([("VULNERABLE", "vulnerable")] * values["TP"] + [("VULNERABLE", "safe")] * values["FP"] + [("NOT_VULNERABLE", "vulnerable")] * values["FN"] + [("NOT_VULNERABLE", "safe")] * values["TN"]) for cwe, values in sorted(all_cwe.items())}}
    return result


def _prefix_candidate(candidate: Candidate, slug: str) -> Candidate:
    """Make per-repository locations resolvable from the RealVuln root."""
    def prefix(location: Location | None) -> Location | None:
        return location.model_copy(update={"file": f"{slug}/{location.file}"}) if location else None
    return candidate.model_copy(update={
        "primary_location": prefix(candidate.primary_location),
        "source": prefix(candidate.source),
        "sink": prefix(candidate.sink),
        "path": [prefix(location) for location in candidate.path if prefix(location)],
        "properties": {**candidate.properties, "repository": slug},
    })


def load_realvuln_union_candidates(manifest_path: Path, runs_dir: Path, repositories_dir: Path, engines: tuple[str, ...] = ("codeql", "semgrep", "opengrep"), require_complete: bool = True, authorship: str = "human_authored") -> list[Candidate]:
    """Load, fuse, and root-prefix RealVuln candidates for one verifier run."""
    manifest = json.loads(manifest_path.read_text())
    result: list[Candidate] = []
    for slug, metadata in manifest["repos"].items():
        if metadata.get("language") != "python" or metadata.get("authorship") != authorship:
            continue
        members: list[Candidate] = []
        for engine in engines:
            sarif = _sarif_for_engine(runs_dir, engine, slug)
            if sarif:
                members.extend(candidate for candidate in load_and_normalize(sarif, metadata.get("commit_sha", "unknown"), repositories_dir / slug, engine) if candidate.cwe in SUPPORTED_CWES)
            elif require_complete:
                raise FileNotFoundError(f"RealVuln raw SARIF missing: {engine}/{slug}")
        result.extend(_prefix_candidate(candidate, slug) for candidate in fuse_candidates(members))
    return result


def score_realvuln_findings(manifest_path: Path, candidates: list[Candidate], findings: list[FinalFinding], ground_truth_dir: Path, authorship: str = "human_authored") -> dict:
    """Score a frozen verifier output with unresolved/error findings treated as undetected."""
    manifest = json.loads(manifest_path.read_text())
    by_repo: dict[str, list[Candidate]] = defaultdict(list)
    all_by_repo: dict[str, list[Candidate]] = defaultdict(list)
    verdicts = {finding.candidate_id: finding.verdict for finding in findings}
    for candidate in candidates:
        slug = str(candidate.properties.get("repository", ""))
        if not slug:
            continue
        def strip(location: Location | None) -> Location | None:
            if not location: return None
            prefix = f"{slug}/"
            return location.model_copy(update={"file": location.file.removeprefix(prefix)})
        stripped = candidate.model_copy(update={"primary_location": strip(candidate.primary_location), "source": strip(candidate.source), "sink": strip(candidate.sink), "path": [strip(location) for location in candidate.path if strip(location)]})
        all_by_repo[slug].append(stripped)
        if verdicts.get(candidate.candidate_id) == Verdict.VULNERABLE:
            by_repo[slug].append(stripped)
    overall = Counter(); all_cwe: dict[int, Counter] = defaultdict(Counter); per_repository = []
    false_negative_origin = Counter()
    for slug, metadata in manifest["repos"].items():
        if metadata.get("language") != "python" or metadata.get("authorship") != authorship: continue
        gt_path = ground_truth_dir / slug / "ground-truth.json"
        if not gt_path.exists(): continue
        ground_truth = json.loads(gt_path.read_text())
        counts, per_cwe = _score_repo(by_repo.get(slug, []), ground_truth)
        overall.update(counts)
        entries = []
        for entry in ground_truth.get("findings", []):
            accepted = {_cwe_number(cwe) for cwe in entry.get("acceptable_cwes", [])}
            accepted.discard(None)
            if accepted & SUPPORTED_CWES:
                entries.append((entry, accepted))
        matched_ids: set[str] = set()
        # Assign accepted candidates first with the same one-to-one,
        # vulnerable-first order as _score_repo. Then classify only findings
        # that remain false negatives. A rejected duplicate must not count as
        # a verifier loss when another candidate detected the same finding.
        for candidate in by_repo.get(slug, []):
            hits = [(entry, accepted) for entry, accepted in entries if entry["id"] not in matched_ids and _matches_truth(candidate, entry)]
            if not hits:
                continue
            entry, _ = sorted(hits, key=lambda item: not item[0].get("is_vulnerable", False))[0]
            matched_ids.add(entry["id"])
        for entry, _ in entries:
            if entry.get("is_vulnerable") and entry["id"] not in matched_ids:
                matching = [candidate for candidate in all_by_repo.get(slug, []) if _matches_truth(candidate, entry)]
                if not matching:
                    key = "NO_SCANNER_CANDIDATE"
                elif any(verdicts.get(candidate.candidate_id) == Verdict.VULNERABLE for candidate in matching):
                    key = "ONE_TO_ONE_MATCH_CONFLICT"
                else:
                    key = "GEMMA_REJECTED_TRUE_CANDIDATE"
                false_negative_origin[key] += 1
        for cwe, values in per_cwe.items(): all_cwe[cwe].update(values)
        per_repository.append({"repo": slug, "candidate_count": len(by_repo.get(slug, [])), **{key: counts.get(key, 0) for key in ("TP", "FP", "FN", "TN")}})
    rows = [("VULNERABLE", "vulnerable")] * overall["TP"] + [("VULNERABLE", "safe")] * overall["FP"] + [("NOT_VULNERABLE", "vulnerable")] * overall["FN"] + [("NOT_VULNERABLE", "safe")] * overall["TN"]
    return {"benchmark": "RealVuln", "scope": f"{authorship.replace('_', '-')} Python repositories; CWE-22/78/79/89", "overall": calculate_metrics(rows), "macro_average": _macro_metrics(per_repository), "repositories": len(per_repository), "per_cwe": {str(cwe): calculate_metrics([("VULNERABLE", "vulnerable")] * values["TP"] + [("VULNERABLE", "safe")] * values["FP"] + [("NOT_VULNERABLE", "vulnerable")] * values["FN"] + [("NOT_VULNERABLE", "safe")] * values["TN"]) for cwe, values in sorted(all_cwe.items())}, "per_repository": per_repository, "false_negative_origin": dict(sorted(false_negative_origin.items()))}
