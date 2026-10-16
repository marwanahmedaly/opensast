from __future__ import annotations

import hashlib
import json
import platform
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aisast import __version__
from aisast.context.context_builder import ContextBuilder
from aisast.evaluation.metrics import calculate_metrics
from aisast.evaluation.report import per_cwe
from aisast.models import Candidate, FinalFinding, RunManifest, Verdict
from aisast.verifier.client import VerifierClient
from aisast.verifier.pipeline import VerificationPipeline
from aisast.verifier.prompts import render_prompt


EXPERIMENTS = {
    "A": {"llm": False, "guided": False, "expand": False, "evidence_gate": False},
    "B": {"llm": True, "guided": False, "expand": False, "evidence_gate": True},
    "C": {"llm": True, "guided": True, "expand": False, "evidence_gate": True},
    "D": {"llm": True, "guided": True, "expand": True, "evidence_gate": True},
    # plan2 names; the legacy A-D names remain stable for replaying the
    # already published CodeQL-only runs.
    "G1": {"llm": False, "guided": False, "expand": False, "evidence_gate": False},
    "G2": {"llm": False, "guided": False, "expand": False, "evidence_gate": False},
    "G3": {"llm": False, "guided": False, "expand": False, "evidence_gate": False},
    "G4": {"llm": False, "guided": False, "expand": False, "evidence_gate": False},
    "V1": {"llm": True, "guided": False, "expand": False, "evidence_gate": True},
    "V2": {"llm": True, "guided": True, "expand": False, "evidence_gate": True},
    "P3": {"llm": True, "guided": True, "expand": True, "evidence_gate": True, "conservative_rejection": True},
}


def _percentile(values: list[float], percentile: float) -> float:
    """Return a linear percentile without adding a statistics dependency."""
    if not values:
        return 0.0
    values = sorted(values)
    position = (len(values) - 1) * percentile
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    fraction = position - lower
    return values[lower] + (values[upper] - values[lower]) * fraction


def _jsonl(path: Path, values: list[Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(value.model_dump() if hasattr(value, "model_dump") else value, sort_keys=True) for value in values) + ("\n" if values else ""))


def run_experiment(experiment_id: str, repository: Path, candidates: list[Candidate], output: Path, client: VerifierClient | None = None, labels: dict[str, str] | None = None, repository_sha: str = "unknown", quantization: str | None = None, codeql_version: str | None = None, query_pack_version: str | None = None, workers: int = 1, backend: str | None = None, scan_manifest: dict[str, Any] | None = None, model_sha256: str | None = None, context_length: int = 10240, resume: bool = False) -> dict[str, Any]:
    """Run one frozen A/B/C/D configuration and save replayable artifacts."""
    if experiment_id not in EXPERIMENTS: raise ValueError(f"unknown experiment {experiment_id}; choose P3, G1-G4, V1-V2, or legacy A-D")
    spec = EXPERIMENTS[experiment_id]
    if experiment_id in {"V1", "V2", "P3"}:
        if not scan_manifest or not scan_manifest.get("stage_gate_passed"):
            raise ValueError(f"{experiment_id} requires a passed, frozen scanner manifest")
        if not candidates:
            raise ValueError(f"{experiment_id} candidate set is empty")
        for candidate in candidates:
            location = candidate.primary_location
            if Path(location.file).is_absolute() or not (repository / location.file).is_file():
                raise ValueError(f"candidate source is missing: {candidate.candidate_id}: {location.file}")
    context = ContextBuilder(repository)
    packets = [context.packet(candidate) for candidate in candidates]
    if experiment_id in {"V1", "V2", "P3"}:
        for packet in packets:
            if not packet.evidence:
                raise ValueError(f"candidate has no evidence: {packet.candidate.candidate_id}")
    if resume:
        for name, values in (("candidates.jsonl", candidates), ("evidence_packets.jsonl", packets)):
            path = output / name
            if not path.is_file():
                raise ValueError(f"resume requires {path}")
            expected = "\n".join(json.dumps(value.model_dump(), sort_keys=True) for value in values) + "\n"
            if path.read_text() != expected:
                raise ValueError(f"resume input changed: {path}")
    else:
        _jsonl(output / "candidates.jsonl", candidates); _jsonl(output / "evidence_packets.jsonl", packets)
    if experiment_id in {"V1", "V2", "P3"} and hashlib.sha256((output / "candidates.jsonl").read_bytes()).hexdigest() != scan_manifest.get("candidate_sha256"):
        raise ValueError(f"{experiment_id} candidate serialization differs from frozen scanner candidates")
    findings: list[FinalFinding] = []; responses: list[dict[str, Any]] = []; prompts: list[dict[str, Any]] = []
    completed_ids: set[str] = set()
    if resume:
        paths = [output / name for name in ("final_findings.jsonl", "responses.jsonl", "prompts.jsonl")]
        if not all(path.is_file() for path in paths):
            raise ValueError("resume requires findings, responses, and prompts")
        findings = [FinalFinding.model_validate(json.loads(line)) for line in paths[0].read_text().splitlines() if line.strip()]
        responses = [json.loads(line) for line in paths[1].read_text().splitlines() if line.strip()]
        prompts = [json.loads(line) for line in paths[2].read_text().splitlines() if line.strip()]
        expected_ids = {candidate.candidate_id for candidate in candidates}
        finding_ids = [finding.candidate_id for finding in findings]
        prompt_ids = [item["candidate_id"] for item in prompts]
        response_ids = {item["candidate_id"] for item in responses}
        if (len(finding_ids) != len(set(finding_ids)) or set(finding_ids) != set(prompt_ids)
                or len(prompt_ids) != len(set(prompt_ids)) or response_ids != set(finding_ids)
                or not set(finding_ids) <= expected_ids):
            raise ValueError("resume artifacts have inconsistent candidate IDs")
        completed_ids = set(finding_ids)
    started = time.perf_counter()
    if not spec["llm"]:
        findings = [FinalFinding(candidate_id=c.candidate_id, cwe=c.cwe, rule_id=c.rule_id, verdict=Verdict.VULNERABLE, location=c.primary_location, evidence_ids=[e.id for e in packet.evidence], explanation="CodeQL baseline candidate") for c, packet in zip(candidates, packets)]
    else:
        if client is None: raise ValueError("experiments B-D require a verifier client")
        if workers < 1:
            raise ValueError("workers must be positive")
        pipeline = VerificationPipeline(context, client, guided=spec["guided"], expand=spec["expand"], conservative_rejection=spec.get("conservative_rejection", False))
        order = {candidate.candidate_id: index for index, candidate in enumerate(candidates)}
        ordered: dict[int, FinalFinding] = {order[finding.candidate_id]: finding for finding in findings}
        def verify_one(index: int, candidate: Candidate) -> tuple[int, Any]:
            return index, pipeline.run(candidate)
        if workers == 1:
            completed = (verify_one(index, candidate) for index, candidate in enumerate(candidates)
                         if candidate.candidate_id not in completed_ids)
        else:
            executor = ThreadPoolExecutor(max_workers=workers)
            futures = [executor.submit(verify_one, index, candidate) for index, candidate in enumerate(candidates)
                       if candidate.candidate_id not in completed_ids]
            completed = (future.result() for future in as_completed(futures))
        try:
            for index, result in completed:
                ordered[index] = result.finding
                prompts.append({"candidate_id": candidates[index].candidate_id, "prompt": render_prompt(packets[index], guided=spec["guided"])})
                responses.extend(result.response_logs)
                findings = [ordered[key] for key in sorted(ordered)]
                _jsonl(output / "prompts.jsonl", prompts)
                _jsonl(output / "responses.jsonl", responses)
                _jsonl(output / "final_findings.jsonl", findings)
                print(f"{experiment_id}: {len(ordered)}/{len(candidates)} {candidates[index].candidate_id}", flush=True)
        finally:
            if workers > 1:
                executor.shutdown(wait=True)
        findings = [ordered[key] for key in sorted(ordered)]
    order = {candidate.candidate_id: index for index, candidate in enumerate(candidates)}
    prompts.sort(key=lambda item: order.get(item["candidate_id"], len(order)))
    responses.sort(key=lambda item: order.get(item["candidate_id"], len(order)))
    _jsonl(output / "prompts.jsonl", prompts); _jsonl(output / "responses.jsonl", responses); _jsonl(output / "final_findings.jsonl", findings)
    metrics = None
    if labels:
        rows = [(finding.verdict.value, labels[finding.candidate_id]) for finding in findings if finding.candidate_id in labels]
        metrics = {"overall": calculate_metrics(rows), "per_cwe": per_cwe([(finding.cwe, finding.verdict.value, labels[finding.candidate_id]) for finding in findings if finding.candidate_id in labels]), "matched": len(rows)}
    config_text = json.dumps({"experiment": experiment_id, **spec}, sort_keys=True)
    prompt_text = "\n".join(item["prompt"] for item in prompts)
    scanners = sorted({engine for candidate in candidates for engine in candidate.engines})
    scan_manifest = scan_manifest or {}
    source_manifest = scan_manifest.get("manifest_path")
    manifest = RunManifest(run_id=output.name, repository=str(repository), repository_sha=repository_sha, dataset_commit=repository_sha if repository_sha != "unknown" else None, scanner_version=__version__, python_version=platform.python_version(), codeql_version=codeql_version or scan_manifest.get("codeql_version"), query_pack_version=query_pack_version or scan_manifest.get("query_pack_version"), model=client.model if client else None, quantization=quantization, context_length=context_length, temperature=client.temperature if client else 0.0, top_p=client.top_p if client else 1.0, prompt_hash=hashlib.sha256((prompt_text or config_text).encode()).hexdigest(), config_hash=hashlib.sha256(config_text.encode()).hexdigest(), created_at=datetime.now(timezone.utc).isoformat(), scanners=scanners, scanner_versions=scan_manifest.get("scanner_versions", {}), backend=backend, model_sha256=model_sha256, candidate_sha256=hashlib.sha256((output / "candidates.jsonl").read_bytes()).hexdigest(), max_tokens=client.max_tokens if client else None, max_retries=client.max_retries if client else None, rule_profile=scan_manifest.get("rule_profile"), rule_profile_sha256=scan_manifest.get("rule_profile_sha256"), guided_questions_sha256=scan_manifest.get("guided_questions_sha256"), source_run_sha256=hashlib.sha256(Path(source_manifest).read_bytes()).hexdigest() if source_manifest else None)
    (output / "manifest.json").write_text(manifest.model_dump_json(indent=2) + "\n")
    latencies = [float(item["latency_seconds"]) for item in responses if "latency_seconds" in item]
    usage = [item.get("raw", {}).get("usage", {}) for item in responses]
    verdict_counts = {verdict.value: sum(finding.verdict == verdict for finding in findings) for verdict in Verdict}
    request_attempts = sum(len(item.get("attempt_log", [])) or int(item.get("attempt", 1)) for item in responses)
    retries = sum(max((len(item.get("attempt_log", [])) or int(item.get("attempt", 1))) - 1, 0) for item in responses)
    attempt_latencies = [float(attempt["latency_seconds"]) for item in responses
                         for attempt in item.get("attempt_log", []) if "latency_seconds" in attempt]
    measured_latencies = attempt_latencies or latencies
    usage_observed = sum(bool(attempt.get("usage")) for item in responses
                         for attempt in item.get("attempt_log", []))
    result = {"experiment": experiment_id, "candidates": len(candidates), "findings": len(findings), "elapsed_seconds": time.perf_counter() - started, "model_calls": request_attempts, "response_records": len(responses), "latency_seconds_total": sum(measured_latencies), "latency_seconds_mean": sum(measured_latencies) / len(measured_latencies) if measured_latencies else 0.0, "latency_seconds_p95": _percentile(measured_latencies, 0.95), "prompt_tokens": sum(int(item.get("prompt_tokens", 0) or 0) for item in usage), "completion_tokens": sum(int(item.get("completion_tokens", 0) or 0) for item in usage), "token_usage_observed_attempts": usage_observed, "token_usage_complete": usage_observed == request_attempts if attempt_latencies else None, "operational": {"valid_response_rate": sum(verdict_counts[v] for v in (Verdict.VULNERABLE, Verdict.NOT_VULNERABLE)) / len(candidates) if candidates else 0.0, "system_error_rate": verdict_counts[Verdict.SYSTEM_ERROR] / len(candidates) if candidates else 0.0, "unresolved_rate": verdict_counts[Verdict.UNRESOLVED] / len(candidates) if candidates else 0.0, "retry_count": retries, "verdict_counts": verdict_counts}, "metrics": metrics}
    (output / "metrics.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def run_repeated_experiments(experiment_id: str, repository: Path, candidates: list[Candidate], output: Path, repetitions: int, client: VerifierClient | None = None, labels: dict[str, str] | None = None, repository_sha: str = "unknown", quantization: str | None = None, codeql_version: str | None = None, query_pack_version: str | None = None, workers: int = 1, backend: str | None = None, scan_manifest: dict[str, Any] | None = None, model_sha256: str | None = None, context_length: int = 10240) -> dict[str, Any]:
    """Run a frozen verifier configuration repeatedly and summarize variation."""
    if repetitions < 1:
        raise ValueError("repetitions must be positive")
    runs = [run_experiment(experiment_id, repository, candidates, output / f"repetition-{index}", client, labels, repository_sha, quantization, codeql_version, query_pack_version, workers, backend, scan_manifest, model_sha256, context_length) for index in range(1, repetitions + 1)]
    metric_names = ("precision", "recall", "f1", "f2")
    values = {name: [float(run["metrics"]["overall"][name]) for run in runs if run.get("metrics")] for name in metric_names}
    summary = {"experiment": experiment_id, "repetitions": repetitions, "runs": runs, "mean": {name: statistics.mean(items) if items else 0.0 for name, items in values.items()}, "std": {name: statistics.pstdev(items) if len(items) > 1 else 0.0 for name, items in values.items()}}
    output.mkdir(parents=True, exist_ok=True); (output / "repeated-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary
