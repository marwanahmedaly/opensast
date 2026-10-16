"""Worker child process. Uses the current detector and verifier without modifying them."""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

from aisast.resources import scanner_root
from .incremental import atomic_json, file_hash, identity, inventory, plan, relationships, snapshot


def load(path, default=None):
    return json.loads(path.read_text()) if path.is_file() else default


def progress(run, **values):
    atomic_json(run / "progress.json", {"updated_at": time.time(), **values})


def analysis_identity(settings):
    from aisast import __version__
    from aisast.verifier.prompts import QUESTION_FILE, PROFILE_FILE
    package = Path(__file__).resolve().parents[1]
    checkout = scanner_root()
    files = {str(path.relative_to(package)): file_hash(path) for path in package.rglob("*.py")}
    for name, path in (("guided_questions", QUESTION_FILE), ("question_routing", PROFILE_FILE)):
        if not path.is_file():
            raise RuntimeError("Bundled prompt assets are missing. Reinstall the complete OpenSAST package")
        files[name] = file_hash(path)
    for base in (checkout / "config/plan7", checkout / "config/codeql-xss-models"):
        if base.is_dir():
            for path in base.rglob("*"):
                if path.is_file() and path.suffix in {".ql", ".qll", ".yml", ".json"}:
                    files[str(path.relative_to(checkout))] = file_hash(path)
    executable = shutil.which(settings["codeql"])
    if executable:
        files["codeql_executable"] = file_hash(Path(executable))
    query_root = settings.get("query_search_path")
    if query_root:
        # Installed query packs are part of the analysis identity, including versions.
        for path in Path(query_root).rglob("*"):
            if path.is_file() and path.suffix in {".ql", ".qll", ".qls", ".yml"}:
                files["query_pack:" + str(path.relative_to(query_root))] = file_hash(path)
    return identity({"version": __version__, "settings": settings, "files": files})


def execute(root: Path, state: Path, jid: str, settings: dict, full=False):
    from aisast.context.context_builder import ContextBuilder
    from aisast.models import Candidate
    from aisast.verifier.client import VerifierClient
    from aisast.verifier.pipeline import VerificationPipeline

    started = time.monotonic()
    run = state / "runs" / jid
    run.mkdir(parents=True, exist_ok=True)
    progress(run, stage="snapshot", completed=0, total=0)
    previous = load(state / "baseline.json", {})
    from .git_changes import working_tree_metadata
    git_metadata = working_tree_metadata(root)
    files = inventory(root)
    fingerprint = analysis_identity(settings)
    model_pinned = bool(settings.get("model_revision")) or not settings.get("endpoint")
    config_changed = previous.get("analysis_identity") != fingerprint
    snap = run / "source"
    snapshot(root, snap, files)
    if working_tree_metadata(root) != git_metadata:
        raise RuntimeError("Git checkout changed while snapshotting; queue another scan")
    atomic_json(run / "git-changes.json", git_metadata)
    graph, reasons = relationships(snap, files)
    scope = plan(files, previous, graph, reasons, full=full or config_changed)
    if config_changed and previous:
        scope["fallback_reasons"].append("analysis code/configuration/query/model identity changed")
    atomic_json(run / "incremental-plan.json", scope)
    reusable = previous and not full and not config_changed and model_pinned
    previous_payload = load(state / "runs" / previous.get("job_id", "none") / "result.json", {})
    all_cacheable = not settings.get("endpoint") or len(previous.get("cache", {})) == len(previous_payload.get("findings", []))
    if reusable and all_cacheable and files == previous.get("files"):
        payload = previous_payload
        if payload is not None:
            payload["summary"] = {**payload["summary"], **scope, "scanner_scope": "unchanged snapshot reused",
                                  "reused": len(payload["findings"]), "verified": 0,
                                  "detector_seconds": 0, "verification_seconds": 0,
                                  "elapsed_seconds": time.monotonic() - started, "source_identity": identity(files)}
            payload["git"] = git_metadata
            payload["closed_finding_ids"] = []
            payload["new_finding_ids"] = []
            for finding in payload["findings"]:
                finding["reused"] = True
            atomic_json(run / "result.json", payload)
            atomic_json(run / "next-baseline.json", {**previous, "job_id": jid})
            progress(run, stage="complete", completed=len(payload["findings"]), total=len(payload["findings"]))
            return

    progress(run, stage="codeql_and_context", completed=0, total=0)
    output = run / "analysis"
    # Stable project identity keeps candidate/evidence IDs comparable; source revision is
    # separately captured by source_identity, not misrepresented as a Git commit.
    command = [sys.executable, "-m", "aisast.cli", "scan", str(snap), "--output", str(output),
               "--repo-sha", settings["project_id"], "--codeql", settings["codeql"], "--dry-run"]
    for cwe in (22, 78, 79, 89):
        command.extend(["--cwe", str(cwe)])
    if settings.get("query_search_path"):
        command.extend(["--query-search-path", settings["query_search_path"]])
    # All query packs must be preinstalled; never allow the existing runner's download fallback.
    else:
        raise RuntimeError("Configure --query-search-path to preinstalled CodeQL packs; offline scans never download packs")
    atomic_json(run / "detector-command.json", command)
    detector_started = time.monotonic()
    with (run / "detector.stdout.log").open("w") as stdout, (run / "detector.stderr.log").open("w") as stderr:
        result = subprocess.run(command, stdout=stdout, stderr=stderr, check=False)
    if result.returncode:
        raise RuntimeError("Detector failed; inspect detector.stderr.log in the local worker run directory")
    detector_seconds = time.monotonic() - detector_started
    candidates = [Candidate.model_validate_json(line) for line in (output / "candidates.jsonl").read_text().splitlines() if line.strip()]
    packets = [json.loads(line) for line in (output / "evidence_packets.jsonl").read_text().splitlines() if line.strip()]
    if len(candidates) != len(packets):
        raise RuntimeError("Detector candidate/evidence counts differ")
    context = ContextBuilder(snap) if settings.get("endpoint") else None
    pipeline = None
    if context:
        client = VerifierClient(settings["endpoint"], settings["model"], max_tokens=settings["max_tokens"],
                                context_window=settings["context_window"],
                                attempt_sink=lambda event: append(output / "product-wire-events.jsonl", event))
        pipeline = VerificationPipeline(context, client, guided=True)
    old_cache = previous.get("cache", {}) if reusable else {}
    cache, findings = {}, []
    affected = set(scope["affected_files"])
    all_affected = scope["mode"] == "full"
    reused = verified = 0
    verification_started = time.monotonic()
    dry_findings = [json.loads(line) for line in (output / "final_findings.jsonl").read_text().splitlines() if line.strip()]
    for index, (candidate, packet) in enumerate(zip(candidates, packets)):
        key = identity(packet)
        evidence_files = {block["file"] for block in packet["evidence"]}
        evidence_files.update(loc.file for loc in [candidate.primary_location, candidate.source, candidate.sink, *candidate.path] if loc)
        cached = old_cache.get(key)
        if cached and not all_affected and not (evidence_files & affected):
            finding = cached["finding"]
            cache[key] = cached
            reused += 1
            evidence = cached["evidence"]
        elif pipeline:
            verified += 1
            result = pipeline.run(candidate)
            finding = result.finding.model_dump(mode="json")
            evidence = [block.model_dump(mode="json") for block in result.packet.evidence]
            append(output / "product-verifier-results.jsonl", {"finding": finding,
                   "responses": [response.model_dump(mode="json") for response in result.responses], "logs": result.response_logs})
            if model_pinned and finding["verdict"] in {"VULNERABLE", "NOT_VULNERABLE"} and not any("context_expansion" in log for log in result.response_logs):
                cache[key] = {"finding": finding, "evidence": evidence}
        else:
            finding = dry_findings[index]
            evidence = packet["evidence"]
        stable = identity({"rule": candidate.rule_id, "cwe": candidate.cwe,
                           "location": candidate.primary_location.model_dump(),
                           "source": candidate.source.model_dump() if candidate.source else None,
                           "sink": candidate.sink.model_dump() if candidate.sink else None,
                           "expression": candidate.properties.get("expression")})
        findings.append({**finding, "finding_id": stable, "evidence": evidence, "candidate": candidate.model_dump(mode="json"),
                         "reused": bool(cached and not all_affected and not (evidence_files & affected))})
        progress(run, stage="verification", completed=index + 1, total=len(candidates), reused=reused, verified=verified)
    previous_result = load(state / "runs" / previous.get("job_id", "none") / "result.json", {})
    current_ids = {f["finding_id"] for f in findings}
    old_ids = {f["finding_id"] for f in previous_result.get("findings", [])}
    payload = {"summary": {**scope, "scanner_scope": "full repository CodeQL and fresh context",
               "candidates": len(candidates), "reused": reused, "verified": verified,
               "verifier_configured": bool(pipeline), "model_identity_pinned": model_pinned,
               "analysis_identity": fingerprint, "source_identity": identity(files),
               "detector_seconds": detector_seconds, "verification_seconds": time.monotonic() - verification_started,
               "elapsed_seconds": time.monotonic() - started}, "findings": findings,
               "new_finding_ids": sorted(current_ids - old_ids), "closed_finding_ids": sorted(old_ids - current_ids),
               "git": git_metadata}
    atomic_json(run / "result.json", payload)
    # Parent commits this only after the server accepted successful completion.
    atomic_json(run / "next-baseline.json", {"job_id": jid, "files": files, "graph": graph, "graph_reasons": reasons,
                                            "analysis_identity": fingerprint, "cache": cache})
    progress(run, stage="complete", completed=len(candidates), total=len(candidates), reused=reused, verified=verified)


def append(path, value):
    with path.open("a") as stream:
        stream.write(json.dumps(value, default=str) + "\n")
        stream.flush()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--job", required=True)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--full", action="store_true")
    args = parser.parse_args()
    try:
        execute(args.root, args.state, args.job, load(args.settings), args.full)
    except Exception as exc:
        atomic_json(args.state / "runs" / args.job / "error.json", {"error": str(exc), "type": type(exc).__name__})
        raise


if __name__ == "__main__":
    main()
