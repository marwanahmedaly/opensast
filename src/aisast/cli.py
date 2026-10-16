from __future__ import annotations

import argparse
import hashlib
import json
import platform
from datetime import datetime, timezone
from pathlib import Path

import yaml

from aisast import __version__
from aisast.resources import scanner_root
from aisast.codeql.normalizer import load_and_normalize
from aisast.codeql.runner import CodeQLRunner
from aisast.codeql.query_profile import materialize_current_queries
from aisast.fusion import fuse_candidates
from aisast.scanners.runners import OpenGrepRunner, SemgrepRunner
from aisast.scanners.xss import scan_xss_candidates, client_code_paths
from aisast.context.context_builder import ContextBuilder
from aisast.models import FinalFinding, RunManifest, Verdict
from aisast.evaluation.metrics import calculate_metrics
from aisast.evaluation.error_analysis import classify_findings, classify_owasp_misses
from aisast.evaluation.owasp import load_expected_results, score_codeql_candidates, score_candidate_generators, score_verifier_tests
from aisast.evaluation.owasp import labels_for_candidates
from aisast.evaluation.experiment import run_experiment, run_repeated_experiments
from aisast.evaluation.realvuln import score_realvuln, score_realvuln_generators, load_realvuln_union_candidates, score_realvuln_findings
from aisast.verifier.client import VerifierClient
from aisast.verifier.pipeline import VerificationPipeline
from aisast.codeql.sarif import write_sarif
from aisast.environment import environment_report, write_environment_versions
from aisast.corpus.io import append_jsonl, atomic_write_json, atomic_write_jsonl

def _write_jsonl(path: Path, values: list[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(v.model_dump() if hasattr(v, "model_dump") else v, sort_keys=True) for v in values) + ("\n" if values else ""))

def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

def scan(args: argparse.Namespace) -> int:
    root = Path(args.repository).resolve(); out = Path(args.output).resolve(); out.mkdir(parents=True, exist_ok=True)
    target_cwes = sorted(set(getattr(args, "cwe", None) or []))
    if any(cwe not in {22, 78, 79, 89} for cwe in target_cwes):
        raise SystemExit("--cwe values must be 22, 78, 79, or 89")
    scanner = args.scanner
    requested = ["codeql", "semgrep", "opengrep"] if scanner == "all" else [scanner]
    model_packs = [Path(path).resolve() for path in getattr(args, "model_pack", [])]
    if args.xss_candidates:
        model_packs.append(scanner_root() / "config/codeql-xss-models")
    model_packs = list(dict.fromkeys(model_packs))
    raw_paths: dict[str, Path] = {}
    custom_profile = None
    for engine in requested:
        supplied_sarif = {"codeql": args.codeql_sarif, "semgrep": args.semgrep_sarif, "opengrep": args.opengrep_sarif}.get(engine)
        if supplied_sarif:
            raw = Path(supplied_sarif)
        elif args.sarif and len(requested) == 1:
            raw = Path(args.sarif)
        elif engine == "codeql":
            if not args.codeql:
                raise SystemExit("--codeql is required for the codeql scanner")
            raw = CodeQLRunner(args.codeql, log_dir=out / "logs" / "codeql").scan(
                root, out / "raw" / engine, args.suite, args.max_paths,
                Path(args.query_search_path) if args.query_search_path else None,
                model_packs=model_packs or None,
                no_database_extension_packs=getattr(args, "no_database_extension_packs", False),
            )
        elif engine == "semgrep":
            raw = SemgrepRunner(args.semgrep).scan(root, out / "raw" / engine / "raw.sarif", args.semgrep_config)
        else:
            raw = OpenGrepRunner(args.opengrep).scan(root, out / "raw" / engine / "raw.sarif", args.opengrep_config)
        raw_paths[engine] = raw
        normalized = load_and_normalize(raw, args.repo_sha, root, engine)
        _write_jsonl(out / "normalized" / engine / "candidates.jsonl", normalized)
        if engine == "codeql" and getattr(args, "custom_rules", True):
            supplied_custom = getattr(args, "custom_sarif", None)
            if supplied_custom:
                custom_raw = Path(supplied_custom)
                custom_profile = {"mode": "supplied_sarif", "current_profile_executed": False}
            elif supplied_sarif or args.sarif:
                # Replaying stock SARIF cannot silently claim a fresh custom run.
                custom_raw = None
                custom_profile = {"mode": "not_executed", "reason": "SARIF replay without --custom-sarif", "current_profile_executed": False}
            else:
                custom_suite, custom_profile = materialize_current_queries(out / "query-snapshots")
                custom_raw = out / "raw" / "codeql-custom" / "raw.sarif"
                CodeQLRunner(args.codeql, log_dir=out / "logs" / "codeql-custom").analyze(
                    out / "raw" / engine / "codeql-db", custom_raw, str(custom_suite),
                    args.max_paths, Path(args.query_search_path) if args.query_search_path else None,
                    model_packs=model_packs or None,
                    no_database_extension_packs=getattr(args, "no_database_extension_packs", False),
                )
                custom_profile["current_profile_executed"] = True
            if custom_raw is not None:
                raw_paths["codeql-custom"] = custom_raw
                _write_jsonl(out / "normalized" / "codeql-custom" / "candidates.jsonl",
                             load_and_normalize(custom_raw, args.repo_sha, root, "codeql-custom"))
    raw_candidates = [candidate for engine, path in raw_paths.items() for candidate in load_and_normalize(path, args.repo_sha, root, engine)]
    template_diagnostics: list[dict] = []
    use_template_companion = getattr(args, "template_candidates", True) or args.xss_candidates
    if use_template_companion:
        xss_candidates = scan_xss_candidates(root, args.repo_sha,
                                             include_python_responses=args.xss_candidates,
                                             diagnostics=template_diagnostics)
        raw_candidates.extend(xss_candidates)
        _write_jsonl(out / "normalized" / "xss-model" / "candidates.jsonl", xss_candidates)
        _write_jsonl(out / "normalized" / "xss-model" / "diagnostics.jsonl", template_diagnostics)
    if args.javascript_xss and client_code_paths(root):
        js_raw = CodeQLRunner(args.codeql, log_dir=out / "logs" / "codeql").scan(root, out / "raw" / "codeql-js", "codeql/javascript-queries:Security/CWE-079", args.max_paths, Path(args.query_search_path) if args.query_search_path else None, language="javascript")
        js_candidates = [item for item in load_and_normalize(js_raw, args.repo_sha, root, "codeql-js") if item.cwe == 79]
        raw_candidates.extend(js_candidates)
        _write_jsonl(out / "normalized" / "codeql-js" / "candidates.jsonl", js_candidates)
    candidates = fuse_candidates(raw_candidates, args.line_window) if len(raw_paths) > 1 or use_template_companion or args.javascript_xss else raw_candidates
    if target_cwes:
        candidates = [candidate for candidate in candidates if candidate.cwe in target_cwes]
    _write_jsonl(out / "candidates.jsonl", candidates)
    context = ContextBuilder(root)
    packets = [context.packet(c) for c in candidates]
    _write_jsonl(out / "evidence_packets.jsonl", packets)
    scan_manifest = {
        "repository": str(root), "repository_sha": args.repo_sha,
        "model_packs": [{
            "path": str(pack),
            "name": yaml.safe_load((pack / "qlpack.yml").read_text(encoding="utf-8")).get("name"),
            "qlpack_sha256": hashlib.sha256((pack / "qlpack.yml").read_bytes()).hexdigest(),
            "model_files": {
                model.relative_to(pack).as_posix(): hashlib.sha256(model.read_bytes()).hexdigest()
                for model in sorted(pack.rglob("*.model.yml"))
            },
        } for pack in model_packs],
        "no_database_extension_packs": getattr(args, "no_database_extension_packs", False),
        "candidate_sha256": hashlib.sha256((out / "candidates.jsonl").read_bytes()).hexdigest(),
        "raw_sarif": {engine: {"path": str(path.resolve()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for engine, path in raw_paths.items()},
        "xss_candidates": bool(args.xss_candidates), "javascript_xss": bool(args.javascript_xss),
        "template_candidates": bool(use_template_companion),
        "template_parse_errors": sum(row.get("status") == "parse_error" for row in template_diagnostics),
        "custom_query_profile": custom_profile,
        "target_cwes": target_cwes or None,
        "candidate_count": len(candidates),
        "scan_completed": False,
        "verifier_status": "pending",
        "line_window": args.line_window, "max_paths": args.max_paths,
        "stage_gate_passed": bool(candidates) and all(packet.evidence for packet in packets),
    }
    atomic_write_json(out / "scan_manifest.json", scan_manifest)
    responses_path = out / "responses.jsonl"
    attempts_path = out / "verifier_attempts.jsonl"
    wire_events_path = out / "verifier_wire_events.jsonl"
    findings_path = out / "final_findings.jsonl"
    atomic_write_jsonl(responses_path, [])
    atomic_write_jsonl(attempts_path, [])
    atomic_write_jsonl(wire_events_path, [])
    atomic_write_jsonl(findings_path, [])
    if args.endpoint and args.model and not args.dry_run:
        client = VerifierClient(
            args.endpoint, args.model, temperature=args.temperature,
            top_p=args.top_p, max_tokens=args.max_tokens, context_window=getattr(args, "context_window", None),
            attempt_sink=lambda event: append_jsonl(wire_events_path, event),
        )
        pipeline = VerificationPipeline(
            context, client, guided=args.guided, expand=not args.no_expand,
            conservative_rejection=args.conservative_rejection,
        )
        findings = []
        for candidate in candidates:
            result = pipeline.run(candidate)
            findings.append(result.finding)
            append_jsonl(findings_path, result.finding)
            for response in result.responses:
                append_jsonl(responses_path, response.model_dump())
            for event in result.response_logs:
                append_jsonl(attempts_path, event)
        scan_manifest["verifier_status"] = "complete"
    else:
        findings = [FinalFinding(candidate_id=c.candidate_id, cwe=c.cwe, rule_id=c.rule_id, verdict=Verdict.UNRESOLVED, location=c.primary_location, evidence_ids=[e.id for e in p.evidence], explanation="Verifier not configured") for c, p in zip(candidates, packets)]
        atomic_write_jsonl(findings_path, findings)
        scan_manifest["verifier_status"] = "not_configured"
    scan_manifest["scan_completed"] = True
    atomic_write_json(out / "scan_manifest.json", scan_manifest)
    write_sarif(findings, out / "final_findings.sarif")
    print(json.dumps({"repository": str(root), "scanners": requested, "raw_candidates": len(raw_candidates), "candidates": len(candidates), "evidence_packets": len(packets), "output": str(out)}, indent=2))
    return 0

def manifest(args: argparse.Namespace) -> int:
    output = Path(args.output); prompt_hash = hashlib.sha256(b"prompt-set-v1").hexdigest(); config_hash = hashlib.sha256(b"config-v1").hexdigest()
    item = RunManifest(run_id=output.parent.name or "run", repository=args.repository, repository_sha=args.repo_sha, scanner_version=__version__, python_version=platform.python_version(), model=args.model, prompt_hash=prompt_hash, config_hash=config_hash, created_at=datetime.now(timezone.utc).isoformat())
    output.parent.mkdir(parents=True, exist_ok=True); output.write_text(item.model_dump_json(indent=2) + "\n"); print(output); return 0

def metrics(args: argparse.Namespace) -> int:
    labels = json.loads(Path(args.labels).read_text()); rows = []
    for line in Path(args.predictions).read_text().splitlines():
        item = json.loads(line); rows.append((item["verdict"], labels[item["candidate_id"]]))
    result = calculate_metrics(rows); print(json.dumps(result, indent=2)); return 0

def baseline(args: argparse.Namespace) -> int:
    candidates = [json.loads(line) for line in Path(args.candidates).read_text().splitlines() if line.strip()]
    result = score_codeql_candidates(candidates, load_expected_results(Path(args.expected)))
    output = Path(args.output); output.parent.mkdir(parents=True, exist_ok=True); output.write_text(json.dumps(result, indent=2) + "\n")
    output.with_suffix(".csv").write_text("scope,TP,FP,FN,TN,precision,recall,f1,f2,false_positive_rate\n" + ",".join([result["scope"], *[str(result["overall"][key]) for key in ["TP", "FP", "FN", "TN", "precision", "recall", "f1", "f2", "false_positive_rate"]]]) + "\n")
    lines = ["# CodeQL baseline", "", f"Scope: {result['scope']}", "", "| Metric | Value |", "|---|---:|"]
    lines.extend(f"| {key} | {value} |" for key, value in result["overall"].items())
    output.with_suffix(".md").write_text("\n".join(lines) + "\n")
    print(json.dumps(result, indent=2)); return 0

def candidate_report(args: argparse.Namespace) -> int:
    candidates = [json.loads(line) for line in Path(args.candidates).read_text().splitlines() if line.strip()]
    result = score_candidate_generators(candidates, load_expected_results(Path(args.expected)))
    if args.raw_candidates:
        raw = [json.loads(line) for line in Path(args.raw_candidates).read_text().splitlines() if line.strip()]
        raw_result = score_candidate_generators(raw, load_expected_results(Path(args.expected)))
        result["raw_candidate_counts"] = {name: values.get("candidate_count", 0) for name, values in raw_result["generators"].items() if name in {"codeql", "semgrep", "opengrep"}}
    output = Path(args.output); output.parent.mkdir(parents=True, exist_ok=True); output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2)); return 0

def evaluate_owasp(args: argparse.Namespace) -> int:
    findings = [json.loads(line) for line in Path(args.predictions).read_text().splitlines() if line.strip()]
    expected = load_expected_results(Path(args.expected))
    candidates = [{"candidate_id": item["candidate_id"], "cwe": item["cwe"], "primary_location": item["location"]} for item in findings]
    result = score_verifier_tests(findings, candidates, expected)
    result["prediction_count"] = len(findings)
    output = Path(args.output); output.parent.mkdir(parents=True, exist_ok=True); output.write_text(json.dumps(result, indent=2) + "\n")
    lines = ["# OWASP experiment evaluation", "", f"Scope: {result['scope']}", "", "| Metric | Value |", "|---|---:|"]
    lines.extend(f"| {key} | {value} |" for key, value in result["overall"].items())
    output.with_suffix(".md").write_text("\n".join(lines) + "\n")
    print(json.dumps(result, indent=2)); return 0

def error_analysis(args: argparse.Namespace) -> int:
    findings = [json.loads(line) for line in Path(args.predictions).read_text().splitlines() if line.strip()]
    expected = load_expected_results(Path(args.expected))
    candidates = [{"candidate_id": item["candidate_id"], "cwe": item["cwe"], "primary_location": item["location"]} for item in findings]
    labels = labels_for_candidates(candidates, expected)
    result = classify_findings(findings, labels)
    if args.candidates:
        candidates = [json.loads(line) for line in Path(args.candidates).read_text().splitlines() if line.strip()]
        result["false_negative_origin"] = classify_owasp_misses(candidates, findings, expected)
    output = Path(args.output); output.parent.mkdir(parents=True, exist_ok=True); output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["counts"], indent=2)); return 0

def experiment(args: argparse.Namespace) -> int:
    candidates = [__import__("aisast.models", fromlist=["Candidate"]).Candidate.model_validate(json.loads(line)) for line in Path(args.candidates).read_text().splitlines() if line.strip()]
    client = None
    if args.experiment not in {"A", "G1", "G2", "G3", "G4"}:
        if not args.endpoint or not args.model: raise SystemExit("experiments B-D require --endpoint and --model")
        client = VerifierClient(args.endpoint, args.model, temperature=args.temperature, top_p=args.top_p, max_tokens=args.max_tokens, context_window=getattr(args, "context_window", None))
    labels = json.loads(Path(args.labels).read_text()) if args.labels else None
    if args.expected:
        labels = labels_for_candidates([candidate.model_dump() for candidate in candidates], load_expected_results(Path(args.expected)))
    scan_manifest = json.loads(Path(args.scan_manifest).read_text()) if args.scan_manifest else None
    if scan_manifest is not None:
        scan_manifest["manifest_path"] = str(Path(args.scan_manifest).resolve())
    common = dict(client=client, labels=labels, repository_sha=args.repo_sha, quantization=args.quantization,
                  codeql_version=args.codeql_version, query_pack_version=args.query_pack_version,
                  workers=args.workers, backend=args.backend, scan_manifest=scan_manifest,
                  model_sha256=_sha256_file(Path(args.model_file)) if args.model_file else None)
    if args.repetitions > 1:
        if args.resume:
            raise ValueError("resume is only supported for a single experiment run")
        result = run_repeated_experiments(args.experiment, Path(args.repository), candidates, Path(args.output), args.repetitions, **common)
    else:
        result = run_experiment(args.experiment, Path(args.repository), candidates, Path(args.output), resume=args.resume, **common)
    print(json.dumps(result, indent=2)); return 0

def realvuln_baseline(args: argparse.Namespace) -> int:
    result = score_realvuln(Path(args.manifest), Path(args.runs), Path(args.repositories), Path(args.ground_truth), args.authorship)
    output = Path(args.output); output.parent.mkdir(parents=True, exist_ok=True); output.write_text(json.dumps(result, indent=2) + "\n")
    lines = ["# RealVuln CodeQL baseline", "", f"Scope: {result['scope']}", f"Repositories: {result['repositories']}", "", "| Metric | Value |", "|---|---:|"]
    lines.extend(f"| {key} | {value} |" for key, value in result["overall"].items())
    output.with_suffix(".md").write_text("\n".join(lines) + "\n"); print(json.dumps(result, indent=2)); return 0

def realvuln_report(args: argparse.Namespace) -> int:
    result = score_realvuln_generators(Path(args.manifest), Path(args.runs), Path(args.repositories), Path(args.ground_truth), tuple(args.engines), authorship=args.authorship)
    output = Path(args.output); output.parent.mkdir(parents=True, exist_ok=True); output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2)); return 0

def realvuln_scan(args: argparse.Namespace) -> int:
    manifest = json.loads(Path(args.manifest).read_text()); root = Path(args.repositories); output = Path(args.output); completed = []; failures = []
    for slug, metadata in manifest["repos"].items():
        if metadata.get("language") != "python" or metadata.get("authorship") != args.authorship: continue
        repository = root / slug
        for engine in args.engines:
            target = output / engine / slug / "raw.sarif"
            try:
                if engine == "codeql":
                    CodeQLRunner(args.codeql).scan(repository, target.parent, args.suite, args.max_paths, Path(args.query_search_path) if args.query_search_path else None)
                    generated = target.parent / "codeql.sarif"
                    if generated != target: target.write_bytes(generated.read_bytes())
                elif engine == "semgrep":
                    SemgrepRunner(args.semgrep).scan(repository, target, args.semgrep_config)
                else:
                    OpenGrepRunner(args.opengrep).scan(repository, target, args.opengrep_config)
                completed.append({"engine": engine, "repo": slug})
            except Exception as exc:
                failures.append({"engine": engine, "repo": slug, "error": str(exc)})
                if not args.continue_on_error: raise
    summary = {"completed": completed, "failures": failures, "output": str(output)}; output.mkdir(parents=True, exist_ok=True); (output / "scan-summary.json").write_text(json.dumps(summary, indent=2) + "\n"); print(json.dumps(summary, indent=2)); return 0 if not failures else 2

def realvuln_candidates(args: argparse.Namespace) -> int:
    candidates = load_realvuln_union_candidates(Path(args.manifest), Path(args.runs), Path(args.repositories), tuple(args.engines), authorship=args.authorship)
    output = Path(args.output); _write_jsonl(output, candidates)
    print(json.dumps({"candidates": len(candidates), "output": str(output)}, indent=2)); return 0

def realvuln_evaluate(args: argparse.Namespace) -> int:
    from aisast.models import Candidate
    candidates = [Candidate.model_validate(json.loads(line)) for line in Path(args.candidates).read_text().splitlines() if line.strip()]
    findings = [FinalFinding.model_validate(json.loads(line)) for line in Path(args.predictions).read_text().splitlines() if line.strip()]
    result = score_realvuln_findings(Path(args.manifest), candidates, findings, Path(args.ground_truth), args.authorship)
    output = Path(args.output); output.parent.mkdir(parents=True, exist_ok=True); output.write_text(json.dumps(result, indent=2) + "\n"); print(json.dumps(result, indent=2)); return 0

def check_env(args: argparse.Namespace) -> int:
    report = environment_report()
    print(json.dumps(report, indent=2)); return 0 if len(report["available"]) >= args.minimum else 1

def freeze_env(args: argparse.Namespace) -> int:
    report = write_environment_versions(Path(args.output))
    print(json.dumps(report, indent=2)); return 0

def main() -> int:
    parser = argparse.ArgumentParser(prog="aisast"); subs = parser.add_subparsers(dest="command", required=True)
    p = subs.add_parser("scan"); p.add_argument("repository"); p.add_argument("--scanner", choices=["codeql", "semgrep", "opengrep", "all"], default="codeql"); p.add_argument("--sarif"); p.add_argument("--codeql-sarif"); p.add_argument("--semgrep-sarif"); p.add_argument("--opengrep-sarif"); p.add_argument("--codeql", default="codeql", help="CodeQL executable"); p.add_argument("--semgrep", default="semgrep", help="Semgrep executable"); p.add_argument("--opengrep", default="opengrep", help="OpenGrep executable"); p.add_argument("--suite", default="codeql/python-queries:codeql-suites/python-security-extended.qls"); p.add_argument("--query-search-path", help="Local CodeQL query-pack root; avoids downloading packs"); p.add_argument("--semgrep-config", default="p/python"); p.add_argument("--opengrep-config", default="p/python"); p.add_argument("--xss-candidates", action="store_true", help="add Python response and Jinja XSS candidates and CodeQL Python XSS models"); p.add_argument("--javascript-xss", action="store_true", help="run CodeQL JavaScript security-extended queries for CWE-79"); p.add_argument("--conservative-rejection", action="store_true", help="require cited safety code before rejecting candidates"); p.add_argument("--max-paths", type=int, default=4); p.add_argument("--line-window", type=int, default=2); p.add_argument("--repo-sha", default="unknown"); p.add_argument("--output", default="runs/local"); p.add_argument("--endpoint"); p.add_argument("--model"); p.add_argument("--temperature", type=float, default=0.0); p.add_argument("--top-p", type=float, default=1.0); p.add_argument("--max-tokens", type=int, default=700); p.add_argument("--context-window", type=int, help="Enable full-prompt token budgeting using the local llama.cpp tokenizer"); p.add_argument("--guided", action=argparse.BooleanOptionalAction, default=True); p.add_argument("--no-expand", action="store_true"); p.add_argument("--dry-run", action="store_true", help="build candidates and evidence without a model"); p.set_defaults(func=scan)
    p.add_argument("--custom-rules", action=argparse.BooleanOptionalAction, default=True, help="run current custom CodeQL suspects alongside stock queries")
    p.add_argument("--custom-sarif", help="custom query SARIF to use when replaying scanner output")
    p.add_argument("--template-candidates", action=argparse.BooleanOptionalAction, default=True, help="include Jinja/Django template output suspects")
    p.add_argument("--model-pack", action="append", type=Path, default=[], help="local CodeQL model pack; may be repeated")
    p.add_argument("--no-database-extension-packs", action="store_true", help="ignore model packs embedded when the database was created")
    p.add_argument("--cwe", action="append", type=int, help="limit saved candidates and verifier inputs to CWE 22, 78, 79, or 89")
    p = subs.add_parser("manifest"); p.add_argument("--output", required=True); p.add_argument("--repository", default="unknown"); p.add_argument("--repo-sha", default="unknown"); p.add_argument("--model"); p.set_defaults(func=manifest)
    p = subs.add_parser("metrics"); p.add_argument("--predictions", required=True); p.add_argument("--labels", required=True); p.set_defaults(func=metrics)
    p = subs.add_parser("baseline"); p.add_argument("--candidates", required=True); p.add_argument("--expected", required=True); p.add_argument("--output", default="reports/baseline_codeql.json"); p.set_defaults(func=baseline)
    p = subs.add_parser("candidate-report"); p.add_argument("--candidates", required=True); p.add_argument("--raw-candidates"); p.add_argument("--expected", required=True); p.add_argument("--output", default="reports/candidate_generators.json"); p.set_defaults(func=candidate_report)
    p = subs.add_parser("evaluate-owasp"); p.add_argument("--predictions", required=True); p.add_argument("--expected", required=True); p.add_argument("--output", required=True); p.set_defaults(func=evaluate_owasp)
    p = subs.add_parser("error-analysis"); p.add_argument("--predictions", required=True); p.add_argument("--expected", required=True); p.add_argument("--candidates"); p.add_argument("--output", required=True); p.set_defaults(func=error_analysis)
    p = subs.add_parser("experiment"); p.add_argument("--experiment", choices=["A", "B", "C", "D", "G1", "G2", "G3", "G4", "V1", "V2", "P3"], required=True); p.add_argument("--repository", required=True); p.add_argument("--candidates", required=True); p.add_argument("--scan-manifest"); p.add_argument("--output", required=True); p.add_argument("--repetitions", type=int, default=1); p.add_argument("--resume", action="store_true", help="continue a run after validating its saved candidates, evidence, findings, prompts, and responses"); p.add_argument("--workers", type=int, default=1); p.add_argument("--repo-sha", default="unknown"); p.add_argument("--labels"); p.add_argument("--expected"); p.add_argument("--endpoint"); p.add_argument("--model"); p.add_argument("--model-file", help="GGUF checkpoint to hash in the run manifest"); p.add_argument("--quantization"); p.add_argument("--backend", default="llama.cpp"); p.add_argument("--codeql-version"); p.add_argument("--query-pack-version"); p.add_argument("--temperature", type=float, default=0.0); p.add_argument("--top-p", type=float, default=1.0); p.add_argument("--max-tokens", type=int, default=400); p.set_defaults(func=experiment)
    p = subs.add_parser("realvuln-baseline"); p.add_argument("--manifest", required=True); p.add_argument("--runs", required=True); p.add_argument("--repositories", required=True); p.add_argument("--ground-truth", required=True); p.add_argument("--output", default="reports/baseline_realvuln_codeql.json"); p.set_defaults(func=realvuln_baseline)
    p.add_argument("--authorship", default="human_authored")
    p = subs.add_parser("realvuln-report"); p.add_argument("--manifest", required=True); p.add_argument("--runs", required=True); p.add_argument("--repositories", required=True); p.add_argument("--ground-truth", required=True); p.add_argument("--engines", nargs="+", default=["codeql", "semgrep", "opengrep"]); p.add_argument("--output", default="reports/realvuln-generators.json"); p.set_defaults(func=realvuln_report)
    p.add_argument("--authorship", default="human_authored")
    p = subs.add_parser("realvuln-scan"); p.add_argument("--manifest", required=True); p.add_argument("--repositories", required=True); p.add_argument("--output", default="runs/realvuln-multisast"); p.add_argument("--engines", nargs="+", default=["codeql", "semgrep", "opengrep"]); p.add_argument("--codeql", default="codeql"); p.add_argument("--semgrep", default="semgrep"); p.add_argument("--opengrep", default="opengrep"); p.add_argument("--suite", default="codeql/python-queries:codeql-suites/python-security-extended.qls"); p.add_argument("--query-search-path"); p.add_argument("--semgrep-config", default="p/python"); p.add_argument("--opengrep-config", default="p/python"); p.add_argument("--max-paths", type=int, default=4); p.add_argument("--continue-on-error", action="store_true"); p.set_defaults(func=realvuln_scan)
    p.add_argument("--authorship", default="human_authored")
    p = subs.add_parser("realvuln-candidates"); p.add_argument("--manifest", required=True); p.add_argument("--runs", required=True); p.add_argument("--repositories", required=True); p.add_argument("--engines", nargs="+", default=["codeql", "semgrep", "opengrep"]); p.add_argument("--output", default="runs/realvuln-multisast/union-candidates.jsonl"); p.set_defaults(func=realvuln_candidates)
    p.add_argument("--authorship", default="human_authored")
    p = subs.add_parser("realvuln-evaluate"); p.add_argument("--manifest", required=True); p.add_argument("--candidates", required=True); p.add_argument("--predictions", required=True); p.add_argument("--ground-truth", required=True); p.add_argument("--output", default="reports/realvuln-verifier.json"); p.set_defaults(func=realvuln_evaluate)
    p.add_argument("--authorship", default="human_authored")
    p = subs.add_parser("check-env"); p.add_argument("--minimum", type=int, default=0, help="minimum number of available scanner CLIs"); p.set_defaults(func=check_env)
    p = subs.add_parser("freeze-env"); p.add_argument("--output", default="versions"); p.set_defaults(func=freeze_env)
    return args_func(parser.parse_args())

def args_func(args: argparse.Namespace) -> int:
    return args.func(args)

if __name__ == "__main__": raise SystemExit(main())
