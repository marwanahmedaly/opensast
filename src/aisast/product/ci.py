"""Offline CI entry point using the same product scan and verifier pipeline."""
from __future__ import annotations

import difflib
import fcntl
import json
import uuid
from pathlib import Path

from .git_changes import changes, export_revision, git
from .incremental import atomic_json, identity, inventory
from .scan_job import execute, load
from .store import private_directory


def scan(root, state, settings, full=False):
    job = uuid.uuid4().hex
    execute(root, state, job, settings, full)
    run = state / "runs" / job
    atomic_json(state / "baseline.json", load(run / "next-baseline.json"))
    return load(run / "result.json"), run / "source"


def ensure_checkout(root, commit, source):
    if not source.exists():
        temporary = source.with_name("checkout-incomplete-" + uuid.uuid4().hex)
        export_revision(root, commit, temporary)
        temporary.rename(source)


def comparison(current, baseline, current_source, base_source):
    """Match unchanged operation lines, tolerating insertions above them.

    Modified operations, renamed files, or new verifier-positive decisions are
    conservatively new alerts. A changed verdict cannot hide behind a candidate ID.
    """
    maps = {}

    def location(value):
        if value is None:
            return None
        name, line = value["file"], value["line"]
        if name not in maps:
            before, after = base_source / name, current_source / name
            mapping = {}
            if before.is_file() and after.is_file():
                old = before.read_bytes().splitlines()
                new = after.read_bytes().splitlines()
                for block in difflib.SequenceMatcher(None, old, new, autojunk=False).get_matching_blocks():
                    mapping.update({block.b + i + 1: block.a + i + 1 for i in range(block.size)})
            maps[name] = mapping
        mapped = maps[name].get(line)
        return (name, mapped, value.get("column")) if mapped else (name, "modified", line, value.get("column"))

    def key(finding, head=False):
        candidate = finding["candidate"]
        loc = location if head else lambda v: (v["file"], v["line"], v.get("column")) if v else None
        return (candidate["cwe"], candidate["rule_id"], loc(candidate["primary_location"]),
                loc(candidate.get("source")), loc(candidate.get("sink")))

    old = {key(f): f for f in baseline["findings"] if f["verdict"] == "VULNERABLE"}
    existing, introduced, matched = [], [], set()
    for finding in current["findings"]:
        if finding["verdict"] != "VULNERABLE":
            continue
        value = key(finding, True)
        if value in old:
            existing.append(finding["finding_id"])
            matched.add(value)
        else:
            introduced.append(finding["finding_id"])
    return {"new_alert_ids": sorted(introduced), "existing_alert_ids": sorted(existing),
            "no_longer_reported_alert_ids": sorted(old[k]["finding_id"] for k in old.keys() - matched),
            "matching_policy": "CWE/rule and unchanged primary/source/sink lines; changed or renamed operations count as new",
            "note": "No longer reported does not establish that a vulnerability was fixed."}


def run(args, settings):
    root = Path.cwd().resolve()
    metadata = changes(root, args.base)
    state = args.state.resolve()
    output = args.output.resolve()
    if state.is_relative_to(root) or output.is_relative_to(root):
        raise RuntimeError("CI state and output must be outside the scanned checkout")
    private_directory(state)
    project = private_directory(state / identity(settings["project_id"]))
    with (project / "ci.lock").open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Another CI scan is using this project's cache")
        if args.base:
            commit = metadata["merge_base"]
            base_state = private_directory(project / "bases" / commit)
            source = base_state / "checkout"
            ensure_checkout(root, commit, source)
            baseline, base_source = scan(source, base_state, settings, args.full)
            # PR runs never overwrite the trusted commit baseline.
            head_state = private_directory(project / "heads" / identity({"head": metadata["head"], "base": commit}))
            if not (head_state / "baseline.json").exists():
                previous = load(base_state / "baseline.json")
                old_run = previous["job_id"]
                atomic_json(head_state / "runs" / old_run / "result.json", baseline)
                atomic_json(head_state / "baseline.json", previous)
            current, current_source = scan(root, head_state, settings, args.full)
            if current["summary"]["analysis_identity"] != baseline["summary"]["analysis_identity"]:
                raise RuntimeError("Analysis configuration changed between baseline and head scans")
            delta = comparison(current, baseline, current_source, base_source)
            delta["base_commit"] = commit
            delta["base_summary"] = baseline["summary"]
        else:
            branch_state = private_directory(project / "branch")
            current, _ = scan(root, branch_state, settings, args.full)
            delta = {"new_alert_ids": [f["finding_id"] for f in current["findings"] if f["verdict"] == "VULNERABLE"],
                     "existing_alert_ids": [], "note": "No --base: all current alerts are reported; no PR introduction claim."}
            # A clean branch/push scan can warm the exact commit cache for later
            # PRs. Never label ignored/local modifications as committed source.
            if not metadata["changed_files"] and not any(entry.startswith(b"160000 ") for entry in git(root, "ls-tree", "-r", metadata["head"]).splitlines()):
                base_state = private_directory(project / "bases" / metadata["head"])
                source = base_state / "checkout"
                ensure_checkout(root, metadata["head"], source)
                previous = load(branch_state / "baseline.json")
                if inventory(source) == previous["files"]:
                    old_run = previous["job_id"]
                    atomic_json(base_state / "runs" / old_run / "result.json", current)
                    atomic_json(base_state / "baseline.json", previous)
        if changes(root, args.base) != metadata or (current.get("git") or {}).get("head") != metadata["head"]:
            raise RuntimeError("Git revision changed during CI scanning; rerun on a stable checkout")
        current["git"] = metadata
        current["pull_request"] = delta
        issues = sum(f["verdict"] in {"SYSTEM_ERROR", "UNRESOLVED", "NEEDS_MORE_CONTEXT"} for f in current["findings"])
        if args.base:
            issues += sum(f["verdict"] in {"SYSTEM_ERROR", "UNRESOLVED", "NEEDS_MORE_CONTEXT"} for f in baseline["findings"])
        current["pull_request"]["incomplete_decisions_both_revisions"] = issues
        atomic_json(output, current)
        print(json.dumps({"report": str(output), "summary": current["summary"], "pull_request": delta,
                          "unresolved_or_errors": issues}, indent=2))
        if issues:
            return 2
        return 1 if args.fail_on == "new" and delta["new_alert_ids"] else 0
