from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from aisast.models import Candidate, Location

RULE_CWES = {"sql-injection": 89, "command-injection": 78, "reflected-xss": 79, "path-injection": 22, "path-traversal": 22}


def _cwe(rule: dict[str, Any]) -> int | None:
    for tag in rule.get("properties", {}).get("tags", []) or []:
        if isinstance(tag, str):
            match = re.search(r"cwe[-_](\d+)", tag.lower())
            if match: return int(match.group(1))
    rid = str(rule.get("id", "")).lower()
    for key, value in RULE_CWES.items():
        if key in rid: return value
    return None


def _supported_cwes(rule: dict[str, Any]) -> list[int]:
    """Do not discard a supported component because another tag came first."""
    tagged = set()
    for tag in rule.get("properties", {}).get("tags", []) or []:
        if isinstance(tag, str):
            match = re.search(r"cwe[-_](\d+)", tag.lower())
            if match:
                tagged.add(int(match[1]))
    if not tagged:
        inferred = _cwe(rule)
        if inferred is not None:
            tagged.add(inferred)
    return sorted(tagged & {22, 78, 79, 89})


def _location(item: dict[str, Any], root: Path | None = None) -> Location | None:
    physical = item.get("physicalLocation", {})
    artifact = physical.get("artifactLocation", {})
    uri = artifact.get("uri") or artifact.get("uriBaseId")
    region = physical.get("region", {})
    if not uri or not region.get("startLine"): return None
    file = str(uri)
    if root and file.startswith("file://"): file = file.removeprefix("file://")
    if root:
        path = Path(file)
        # SARIF producers may emit either a path relative to the scanned
        # repository or a path relative to the process working directory.
        # Normalize both before matching ground truth or reading source code.
        if path.is_absolute() or not (root / path).exists():
            relative = None
            try:
                resolved = path.resolve().relative_to(root.resolve())
                if (root / resolved).exists():
                    relative = resolved
            except ValueError:
                pass
            if relative is None and not path.is_absolute():
                root_parts = root.resolve().parts
                for start in range(len(root_parts)):
                    prefix = root_parts[start:]
                    if path.parts[:len(prefix)] == prefix:
                        candidate = Path(*path.parts[len(prefix):])
                        if (root / candidate).exists():
                            relative = candidate
                            break
            if relative is not None:
                file = str(relative)
    return Location(file=file, line=int(region["startLine"]), column=region.get("startColumn"))


def _candidate_id(repo_sha: str, rule: str, sink: Location, source: Location | None, engine: str = "codeql") -> str:
    parts = [repo_sha, engine, rule, sink.file, str(sink.line), source.file if source else "", str(source.line) if source else ""]
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()


def normalize_sarif(sarif: dict[str, Any], repository_sha: str = "unknown", source_root: str | Path | None = None, engine: str = "codeql") -> list[Candidate]:
    root = Path(source_root) if source_root else None
    candidates: list[Candidate] = []
    for run in sarif.get("runs", []):
        rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            rule = rules.get(rule_id, {"id": rule_id})
            cwes = _supported_cwes(rule)
            if not cwes: continue
            locations = result.get("locations", [])
            primary = _location(locations[0], root) if locations else None
            if not primary: continue
            paths = result.get("codeFlows", [])
            code_flows: list[list[Location]] = []
            for flow in paths:
                for thread in flow.get("threadFlows", []):
                    locations_in_path: list[Location] = []
                    for loc in thread.get("locations", []):
                        parsed = _location(loc.get("location", {}), root)
                        if parsed:
                            locations_in_path.append(parsed)
                    if locations_in_path:
                        code_flows.append(locations_in_path)
            # A SARIF result can carry several alternative thread flows. Keep
            # them grouped; flattening them fabricates a single path whose
            # source and sink may belong to different alternatives.
            path_locations = code_flows[0] if code_flows else []
            source = path_locations[0] if path_locations else None
            sink = path_locations[-1] if path_locations else primary
            properties = dict(result.get("properties", {}))
            if code_flows:
                properties["code_flows"] = [
                    [location.model_dump(mode="json") for location in path]
                    for path in code_flows
                ]
            properties["engine"] = engine
            properties["provenance"] = [{
                "engine": engine,
                "rule_id": rule_id,
                "rule_version": rule.get("version"),
                "severity": result.get("level") or rule.get("defaultConfiguration", {}).get("level"),
                "message": result.get("message", {}).get("text", ""),
                "cwe_tags": [tag for tag in rule.get("properties", {}).get("tags", []) if isinstance(tag, str) and "cwe" in tag.lower()],
            }]
            for cwe in cwes:
                identity_rule = rule_id if len(cwes) == 1 else f"{rule_id}:cwe-{cwe}"
                candidates.append(Candidate(candidate_id=_candidate_id(repository_sha, identity_rule, sink, source, engine), repository_sha=repository_sha, rule_id=rule_id, cwe=cwe, title=result.get("message", {}).get("text", rule.get("name", rule_id)), message=result.get("message", {}).get("text", ""), primary_location=primary, source=source, sink=sink, path=path_locations, properties=properties, engines=[engine], rules=[rule_id]))
    return candidates


def load_and_normalize(path: Path, repository_sha: str = "unknown", source_root: str | Path | None = None, engine: str = "codeql") -> list[Candidate]:
    return normalize_sarif(__import__("json").loads(path.read_text()), repository_sha, source_root, engine)
