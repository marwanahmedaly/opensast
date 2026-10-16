from __future__ import annotations

import hashlib
from collections import defaultdict
from pathlib import Path

from aisast.models import Candidate, Location


def _cluster_key(candidate: Candidate, line_window: int) -> tuple[int, str, int]:
    location = candidate.sink or candidate.primary_location
    # A small window accounts for scanner-specific sink line selection while
    # retaining CWE and file as hard identity components.
    return candidate.cwe, location.file, location.line // max(1, line_window)


def _same_cluster(left: Candidate, right: Candidate, line_window: int) -> bool:
    if left.cwe != right.cwe:
        return False
    l = left.sink or left.primary_location
    r = right.sink or right.primary_location
    if "expression" in left.properties or "expression" in right.properties:
        # Distinct template fields/contexts on one line are distinct suspects.
        # Do not collapse them through a neighboring Python/engine alert.
        if left.properties.get("expression") != right.properties.get("expression"):
            return False
        if l.column != r.column:
            return False
    return l.file == r.file and abs(l.line - r.line) <= line_window


def _merged_id(repository_sha: str, members: list[Candidate]) -> str:
    identity = sorted(
        f"{item.cwe}:{(item.sink or item.primary_location).file}:{(item.sink or item.primary_location).line}"
        + (f":{(item.sink or item.primary_location).column}:{item.properties['expression']}" if "expression" in item.properties else "")
        for item in members
    )
    return hashlib.sha256((repository_sha + "\0" + "\0".join(identity)).encode()).hexdigest()


def fuse_candidates(candidates: list[Candidate], line_window: int = 2) -> list[Candidate]:
    """Merge independent scanner alerts into testable vulnerability candidates.

    Candidates with the same CWE, file and nearby sink location are clustered.
    All scanner and rule provenance survives in the merged object.  A single
    scanner candidate is also normalized to carry its scanner name, inferred
    from ``properties.engine`` when callers did not set ``engines``.
    """
    clusters: list[list[Candidate]] = []
    buckets: dict[tuple[int, str, int], list[int]] = defaultdict(list)
    for candidate in candidates:
        engines = candidate.engines or [str(candidate.properties.get("engine", "unknown"))]
        candidate = candidate.model_copy(update={"engines": engines, "rules": candidate.rules or [candidate.rule_id]})
        key = _cluster_key(candidate, line_window)
        nearby: list[int] = []
        for delta in (-1, 0, 1):
            nearby.extend(buckets.get((key[0], key[1], key[2] + delta), []))
        matches = [index for index in nearby if _same_cluster(clusters[index][0], candidate, line_window)]
        if matches:
            clusters[matches[0]].append(candidate)
        else:
            index = len(clusters)
            clusters.append([candidate])
            buckets[key].append(index)

    merged: list[Candidate] = []
    for members in clusters:
        first = members[0]
        engines = sorted({engine for member in members for engine in (member.engines or ["unknown"])})
        rules = sorted({rule for member in members for rule in (member.rules or [member.rule_id])})
        aliases = [member.candidate_id for member in members]
        props = dict(first.properties)
        evidence_locations = [location for member in members
                              for location in member.properties.get("evidence_locations", []) or []]
        if evidence_locations:
            props["evidence_locations"] = list({str(location): location for location in evidence_locations}.values())
        props["engines"] = engines
        props["rules"] = rules
        props["provenance"] = [entry for member in members for entry in member.properties.get("provenance", [])]
        merged.append(first.model_copy(update={
            "candidate_id": _merged_id(first.repository_sha, members),
            "engines": engines,
            "rules": rules,
            "aliases": aliases,
            "properties": props,
        }))
    return merged


def candidates_by_engine(candidates: list[Candidate]) -> dict[str, list[Candidate]]:
    result: dict[str, list[Candidate]] = defaultdict(list)
    for candidate in candidates:
        for engine in candidate.engines or [str(candidate.properties.get("engine", "unknown"))]:
            result[engine].append(candidate)
    return dict(result)
