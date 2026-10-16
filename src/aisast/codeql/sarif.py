from __future__ import annotations

import json
from pathlib import Path

from aisast.models import FinalFinding

def write_sarif(findings: list[FinalFinding], output: Path) -> None:
    results = []
    for finding in findings:
        result = {"ruleId": finding.rule_id, "message": {"text": finding.explanation or finding.verdict.value}, "level": "error" if finding.verdict == "VULNERABLE" else "note", "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.location.file}, "region": {"startLine": finding.location.line}}}], "properties": {"cwe": finding.cwe, "candidate_id": finding.candidate_id, "verdict": finding.verdict.value, "evidence_ids": finding.evidence_ids}}
        results.append(result)
    payload = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "aisast", "version": "0.1.0"}}, "results": results}]}
    output.parent.mkdir(parents=True, exist_ok=True); output.write_text(json.dumps(payload, indent=2) + "\n")
