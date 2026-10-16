from __future__ import annotations

import re
from dataclasses import dataclass

from aisast.models import EvidencePacket, VerificationResult


@dataclass
class Validation:
    valid: bool
    errors: list[str]


class EvidenceGate:
    def validate(self, packet: EvidencePacket, result: VerificationResult) -> Validation:
        errors: list[str] = []
        ids = {e.id for e in packet.evidence}
        if result.candidate_id != packet.candidate.candidate_id: errors.append("candidate_id does not match packet")
        if result.cwe is not None and result.cwe != packet.candidate.cwe: errors.append("model CWE does not match candidate CWE")
        cited = result.source_evidence + result.sink_evidence + result.sanitizer_evidence
        for evidence_id in cited:
            if evidence_id not in ids: errors.append(f"unknown evidence id: {evidence_id}")
        if packet.candidate.cwe in {22, 78, 79, 89} and result.verdict.value == "VULNERABLE":
            if not result.sink_evidence: errors.append("confirmed flow finding must cite sink evidence")
            if not result.source_evidence: errors.append("confirmed flow finding must cite source evidence")
        # Structured citations remain ID-bound. Optional prose references are
        # valid only when uniquely matched to actually displayed packet lines.
        # A requested missing symbol is not a factual claim about supplied code.
        for match in re.finditer(r"([\w./-]+\.(?:py|html|htm|jinja2?|j2)):(\d+)", result.explanation):
            file, line = match[1], int(match[2])
            files = {block.file for block in packet.evidence
                     if block.file == file or block.file.endswith('/' + file)}
            if len(files) != 1 or not any(block.file in files
                                        and block.start_line <= line <= block.end_line
                                        for block in packet.evidence):
                errors.append(f"unbound or ambiguous prose citation: {file}:{line}")
        return Validation(not errors, errors)
