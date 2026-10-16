from __future__ import annotations

import re

from aisast.models import EvidencePacket, VerificationResult, Verdict


_SAFETY_PATTERNS = {
    89: (r"\.execute\s*\(\s*['\"][^'\"]*(?:\?|%s|:\w+|\$\d+)[^'\"]*['\"]\s*,",),
    79: (r"\b(?:escape|html\.escape|markupsafe\.escape)\s*\(", r"\|\s*escape\b", r"\bautoescape\s+(?:true|on)\b", r"\.textContent\s*="),
    78: (r"\b(?:shlex\.quote|quote)\s*\(", r"\b(?:subprocess\.(?:run|Popen)|check_output|check_call)\s*\(\s*\["),
    22: (r"\.is_relative_to\s*\(", r"\b(?:commonpath|safe_join|secure_filename)\s*\("),
}


def has_verified_safety(packet: EvidencePacket, result: VerificationResult) -> bool:
    """A rejection needs cited code showing a concrete safety mechanism.

    This is deliberately conservative: ambiguous safety goes to review. The
    verifier can still cite a sink block when the protection is inline there.
    """
    cited = set(result.sanitizer_evidence + result.sink_evidence)
    if not cited:
        return False
    for block in packet.evidence:
        if block.id not in cited:
            continue
        if block.id in result.sanitizer_evidence:
            code = re.sub(r"(?m)^\s*\d+\s*\|\s?", "", block.code)
            code = "\n".join(line for line in code.splitlines() if not line.lstrip().startswith("#"))
        else:
            sink_line = (packet.candidate.sink or packet.candidate.primary_location).line
            code = "\n".join(match.group(2) for line in block.code.splitlines()
                             if (match := re.match(r"\s*(\d+)\s*\|\s?(.*)", line)) and int(match.group(1)) == sink_line)
            if not code and block.start_line == sink_line == block.end_line:
                code = block.code
        if any(re.search(pattern, code, re.IGNORECASE) for pattern in _SAFETY_PATTERNS.get(packet.candidate.cwe, ())):
            return True
    return False


def apply_acceptance_policy(packet: EvidencePacket, result: VerificationResult) -> Verdict:
    if result.verdict == Verdict.NOT_VULNERABLE and not has_verified_safety(packet, result):
        return Verdict.UNRESOLVED
    if result.verdict == Verdict.NEEDS_MORE_CONTEXT:
        return Verdict.UNRESOLVED
    return result.verdict
