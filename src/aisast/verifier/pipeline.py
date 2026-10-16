from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aisast.context.context_builder import ContextBuilder
from aisast.context.evidence import EvidenceGate
from aisast.models import Candidate, FinalFinding, EvidencePacket, Verdict, VerificationResult
from aisast.plan4.sql_identifier_guard import prove_quoted_sqlite_identifier
from aisast.verifier.client import VerifierClient
from aisast.verifier.schemas import VerificationError
from aisast.verifier.policy import apply_acceptance_policy


@dataclass
class PipelineResult:
    finding: FinalFinding
    packet: EvidencePacket
    responses: list[VerificationResult]
    response_logs: list[dict[str, Any]]


class VerificationPipeline:
    """Run one candidate with one initial and at most one context-expanded call."""

    def __init__(self, context: ContextBuilder, client: VerifierClient, guided: bool = True, expand: bool = True, conservative_rejection: bool = False) -> None:
        self.context, self.client, self.guided, self.expand = context, client, guided, expand
        self.conservative_rejection = conservative_rejection
        self.gate = EvidenceGate()

    def run(self, candidate: Candidate) -> PipelineResult:
        packet = self.context.packet(candidate)
        responses: list[VerificationResult] = []
        response_logs: list[dict[str, Any]] = []
        try:
            if hasattr(self.client, "prepare_packet"):
                packet = self.client.prepare_packet(packet, guided=self.guided)
            first, first_meta = self.client.verify(packet, guided=self.guided)
            responses.append(first)
            response_logs.append({"candidate_id": candidate.candidate_id, "response": first.model_dump(), **first_meta})
            if first.verdict in {Verdict.NEEDS_MORE_CONTEXT, Verdict.UNRESOLVED} and self.expand and first.missing_symbols:
                expanded = self.context.packet(candidate, first.missing_symbols)
                if hasattr(self.client, "prepare_packet"):
                    expanded = self.client.prepare_packet(expanded, guided=self.guided)
                response_logs[-1]["context_expansion"] = {
                    "requested": first.missing_symbols,
                    "new_evidence_ids": sorted({e.id for e in expanded.evidence} - {e.id for e in packet.evidence}),
                    "removed_evidence_ids": sorted({e.id for e in packet.evidence} - {e.id for e in expanded.evidence}),
                    "resolution": expanded.context_resolution,
                }
                if {e.id for e in expanded.evidence} != {e.id for e in packet.evidence}:
                    packet = expanded
                    second, second_meta = self.client.verify(packet, guided=self.guided)
                    responses.append(second)
                    response_logs.append({"candidate_id": candidate.candidate_id, "response": second.model_dump(), **second_meta})
                    result = second
                else:
                    # Preserve no-op resolution diagnostics without triggering
                    # another identical model request.
                    packet = expanded
                    result = first
            else:
                result = first
        except VerificationError as exc:
            result = self.client.system_error(candidate.candidate_id, str(exc))
            responses.append(result)
            response_logs.append({"candidate_id": candidate.candidate_id, "response": result.model_dump(),
                                  "error": str(exc), "attempt_log": exc.attempt_log,
                                  "prompt": exc.prompt, "prompt_hash": exc.prompt_hash,
                                  "model": exc.model})
        validation = self.gate.validate(packet, result)
        verdict = apply_acceptance_policy(packet, result) if self.conservative_rejection else result.verdict
        if verdict == Verdict.NEEDS_MORE_CONTEXT:
            verdict = Verdict.UNRESOLVED
        if not validation.valid and verdict not in {Verdict.SYSTEM_ERROR, Verdict.NEEDS_MORE_CONTEXT}:
            missing_flow_evidence = {"confirmed flow finding must cite source evidence",
                                     "confirmed flow finding must cite sink evidence"}
            # Missing flow support is an unresolved security judgment. Invalid
            # IDs, wrong CWE and malformed references remain operational errors.
            verdict = (Verdict.UNRESOLVED if set(validation.errors) <= missing_flow_evidence
                       else Verdict.SYSTEM_ERROR)
        explanation = result.explanation
        if (verdict == Verdict.VULNERABLE and candidate.cwe == 89 and candidate.sink and
                candidate.rule_id == "aisast/plan4-direct-cwe-89"):
            proof = prove_quoted_sqlite_identifier(
                self.context.root, candidate.sink.file, candidate.sink.line)
            if proof:
                verdict = Verdict.NOT_VULNERABLE
                explanation = ("SQLite identifier quotes are doubled before the quoted "
                               f"SQL use at {proof['file']}:{proof['sink_line']}.")
                response_logs.append({"candidate_id": candidate.candidate_id,
                                      "structural_guard": proof,
                                      "overrode_verdict": result.verdict.value})
        finding = FinalFinding(candidate_id=candidate.candidate_id, cwe=candidate.cwe, rule_id=candidate.rule_id, verdict=verdict, location=candidate.primary_location, evidence_ids=result.source_evidence + result.sink_evidence + result.sanitizer_evidence, explanation=explanation, validation_errors=validation.errors)
        return PipelineResult(finding, packet, responses, response_logs)
