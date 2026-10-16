"""Fit complete rendered prompts, retaining whole evidence blocks and audit gaps."""
from __future__ import annotations

from typing import Callable
from aisast.context.context_builder import ContextBuilder
from aisast.models import EvidencePacket
from aisast.verifier.prompts import render_prompt
from aisast.verifier.schemas import VerificationError


def fit_packet(packet: EvidencePacket, count: Callable[[str], int], limit: int,
               guided: bool = True) -> EvidencePacket:
    if limit <= 0:
        raise VerificationError('Context window leaves no prompt budget')
    result = packet.model_copy(deep=True)
    before = count(render_prompt(result, guided))
    if before <= limit:
        return result
    # Protect the smallest complete supplied excerpt for each reported anchor.
    protected = set()
    for location in (packet.candidate.primary_location, packet.candidate.source, packet.candidate.sink):
        if location:
            blocks = [e for e in result.evidence if e.file == location.file
                      and e.start_line <= location.line <= e.end_line and not e.truncated]
            if blocks:
                protected.add(min(blocks, key=lambda e: (len(e.code), e.end_line-e.start_line)).id)
    omitted = []
    tokens = before
    while tokens > limit:
        removable = [e for e in reversed(result.evidence) if e.id not in protected]
        if not removable:
            raise VerificationError('Reported anchors and prompt instructions exceed token budget; no model request sent',
                                    prompt=render_prompt(result, guided))
        # Remove lower-priority whole excerpts. Recount the actual chat prompt,
        # including evidence labels, framework facts and call relationships.
        target = tokens - limit
        estimated = 0
        remove = set()
        for block in removable:
            remove.add(block.id)
            omitted.append({'id': block.id, 'file': block.file,
                            'start_line': block.start_line, 'end_line': block.end_line})
            estimated += (len(block.code) + len(block.file)) // 4 + 25
            if estimated >= target:
                break
        result.evidence = [e for e in result.evidence if e.id not in remove]
        events = [e for e in packet.context_resolution if e.get('kind') != 'prompt_token_budget']
        result.context_resolution = ContextBuilder._resolution_status(events, result.evidence)
        missing = {r['fact'] for r in result.context_resolution
                   if r.get('fact') and not r.get('included', True)}
        result.framework_facts = [f for f in packet.framework_facts if f not in missing]
        result.context_truncated = True
        result.incomplete_evidence_blocks = packet.incomplete_evidence_blocks + len(omitted)
        result.context_resolution.append({'kind': 'prompt_token_budget', 'status': 'omitted_by_token_budget',
                                         'initial_prompt_tokens': before, 'prompt_token_limit': limit,
                                         'omitted_blocks': omitted.copy()})
        tokens = count(render_prompt(result, guided))
    result.context_resolution[-1]['final_prompt_tokens'] = tokens
    return result
