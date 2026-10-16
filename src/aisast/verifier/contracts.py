"""Opt-in verifier experiments; no changes to the default verifier contract.

Citation constraints establish output completeness, not source control, feasible
flow or the correctness of a safety explanation. The evidence gate still applies.
"""
from copy import deepcopy

from aisast.models import EvidencePacket
from aisast.verifier.prompts import render_prompt


DECISION_CONTRACT = (
    "EVIDENCE DECISION CONTRACT: Cite actual attacker-controlled producers, not fixed seed/test "
    "values or control of a record selector. Match producers, storage and output to the selected "
    "application; a matching name alone does not prove that relationship. Programmer intent, "
    "authentication and reassuring file names are not safety mechanisms. Deliberate raw HTML "
    "rendering (including safe/mark_safe) is not itself sanitization; bound SQL does not escape "
    "HTML. Judge the effect of a cited defense on accepted input in this output context. "
    "If source, flow or defense applicability is missing, return NEEDS_MORE_CONTEXT; do not "
    "assume a hypothetical validation step. VULNERABLE requires nonempty source and sink citations."
)


def decision_prompt(packet: EvidencePacket, guided: bool = True) -> str:
    return add_decision_contract(render_prompt(packet, guided))


def add_decision_contract(prompt: str) -> str:
    marker = 'FINAL DECISION CHECK:'
    if marker not in prompt:
        raise ValueError('Verifier final decision marker missing')
    return prompt.replace(marker, DECISION_CONTRACT + '\n\n' + marker, 1)


def bound_schema(packet: EvidencePacket, citation_contract: bool = False) -> dict:
    from aisast.verifier.client import OUTPUT_SCHEMA
    schema = deepcopy(OUTPUT_SCHEMA)
    schema['properties']['candidate_id'] = {'type': 'string', 'const': packet.candidate.candidate_id}
    schema['properties']['cwe'] = {'type': 'integer', 'const': packet.candidate.cwe}
    ids = sorted({e.id for e in packet.evidence})
    for key in ('source_evidence', 'sink_evidence', 'sanitizer_evidence'):
        schema['properties'][key]['items'] = {'type': 'string', 'enum': ids} if ids else {'type': 'string'}
        if not ids:
            schema['properties'][key]['maxItems'] = 0
    if not citation_contract:
        return schema
    # llama.cpp cannot reliably mix root properties with oneOf. Each verdict
    # alternative therefore contains a complete object schema. No if/then.
    vulnerable = deepcopy(schema)
    vulnerable['properties']['verdict'] = {'const': 'VULNERABLE'}
    for key in ('source_evidence', 'sink_evidence'):
        vulnerable['properties'][key]['minItems'] = 1
    other = deepcopy(schema)
    other['properties']['verdict']['enum'] = ['NOT_VULNERABLE', 'NEEDS_MORE_CONTEXT', 'UNRESOLVED']
    return {'oneOf': [vulnerable, other]} if ids else {'oneOf': [other]}
