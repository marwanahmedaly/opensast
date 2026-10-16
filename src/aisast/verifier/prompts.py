from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

from aisast.models import EvidencePacket
from aisast.verifier.binding_notes import framework_lines

ASSET_ROOT = Path(__file__).with_name("assets")
QUESTION_FILE = ASSET_ROOT / "python_questions.yaml"
PROFILE_FILE = ASSET_ROOT / "rule_categories.yaml"


@lru_cache(maxsize=1)
def guided_profiles() -> dict[int, list[str]]:
    """Use the pinned VulnHunterX CWE routing and Python question templates."""
    mapping = yaml.safe_load(PROFILE_FILE.read_text())["cwe_question_map"]
    templates = yaml.safe_load(QUESTION_FILE.read_text())
    result = {}
    for cwe in (22, 78, 79, 89):
        key = f"py/{mapping[f'CWE-{cwe}']}"
        questions = templates[key]["questions"]
        if not questions:
            raise ValueError(f"missing VulnHunterX guided questions: {key}")
        # The upstream binary-verdict questions conflict with our three-way
        # evidence policy. Keep the tracing questions, adapt the final verdict.
        result[cwe] = [
            ("At the reported operation, return NOT_VULNERABLE when the supplied code demonstrates "
             "a concrete defense for this CWE. Otherwise return VULNERABLE only with a supported "
             "input-to-sink mechanism; return NEEDS_MORE_CONTEXT for the missing relationship. "
             "A documented framework parameter binding can establish external input without "
             "a literal request.args/form/json access. Cite its supplied declaration evidence."
             if "verdict False Positive." in question else question)
            for question in questions
        ]
    return result


def profile_for(cwe: int) -> str:
    return f"CWE-{cwe}"


def render_prompt(packet: EvidencePacket, guided: bool = True) -> str:
    c = packet.candidate
    questions = guided_profiles()[c.cwe] if guided else [
        "Does the supplied evidence demonstrate a vulnerability mechanism?"
    ]
    evidence = "\n\n".join(
        f"[{item.id}] FILE: {item.file} LINES: {item.start_line}-{item.end_line} KIND: {item.kind}"
        + (
            f" TRUNCATED: original excerpt continued through line {item.source_end_line}; "
            "only the displayed lines are available."
            if item.truncated else ""
        )
        + f"\n{item.code}"
        for item in packet.evidence
    )

    path_lines = []
    code_flows = c.properties.get("code_flows", [])
    if isinstance(code_flows, list):
        for index, flow in enumerate(code_flows, 1):
            if not isinstance(flow, list):
                continue
            locations = [
                f"{location.get('file')}:{location.get('line')}"
                for location in flow
                if isinstance(location, dict)
            ]
            if locations:
                path_lines.append(f"{index}. " + " -> ".join(locations))
    codeql_paths = (
        "\n\nCODEQL POSSIBLE FLOW PATHS (static-analysis traces; assess them against the code below):\n"
        + "\n".join(path_lines)
        if path_lines else ""
    )
    local_slice_note = (
        "\n\nLOCAL VALUE CLUES: `slice` evidence was selected by matching names and earlier assignments in the same function. "
        "These are syntactic candidates, not proven flow edges; they may be branch-irrelevant. Check them against the surrounding code."
        if any(item.kind == "slice" for item in packet.evidence) else ""
    )
    relation_note = (
        "\n\nCONTEXT RELATIONSHIPS: Additional code was selected using template bindings, imports, "
        "assignments, callees, model fields and possible SQL table/column connections. These are "
        "syntactic possible links, not proven flow edges or proof of shared database identity. "
        "Check input origin, reaching assignments, guards, types and output context in the code. "
        "A packet that is not truncated can still lack necessary relationships."
        if packet.context_resolution else ""
    )
    supplied_ids = {item.id for item in packet.evidence}
    grounded_facts = framework_lines(packet)
    framework_note = (
        "\n\nFRAMEWORK SEMANTICS (apply only to the supplied bindings; explicit overrides take precedence):\n"
        + "\n".join(grounded_facts)
        if grounded_facts else ""
    )
    call_contracts = []
    for row in packet.context_resolution:
        if row.get("kind") != "call_argument_contract" or not row.get("included"):
            continue
        ids = [value for value in row.get("evidence_ids", []) if value in supplied_ids]
        if not ids:
            continue
        note = (f"[{', '.join(ids)}] Possible resolved call: {row['caller_file']}::{row['caller']} "
                f"passes {row['argument']} to {row['callee_file']}::{row['callee']}.{row['parameter']}.")
        if row.get("builtin_conversion"):
            note += (f" The argument expression calls unshadowed {row['builtin_conversion']}; "
                     "the converted result, not the original input, is passed on this call. "
                     "Successful built-in int conversion produces an integer. "
                     "Other callers and later transformations still require review.")
        call_contracts.append(note)
    call_note = ("\n\nCALL ARGUMENT RELATIONSHIPS (possible call sites, not exhaustive flow proof):\n"
                 + "\n".join(dict.fromkeys(call_contracts))) if call_contracts else ""
    schema = (
        f'{{"candidate_id":"{c.candidate_id}","cwe":{c.cwe},'
        '"verdict":"VULNERABLE|NOT_VULNERABLE|NEEDS_MORE_CONTEXT",'
        '"source_evidence":[],"sink_evidence":[],"sanitizer_evidence":[],'
        '"explanation":"...","missing_symbols":[]}'
    )
    instructions = (
        "You are verifying a static-analysis candidate. You are not discovering vulnerabilities. "
        "Use only supplied evidence; never assume code outside it. Every factual code claim must cite evidence IDs. "
        "Judge the exact reported operation, not another dangerous operation nearby. "
        "Use documented framework bindings with their referenced declarations as input evidence: "
        "a bound path/query/body parameter need not have a literal request accessor. "
        "Framework type conversion and validation restrict accepted values; a default does not make "
        "a bound input constant. Check concrete defenses before requesting missing input. "
        "A truncated block contains only its displayed lines; omitted lines may contain relevant guards or value changes. "
        "Missing evidence is not evidence of safety. Return VULNERABLE only when the mechanism is demonstrated. "
        "For these flow vulnerabilities, cite both attacker-controlled input in source_evidence and its dangerous use "
        "in sink_evidence, even if the scanner supplied no source location. An unsafe operation or a |safe filter "
        "alone does not demonstrate attacker control. Possible producer links do not prove shared application/session "
        "identity or exhaustive runtime coverage. Selecting a database row does not establish "
        "attacker control of its stored fields. If necessary input origin is missing and no "
        "concrete defense proves safety at the reported operation, return NEEDS_MORE_CONTEXT. "
        "For SQL, distinguish bound values from dynamically constructed SQL identifiers or syntax; "
        "parameterized values alone do not protect dynamic keys, which need their own restrictions. "
        "Choose the verdict using three distinct evidence conditions: Return VULNERABLE when the "
        "supplied code demonstrates attacker-controlled input reaching the reported dangerous operation "
        "with a vulnerability mechanism and no effective defense. The absence of a defense is not by "
        "itself a reason to request more context. Return NOT_VULNERABLE only with cited concrete safety "
        "code, such as parameterized SQL, context-appropriate escaping, an allowlist, or a proven "
        "constant value. Return NEEDS_MORE_CONTEXT only when a specific missing fact prevents judging "
        "input control, flow, execution, or defense applicability; name only that needed relationship in "
        "missing_symbols. For missing relationships use entries such as "
        "'Field origin: user.country', 'Template renderer: profile.html', 'Route binding: get_user', "
        "or 'Caller: helper_name'; legacy symbol names are also allowed. "
        "Do not invent files, lines, candidate IDs, or evidence IDs. "
        "Keep explanation under 35 words. Return only the JSON object, with no reasoning or markdown."
    )
    header = (
        f"CANDIDATE: {c.candidate_id}\nCWE: CWE-{c.cwe}\nRULE: {c.rule_id}\nTITLE: {c.title}\n"
        f"ALERT LOCATION: {c.primary_location.file}:{c.primary_location.line}\n"
        f"PACKET CONTEXT TRUNCATED: {str(packet.context_truncated).lower()} "
        f"(incomplete evidence blocks: {packet.incomplete_evidence_blocks})"
        f"{codeql_paths}{local_slice_note}{relation_note}{framework_note}{call_note}"
    )
    question_text = "\n".join(
        f"{index}. {question}" for index, question in enumerate(questions, 1)
    )
    decision_check = (
        "FINAL DECISION CHECK: Judge only the reported operation. Check the accepted input domain "
        "and every relevant guard on its reaching path before concluding that input can exploit this CWE. "
        "For a documented framework binding, integer conversion validates numeric values; ordinary Python "
        "type annotations alone do not enforce conversion. Do not invent a bypass of supplied conversion, "
        "validation, escaping or allowlists. Parameterized SQL values are data; dynamic SQL keys must be "
        "checked against all supplied allowlists and key insertion paths before declaring them unsafe. "
        "Control of a record selector does not prove control of its stored fields; require their write "
        "provenance if necessary. External input reaching dynamic text alone is insufficient: a vulnerable "
        "decision requires an input accepted by the supplied types and guards that can introduce unintended "
        "SQL syntax outside the permitted query grammar, unintended interpreted commands or executable HTML "
        "markup, or escape the allowed filesystem location for the requested CWE. "
        "Selecting among fixed valid SQL identifier literals is permitted functionality when every key "
        "insertion is restricted to those literals and the corresponding values remain bound parameters. "
        "In that case dynamic column selection is safe for SQL injection. Check the actual membership filters "
        "and updates in the supplied code; arbitrary SQL keys or interpolated values need separate analysis. "
        "If a concrete defense rules out this mechanism at the reported operation, return NOT_VULNERABLE "
        "with cited safety evidence. If necessary provenance remains missing and safety is not demonstrated, "
        "return NEEDS_MORE_CONTEXT. Do not judge an unrelated nearby operation."
    )
    return (
        f"{instructions}\n\n{header}\n\nQUESTIONS:\n{question_text}"
        f"\n\nEVIDENCE:\n{evidence}\n\n{decision_check}"
        f"\n\nReturn JSON matching exactly this shape:\n{schema}"
    )
