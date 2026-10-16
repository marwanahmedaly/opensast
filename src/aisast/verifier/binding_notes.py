"""Render documented facts with references to their individual bindings.

Matching fact text does not establish that two declarations describe the same
producer. These notes preserve that distinction without asserting data flow.
"""
from aisast.models import EvidencePacket


def framework_lines(packet: EvidencePacket) -> list[str]:
    supplied = {item.id for item in packet.evidence}
    lines: list[str] = []
    for fact in packet.framework_facts:
        bindings = [row for row in packet.context_resolution
                    if row.get("fact") == fact and row.get("included")]
        scoped = [row for row in bindings
                  if row.get("certainty") == "documented_api_binding"]
        generic = [row for row in bindings
                   if row.get("certainty") != "documented_api_binding"]
        if not scoped or generic:
            grouped = generic if scoped else bindings
            ids = sorted({value for row in grouped
                          for value in row.get("evidence_ids", []) if value in supplied})
            lines.append(("[" + ", ".join(ids) + "] " if ids else "") + fact)
        for row in scoped:
            ids = sorted({value for value in row.get("evidence_ids", []) if value in supplied})
            ranges = row.get("required_ranges", [])
            anchor = ranges[0] if ranges else None
            valid = (isinstance(anchor, dict)
                     and isinstance(anchor.get("file"), str)
                     and isinstance(anchor.get("start_line"), int)
                     and isinstance(anchor.get("end_line"), int))
            context = (f"{anchor['file']}:{anchor['start_line']}-{anchor['end_line']}"
                       if valid else "supplied binding")
            label = (f"Binding {row.get('kind', 'documented_api_binding')} "
                     f"{row.get('target', '')}; context {context}. ")
            lines.append(("[" + ", ".join(ids) + "] " if ids else "") + label + fact)
    return list(dict.fromkeys(lines))
