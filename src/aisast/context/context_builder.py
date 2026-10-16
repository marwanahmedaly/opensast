from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path

from aisast.context.ast_index import ASTIndex, Symbol
from aisast.context.relationships import RepositoryRelationships
from aisast.models import Candidate, EvidenceBlock, EvidencePacket, Location
from aisast.verifier.prompts import profile_for


class ContextBuilder:
    def __init__(self, root: Path, prompt_version: str = "v1", max_chars: int = 24000,
                 include_call_chains: bool = False) -> None:
        self.root = root
        self.index = ASTIndex(root)
        self.relationships = RepositoryRelationships(root, include_call_chains=include_call_chains)
        self.prompt_version = prompt_version
        self.max_chars = max_chars
        self._tree_cache: dict[str, ast.Module | None] = {}
        self._line_cache: dict[str, list[str] | None] = {}

    def packet(self, candidate: Candidate, extra_symbols: list[str] | None = None) -> EvidencePacket:
        flow_locations: list[Location] = []
        raw_flows = candidate.properties.get("code_flows", [])
        if isinstance(raw_flows, list):
            for flow in raw_flows:
                if not isinstance(flow, list):
                    continue
                for raw_location in flow:
                    if isinstance(raw_location, dict):
                        try:
                            location = Location.model_validate(raw_location)
                        except ValueError:
                            continue
                        if location not in flow_locations:
                            flow_locations.append(location)

        locations = [candidate.source, *candidate.path, *flow_locations, candidate.sink, candidate.primary_location]
        symbols: list[Symbol] = []
        for location in locations:
            if location:
                symbol = self.index.containing(location.file, location.line)
                if symbol and symbol not in symbols: symbols.append(symbol)
        requested = list(dict.fromkeys(extra_symbols or []))
        expression = candidate.properties.get("expression")
        if isinstance(expression, str):
            field = re.match(r"([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)", expression)
            if field:
                requested.append("field origin: " + field[1])
        templates: list[str] = []
        for request in requested:
            typed = re.match(r"(?i)^(?:template renderer|template contents|template)\s*:\s*(.+)$", request.strip())
            name = typed[1].strip() if typed else request
            if name.endswith((".html", ".htm", ".jinja", ".jinja2", ".j2")):
                templates.append(name)
            elif re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*){0,2}", name):
                for symbol in self.index.find(name.rsplit(".", 1)[-1])[:2]:
                    if symbol not in symbols: symbols.append(symbol)
        evidence: list[EvidenceBlock] = []
        for symbol in symbols:
            block = self._read_symbol(symbol, candidate)
            if block: evidence.append(block)
        for location, kind in ((candidate.source, "source"), (candidate.sink, "sink"), (candidate.primary_location, "context")):
            if location and not any(block.file == location.file and block.start_line <= location.line <= block.end_line for block in evidence):
                block = self._read_lines(location.file, max(1, location.line - 8), location.line + 8, kind, candidate)
                if block: evidence.append(block)
        # Renderer references are syntactic evidence, never a fabricated
        # remote-source path. Retain each possible renderer rather than the
        # first matching filename alone.
        for raw in candidate.properties.get("evidence_locations", []) or []:
            if isinstance(raw, dict):
                try:
                    reference = Location.model_validate(raw)
                except ValueError:
                    continue
                symbol = self.index.containing(reference.file, reference.line)
                block = (self._read_symbol(symbol, candidate) if symbol else
                         self._read_lines(reference.file, max(1, reference.line - 8),
                                          reference.line + 8, "relation", candidate))
                if block:
                    evidence.append(block)
        end_line = candidate.properties.get("end_line")
        if isinstance(end_line, int) and end_line > candidate.primary_location.line:
            block = self._read_lines(candidate.primary_location.file,
                                     candidate.primary_location.line, end_line, "sink", candidate)
            if block:
                evidence.append(block)
        # A path through an inherited method can be infeasible when the source
        # subclass overrides that method. Include the override so triage can
        # answer this specific dispatch question from code evidence.
        evidence.extend(self._dispatch_override_evidence(candidate))
        evidence.extend(self._related_state_methods(candidate))
        evidence.extend(self._endpoint_origin_evidence(candidate))
        links = self.relationships.collect(candidate.primary_location.file,
                                           candidate.primary_location.line, requested)
        if candidate.source and candidate.source != candidate.primary_location:
            source_links = self.relationships.collect(candidate.source.file, candidate.source.line)
            links.references.extend(source_links.references)
            links.events.extend(source_links.events)
            links.framework_facts = list(dict.fromkeys([*links.framework_facts, *source_links.framework_facts]))
        for reference in links.references:
            block = self._read_lines(reference.file, reference.start, reference.end, "relation", candidate)
            if block:
                evidence.append(block)
        # Preserve full calls when a location-window ends inside a multiline
        # expression. This does not label the surrounding function as complete.
        for file in dict.fromkeys(block.file for block in evidence):
            tree = self._parsed_tree(file)
            if tree is None:
                continue
            boundaries = [block.end_line for block in evidence if block.file == file]
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and any(node.lineno <= end < node.end_lineno for end in boundaries):
                    block = self._read_lines(file, node.lineno, node.end_lineno, "context", candidate)
                    if block and not any(item.file == file and item.start_line <= node.lineno
                                         and item.end_line >= node.end_lineno for item in evidence):
                        evidence.append(block)
        for name in templates:
            if Path(name).is_absolute() or ".." in Path(name).parts:
                continue
            files = self._template_files(name, candidate)
            links.events.append({"kind": "template_contents", "target": name,
                                 "status": "located" if files else "unresolved",
                                 "files": files, "ambiguous": len(files) > 1})
            for file in files:
                path = (self.root / file).resolve()
                if not path.is_relative_to(self.root.resolve()) or not path.is_file():
                    continue
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
                anchor = candidate.sink if candidate.sink and candidate.sink.file == file else candidate.primary_location
                if anchor.file == file:
                    start, end = max(1, anchor.line - 40), min(len(lines), anchor.line + 40)
                else:
                    start, end = 1, len(lines)
                block = self._read_lines(file, start, end, "expansion", candidate)
                if block and not any(item.file == file and item.start_line <= start and item.end_line >= end for item in evidence):
                    evidence.append(block)
        # Preserve a direct location even when the code is module-level.
        if not evidence:
            location = candidate.primary_location
            block = self._read_lines(location.file, max(1, location.line - 8), location.line + 8, "context", candidate)
            if block: evidence.append(block)
        # Put the exact reported line first so a long function cannot consume
        # the packet budget before the model sees what CodeQL flagged.
        alert = self._read_lines(candidate.primary_location.file, candidate.primary_location.line,
                                 candidate.primary_location.line, "context", candidate)
        if alert:
            evidence.insert(0, alert)
        slice_insert_at = 1
        # For long enclosing functions, give the model nearby guards and value
        # updates before the full function excerpt competes for the budget.
        enclosing = next((block for block in evidence[1:]
                          if block.file == candidate.primary_location.file
                          and block.start_line <= candidate.primary_location.line <= block.end_line
                          and block.end_line - block.start_line > 80), None)
        if enclosing:
            local = self._read_lines(
                candidate.primary_location.file,
                max(enclosing.start_line, candidate.primary_location.line - 20),
                min(enclosing.end_line, candidate.primary_location.line + 20),
                "context", candidate,
            )
            if local:
                evidence.insert(1, local)
                slice_insert_at = 2
        # Without a CodeQL path, add a small same-function assignment slice as
        # a search hint. It is intentionally labeled as syntactic, not as a
        # proven data-flow trace.
        slice_evidence = self._local_value_slice_evidence(candidate) if enclosing else []
        if slice_evidence:
            evidence[slice_insert_at:slice_insert_at] = slice_evidence
        # Identical ranges can arise when a path node and the primary location
        # refer to the same statement. Keep the highest-priority copy.
        unique: list[EvidenceBlock] = []
        seen_ranges: set[tuple[str, int, int]] = set()
        for block in evidence:
            key = (block.file, block.start_line, block.end_line)
            if key not in seen_ranges:
                seen_ranges.add(key)
                unique.append(block)
        evidence = unique
        if templates and any(block.kind == "expansion" for block in evidence):
            original = [block for block in evidence if block.kind != "expansion"]
            extra = [block for block in evidence if block.kind == "expansion"]
            initial, initial_omitted = self._apply_budget(original, limit=self.max_chars * 2 // 3)
            expanded, extra_omitted = self._apply_budget(extra, limit=self.max_chars - sum(len(block.code) for block in initial))
            evidence = initial + expanded
            omitted = initial_omitted + extra_omitted
        else:
            evidence, omitted = self._apply_budget(evidence)
        resolution = self._resolution_status(links.events, evidence)
        omitted_facts = {row['fact'] for row in resolution
                         if row.get('fact') and not row.get('included', True)}
        framework_facts = [fact for fact in links.framework_facts if fact not in omitted_facts]
        if candidate.properties.get("suspect_only"):
            framework_facts.append("This is an output-operation suspect. Scanner renderer references and lexical browser contexts are possible syntactic relationships, not proof of a lower-trust source, feasible flow, framework identity or exploit. Check escaping, MIME, reachability and configuration using the code evidence.")
        return EvidencePacket(candidate=candidate, evidence=evidence, profile=profile_for(candidate.cwe),
                              prompt_version=self.prompt_version,
                              context_truncated=omitted > 0 or any(block.truncated for block in evidence),
                              incomplete_evidence_blocks=omitted,
                              context_resolution=resolution,
                              framework_facts=framework_facts)

    def _template_files(self, name: str, candidate: Candidate) -> list[str]:
        """Resolve safe template paths, including explicit Jinja loader roots."""
        if Path(name).is_absolute() or ".." in Path(name).parts:
            return []
        root = self.root.resolve()
        paths = [root / name, root / "templates" / name, root / "template" / name]
        tree = self._parsed_tree(candidate.primary_location.file)

        def static_path(node: ast.AST, seen: set[str] | None = None) -> Path | None:
            seen = seen or set()
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return Path(node.value)
            if isinstance(node, ast.Name) and node.id == "__file__":
                return root / candidate.primary_location.file
            if isinstance(node, ast.Name) and node.id not in seen and tree:
                assignments = [item for item in tree.body if isinstance(item, ast.Assign)
                               and any(isinstance(target, ast.Name) and target.id == node.id for target in item.targets)]
                if len(assignments) == 1:
                    return static_path(assignments[0].value, seen | {node.id})
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Path" and node.args:
                return static_path(node.args[0], seen)
            if isinstance(node, ast.Attribute) and node.attr == "parent":
                value = static_path(node.value, seen)
                return value.parent if value else None
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
                left, right = static_path(node.left, seen), static_path(node.right, seen)
                return left / right if left is not None and right is not None else None
            return None

        if tree:
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and RepositoryRelationships.dotted(node.func).split(".")[-1] == "FileSystemLoader":
                    for arg in node.args[:1]:
                        loader = static_path(arg)
                        if loader:
                            paths.append((loader if loader.is_absolute() else root / loader) / name)
        # Exact suffixes preserve subdirectory names; avoid treating a basename
        # collision as a unique resolved template.
        paths.extend(path for path in root.rglob(Path(name).name)
                     if path.as_posix().endswith("/" + name)
                     and any(part in {"templates", "template"} for part in path.relative_to(root).parts))
        return sorted({path.resolve().relative_to(root).as_posix() for path in paths
                       if path.resolve().is_relative_to(root) and path.is_file()})

    @staticmethod
    def _resolution_status(events: list[dict], evidence: list[EvidenceBlock]) -> list[dict]:
        """Log whether located relationships survived the packet budget."""
        result = []
        for event in events:
            row = dict(event)
            if row.get("required_ranges"):
                required = row["required_ranges"]
                matches = [[e for e in evidence if e.file == reference["file"]
                            and e.start_line <= reference["start_line"]
                            and e.end_line >= reference["end_line"] and not e.truncated]
                           for reference in required]
                row["included"] = all(matches)
                row["evidence_ids"] = list(dict.fromkeys(e.id for group in matches for e in group))
                if not row["included"]:
                    row["status"] = "omitted_by_budget"
            if "start_line" in row:
                matches = [e for e in evidence if e.file == row["file"]
                           and e.start_line <= row["start_line"] and e.end_line >= row["end_line"]]
                row["included"] = bool(matches)
                row["evidence_ids"] = [e.id for e in matches]
                if not matches:
                    row["status"] = "omitted_by_budget"
            result.append(row)
        return result

    def _local_value_slice_evidence(self, candidate: Candidate) -> list[EvidenceBlock]:
        """Return bounded, syntactically related earlier assignments for a pathless alert."""
        if candidate.path or candidate.properties.get("code_flows"):
            return []
        location = candidate.primary_location
        if not location.file.endswith(".py"):
            return []
        path = (self.root / location.file).resolve()
        if not path.is_relative_to(self.root.resolve()):
            return []
        tree = self._parsed_tree(location.file)
        if tree is None:
            return []

        callables = [
            node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.lineno <= location.line <= node.end_lineno
        ]
        if not callables:
            return []
        owner = min(callables, key=lambda node: node.end_lineno - node.lineno)

        def nested_scope(node: ast.AST) -> bool:
            return isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef))

        def keys_in(node: ast.AST, *, stores: bool) -> set[str]:
            keys: set[str] = set()
            context_type = ast.Store if stores else ast.Load
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and isinstance(child.ctx, context_type):
                    keys.add(child.id)
                elif isinstance(child, ast.Attribute) and isinstance(child.ctx, context_type):
                    if isinstance(child.value, ast.Name):
                        keys.add(f"{child.value.id}.{child.attr}")
            return keys

        def alert_statements(node: ast.AST):
            if nested_scope(node):
                return
            if isinstance(node, ast.stmt) and node.lineno <= location.line <= node.end_lineno:
                yield node
            for child in ast.iter_child_nodes(node):
                yield from alert_statements(child)

        at_alert = [statement for item in owner.body for statement in alert_statements(item)]
        if not at_alert:
            return []
        alert_stmt = min(at_alert, key=lambda node: node.end_lineno - node.lineno)
        needed = keys_in(alert_stmt, stores=False)
        if not needed:
            return []

        def statements_in(body: list[ast.stmt]):
            for statement in body:
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                yield statement
                for field in ("body", "orelse", "finalbody"):
                    nested = getattr(statement, field, None)
                    if isinstance(nested, list):
                        yield from statements_in([item for item in nested if isinstance(item, ast.stmt)])
                handlers = getattr(statement, "handlers", None)
                if isinstance(handlers, list):
                    for handler in handlers:
                        if isinstance(handler, ast.ExceptHandler):
                            yield from statements_in([item for item in handler.body if isinstance(item, ast.stmt)])
                cases = getattr(statement, "cases", None)
                if isinstance(cases, list):
                    for case in cases:
                        yield from statements_in([item for item in case.body if isinstance(item, ast.stmt)])

        prior = sorted(
            (statement for statement in statements_in(owner.body)
             if statement.end_lineno < location.line),
            key=lambda statement: (statement.lineno, statement.end_lineno),
            reverse=True,
        )
        selected: list[ast.stmt] = []
        # Conditional definitions may over-approximate. Keep them as candidate
        # clues instead of claiming one reaches the alert.
        max_statements = 6
        max_source_lines = 120
        for statement in prior:
            written = keys_in(statement, stores=True)
            if not written.intersection(needed):
                continue
            selected.append(statement)
            needed.update(keys_in(statement, stores=False))
            if len(selected) >= max_statements:
                break
            if selected[0].end_lineno - statement.lineno >= max_source_lines:
                break

        blocks = [
            self._read_lines(location.file, statement.lineno, statement.end_lineno, "slice", candidate)
            for statement in sorted(selected, key=lambda item: item.lineno)
        ]
        return [block for block in blocks if block]

    def _endpoint_origin_evidence(self, candidate: Candidate) -> list[EvidenceBlock]:
        """For a source-less endpoint, show the enclosing binding of its argument."""
        sink = candidate.sink
        if candidate.source or not sink or not sink.file.endswith(".py"):
            return []
        path = (self.root / sink.file).resolve()
        if not path.is_relative_to(self.root.resolve()):
            return []
        tree = self._parsed_tree(sink.file)
        if tree is None:
            return []
        functions = sorted(
            (node for node in ast.walk(tree)
             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
             and node.lineno <= sink.line <= node.end_lineno),
            key=lambda node: node.end_lineno - node.lineno,
        )
        if not functions:
            return []
        argument = next(
            (node for node in ast.walk(functions[0])
             if isinstance(node, ast.Name) and node.lineno == sink.line
             and node.col_offset + 1 == sink.column),
            None,
        )
        if argument is None:
            return []
        blocks: list[EvidenceBlock] = []
        for owner in functions[1:3]:
            header_start = min((decorator.lineno for decorator in owner.decorator_list), default=owner.lineno)
            header = self._read_lines(sink.file, header_start, min(owner.lineno + 7, owner.end_lineno),
                                      "context", candidate)
            if header:
                blocks.append(header)
            bindings = [node for node in ast.walk(owner)
                        if isinstance(node, (ast.Assign, ast.AnnAssign))
                        and node.end_lineno < functions[0].lineno
                        and any(isinstance(target, ast.Name) and target.id == argument.id
                                for root in (node.targets if isinstance(node, ast.Assign) else [node.target])
                                for target in ast.walk(root))]
            if not bindings:
                continue
            first = min(bindings, key=lambda node: node.lineno)
            last = max(bindings, key=lambda node: node.end_lineno)
            span_start = max(owner.lineno, first.lineno - (15 if len(bindings) > 1 else 8))
            span_end = min(owner.end_lineno, last.end_lineno + (8 if len(bindings) > 1 else 5),
                           span_start + 129)
            block = self._read_lines(sink.file, span_start, span_end,
                                     "context", candidate)
            if block:
                blocks.append(block)
            value = first.value if len(bindings) == 1 else None
            if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
                for symbol in self.index.find(value.func.id)[:1]:
                    helper = self._read_symbol(symbol, candidate)
                    if helper:
                        blocks.append(helper)
            break
        return blocks

    def _dispatch_override_evidence(self, candidate: Candidate) -> list[EvidenceBlock]:
        source, sink = candidate.source, candidate.sink
        if not source or not sink or source.file != sink.file or not source.file.endswith(".py"):
            return []
        path = (self.root / source.file).resolve()
        if not path.is_relative_to(self.root.resolve()):
            return []
        tree = self._parsed_tree(source.file)
        if tree is None:
            return []
        classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
        source_class = next((node for node in classes if node.lineno <= source.line <= node.end_lineno), None)
        sink_class = next((node for node in classes if node.lineno <= sink.line <= node.end_lineno), None)
        if source_class is None or sink_class is None or source_class is sink_class:
            return []
        if not any(isinstance(base, ast.Name) and base.id == sink_class.name for base in source_class.bases):
            return []
        sink_method = next((node for node in sink_class.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                            and node.lineno <= sink.line <= node.end_lineno), None)
        if sink_method is None:
            return []
        override = next((node for node in source_class.body
                         if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                         and node.name == sink_method.name), None)
        if override is None:
            return []
        header = self._read_lines(source.file, source_class.lineno, source_class.lineno,
                                  "context", candidate)
        body = self._read_lines(source.file, override.lineno, override.end_lineno,
                                "context", candidate)
        return [block for block in (header, body) if block]

    def _related_state_methods(self, candidate: Candidate) -> list[EvidenceBlock]:
        """Show bounded initialization and validation of state read at a sink."""
        sink = candidate.sink
        if not sink or not sink.file.endswith(".py"):
            return []
        path = (self.root / sink.file).resolve()
        if not path.is_relative_to(self.root.resolve()):
            return []
        tree = self._parsed_tree(sink.file)
        if tree is None:
            return []
        owner = next((node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)
                      and node.lineno <= sink.line <= node.end_lineno), None)
        if owner is None:
            return []
        method = next((node for node in owner.body
                       if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                       and node.lineno <= sink.line <= node.end_lineno), None)
        if method is None:
            return []
        fields = {node.attr for node in ast.walk(method)
                  if isinstance(node, ast.Attribute) and
                  isinstance(node.value, ast.Name) and node.value.id == "self" and
                  isinstance(node.ctx, ast.Load)}
        if not fields:
            return []
        siblings = [node for node in owner.body
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and
                    node is not method and
                    (node.name == "__init__" or node.name.startswith("set_")) and
                    any(isinstance(item, ast.Attribute) and item.attr in fields and
                        isinstance(item.value, ast.Name) and item.value.id == "self"
                        for item in ast.walk(node))]
        siblings.sort(key=lambda node: (node.name != "__init__", node.lineno))
        blocks = [self._read_lines(sink.file, sibling.lineno,
                                   min(sibling.end_lineno, sibling.lineno + 79),
                                   "context", candidate)
                  for sibling in siblings[:2]]
        setters = {node.name for node in siblings if node.name.startswith("set_")}
        if setters:
            for base in owner.bases[:2]:
                if not isinstance(base, ast.Name):
                    continue
                base_name = base.id
                base_file = sink.file
                for imported in tree.body:
                    if not isinstance(imported, ast.ImportFrom) or not imported.level:
                        continue
                    if not any(alias.name == base_name for alias in imported.names):
                        continue
                    directory = path.parent
                    for _ in range(imported.level - 1):
                        directory = directory.parent
                    candidate_path = directory / (imported.module or "").replace(".", "/")
                    candidate_path = candidate_path.with_suffix(".py")
                    if candidate_path.is_file() and candidate_path.resolve().is_relative_to(self.root.resolve()):
                        base_file = candidate_path.resolve().relative_to(self.root.resolve()).as_posix()
                        break
                base_path = self.root / base_file
                try:
                    base_tree = ast.parse(base_path.read_text(encoding="utf-8"))
                except (OSError, SyntaxError, UnicodeDecodeError):
                    continue
                base_class = next((node for node in base_tree.body
                                   if isinstance(node, ast.ClassDef) and node.name == base_name), None)
                if base_class is None:
                    continue
                initializer = next((node for node in base_class.body
                                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                                    and node.name == "__init__"), None)
                if initializer and any(isinstance(call, ast.Call) and
                                       isinstance(call.func, ast.Attribute) and
                                       call.func.attr in setters and
                                       isinstance(call.func.value, ast.Name) and
                                       call.func.value.id == "self"
                                       for call in ast.walk(initializer)):
                    blocks.append(self._read_lines(base_file, initializer.lineno,
                                                  min(initializer.end_lineno, initializer.lineno + 49),
                                                  "context", candidate))
                break
        return [block for block in blocks if block]

    def _apply_budget(self, evidence: list[EvidenceBlock], limit: int | None = None) -> tuple[list[EvidenceBlock], int]:
        """Cap serialized code and mark excerpts that the budget cuts."""
        remaining = self.max_chars if limit is None else limit
        result: list[EvidenceBlock] = []
        incomplete = 0
        for block in evidence:
            if remaining <= 0:
                incomplete += 1
                continue
            lines = block.code.splitlines()
            selected: list[str] = []
            used = 0
            cut_line = False
            for line in lines:
                cost = len(line) + (1 if selected else 0)
                if used + cost > remaining:
                    if not selected and remaining > 24:
                        selected.append(line[:remaining - 18] + " …[line truncated]")
                        used = remaining
                    cut_line = True
                    break
                selected.append(line)
                used += cost
            if selected:
                truncated = block.truncated or cut_line or len(selected) < len(lines)
                result.append(block.model_copy(update={
                    "code": "\n".join(selected),
                    "end_line": block.start_line + len(selected) - 1,
                    "truncated": truncated,
                    "source_end_line": block.source_end_line or block.end_line,
                }))
                remaining -= used
                if truncated:
                    incomplete += 1
            else:
                incomplete += 1
        return result, incomplete

    def _read_symbol(self, symbol: Symbol, candidate: Candidate) -> EvidenceBlock | None:
        kind = "context"
        if candidate.source and symbol.file == candidate.source.file and symbol.start_line <= candidate.source.line <= symbol.end_line:
            kind = "source"
        if candidate.sink and symbol.file == candidate.sink.file and symbol.start_line <= candidate.sink.line <= symbol.end_line:
            kind = "sink" if kind == "context" else "path"
        return self._read_lines(symbol.file, symbol.start_line, symbol.end_line, kind, candidate)

    def _parsed_tree(self, file: str) -> ast.Module | None:
        """Parse each repository file at most once per context-builder instance."""
        if file in self._tree_cache:
            return self._tree_cache[file]
        path = (self.root / file).resolve()
        if not path.is_relative_to(self.root.resolve()):
            self._tree_cache[file] = None
            return None
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeDecodeError):
            tree = None
        self._tree_cache[file] = tree
        return tree

    def _source_lines(self, file: str) -> list[str] | None:
        if file in self._line_cache:
            return self._line_cache[file]
        path = (self.root / file).resolve()
        if not path.is_relative_to(self.root.resolve()):
            self._line_cache[file] = None
            return None
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = None
        self._line_cache[file] = lines
        return lines

    def _read_lines(self, file: str, start: int, end: int, kind: str, candidate: Candidate) -> EvidenceBlock | None:
        lines = self._source_lines(file)
        if lines is None:
            return None
        start, end = max(1, start), min(len(lines), end)
        code = "\n".join(f"{n:4d} | {lines[n-1]}" for n in range(start, end + 1))
        if not code:
            return None
        prefix = hashlib.sha256(f"{candidate.candidate_id}:{file}:{start}:{end}".encode()).hexdigest()[:10]
        return EvidenceBlock(id=f"E{prefix}", file=file, start_line=start, end_line=end,
                             code=code, kind=kind, source_end_line=end)
