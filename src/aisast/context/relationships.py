"""Repository-local context links, deliberately not a replacement for data flow.

All matches carry exact source ranges and a reason. Dynamic dispatch, database
identity and template inheritance are not asserted as proven by this index.
"""
from __future__ import annotations

import ast
import re
import tokenize
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from aisast.context.framework_bindings import FastAPIBindings


@dataclass(frozen=True)
class Reference:
    file: str
    start: int
    end: int
    reason: str
    key: str


@dataclass
class Scope:
    file: str
    node: ast.AST
    parent: Scope | None

    @property
    def name(self) -> str:
        return getattr(self.node, 'name', '<module>')


@dataclass
class LinkResult:
    references: list[Reference]
    events: list[dict]
    framework_facts: list[str]


class RepositoryRelationships:
    """Index once per repository; traverse only candidate-related relations."""

    TEMPLATE_SUFFIXES = ('.html', '.htm', '.jinja', '.jinja2', '.j2')
    RENDER_NAMES = {'render_template', 'render', 'render_to_string', 'render_to_response', 'TemplateResponse'}

    def __init__(self, root: Path, max_depth: int = 4, include_call_chains: bool = False):
        self.root = root.resolve()
        self.max_depth = max_depth
        self.include_call_chains = include_call_chains
        self.trees: dict[str, ast.Module] = {}
        self.scopes: dict[int, Scope] = {}
        self.definitions: dict[str, list[Scope]] = defaultdict(list)
        self.classes: list[Scope] = []
        self.calls: list[tuple[Scope, ast.Call]] = []
        self.related_names: dict[str, list[Scope]] = defaultdict(list)
        self.parse_errors: list[dict] = []
        self._inference_cache: dict[tuple, set[str]] = {}
        self._built = False
        self._callers_cache: dict[int, list[tuple[Scope, ast.Call]]] = {}
        self._imports_cache: dict[int, dict[str, str]] = {}
        self._module_files_cache: dict[str, set[str]] = {}
        self._scope_imports: dict[int, list[ast.AST]] = defaultdict(list)
        self._assignment_index: dict[tuple[int, str], list[ast.AST]] | None = None
        self._template_dependencies: dict[str, set[str]] | None = None
        from aisast.context.receiver_bindings import ReceiverBindings
        self.receiver_bindings = ReceiverBindings(self)
        from aisast.context.callback_bindings import CallbackBindings
        self.callback_bindings = CallbackBindings(self)
        self._active_resolution: set[tuple[int, int]] = set()

    def build(self) -> None:
        if self._built:
            return
        self._built = True
        for path in sorted(self.root.rglob('*.py')):
            if not path.resolve().is_relative_to(self.root):
                continue
            file = path.relative_to(self.root).as_posix()
            try:
                with tokenize.open(path) as stream:
                    tree = ast.parse(stream.read(), filename=file)
            except (OSError, SyntaxError, UnicodeError, LookupError) as exc:
                self.parse_errors.append({'file': file, 'reason': type(exc).__name__})
                continue
            self.trees[file] = tree
            module = Scope(file, tree, None)
            self.scopes[id(tree)] = module

            def visit(node: ast.AST, owner: Scope) -> None:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    owner = Scope(file, node, owner)
                    self.definitions[node.name].append(owner)
                    if isinstance(node, ast.ClassDef):
                        self.classes.append(owner)
                self.scopes[id(node)] = owner
                if isinstance(node, ast.Call):
                    self.calls.append((owner, node))
                    for kw in node.keywords:
                        if kw.arg == 'related_name' and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                            current = owner
                            while current and not isinstance(current.node, ast.ClassDef):
                                current = current.parent
                            if current and any(isinstance(statement, (ast.Assign, ast.AnnAssign))
                                               and statement.value is node for statement in current.node.body):
                                self.related_names[kw.value.value].append(current)
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    self._scope_imports[id(owner.node)].append(node)
                for child in ast.iter_child_nodes(node):
                    visit(child, owner)
            for child in ast.iter_child_nodes(tree):
                visit(child, module)

    @staticmethod
    def dotted(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = RepositoryRelationships.dotted(node.value)
            return f'{prefix}.{node.attr}' if prefix else node.attr
        return ''

    @staticmethod
    def start(node: ast.AST) -> int:
        return min([getattr(node, 'lineno', 1), *[d.lineno for d in getattr(node, 'decorator_list', [])]])

    @staticmethod
    def end(node: ast.AST) -> int:
        end = getattr(node, 'end_lineno', None)
        if end is not None:
            return end
        return max((getattr(child, 'end_lineno', 1) or 1 for child in ast.walk(node)), default=1)

    @staticmethod
    def model_key(scope: Scope) -> str:
        return f'{scope.file}::{scope.name}'

    def owner(self, file: str, line: int) -> Scope | None:
        matches = [s for entries in self.definitions.values() for s in entries
                   if s.file == file and self.start(s.node) <= line <= s.node.end_lineno]
        return min(matches, key=lambda s: s.node.end_lineno - self.start(s.node), default=None)

    def imports(self, scope: Scope) -> dict[str, str]:
        if id(scope.node) in self._imports_cache:
            return self._imports_cache[id(scope.node)]
        result = {}
        module = scope.file.removesuffix('.py').replace('/', '.')
        package = module if module.endswith('.__init__') else module.rpartition('.')[0]
        package = package.removesuffix('.__init__')
        lexical = []
        current = scope
        while current:
            lexical.append(current)
            current = current.parent
        nodes = [node for level in reversed(lexical) for node in self._scope_imports[id(level.node)]]
        for node in nodes:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    result[alias.asname or alias.name.split('.')[0]] = alias.name if alias.asname else alias.name.split('.')[0]
            elif isinstance(node, ast.ImportFrom):
                prefix = node.module or ''
                if node.level:
                    pieces = package.split('.') if package else []
                    prefix = '.'.join(pieces[:len(pieces) - node.level + 1] + ([prefix] if prefix else []))
                for alias in node.names:
                    result[alias.asname or alias.name] = '.'.join(x for x in (prefix, alias.name) if x)
        self._imports_cache[id(scope.node)] = result
        return result

    def module_files(self, module: str) -> set[str]:
        """Possible source-root bindings, including src and monorepo packages.

        Multiple roots remain possible; this does not infer sys.path precedence.
        """
        if module not in self._module_files_cache:
            suffixes = (module.replace('.', '/') + '.py', module.replace('.', '/') + '/__init__.py')
            self._module_files_cache[module] = {file for file in self.trees
                if any(file == suffix or file.endswith('/' + suffix) for suffix in suffixes)}
        return self._module_files_cache[module]

    def resolve(self, node: ast.AST, scope: Scope, seen=None) -> list[Scope]:
        key = (id(node), id(scope.node))
        if key in self._active_resolution:
            return []
        self._active_resolution.add(key)
        try:
            return self._resolve(node, scope, seen) or self.receiver_bindings.methods(node, scope)
        finally:
            self._active_resolution.remove(key)

    def _resolve(self, node: ast.AST, scope: Scope, seen=None) -> list[Scope]:
        seen = set() if seen is None else seen
        name = self.dotted(node)
        if not name:
            return []
        parts = name.split('.')
        imported = self.imports(scope).get(parts[0])
        if imported:
            qualified = '.'.join([imported, *parts[1:]])
            module, _, symbol = qualified.rpartition('.')
            files = self.module_files(module)
            found = [s for s in self.definitions.get(symbol, []) if s.file in files]
            if found or qualified in seen:
                return found
            for file in sorted(files & self.trees.keys()):
                module_scope = self.scopes[id(self.trees[file])]
                if symbol in self.imports(module_scope):
                    found.extend(self.resolve(ast.Name(id=symbol), module_scope, seen | {qualified}))
                # Only follow explicit wildcard exports in the imported package.
                for exported in self.trees[file].body:
                    if isinstance(exported, ast.ImportFrom) and any(a.name == '*' for a in exported.names):
                        package = file.removesuffix('.py').replace('/', '.').removesuffix('.__init__')
                        if not file.endswith('/__init__.py'):
                            package = package.rpartition('.')[0]
                        parts = package.split('.') if package else []
                        exports = '.'.join(parts[:len(parts) - exported.level + 1] + ([exported.module] if exported.module else [])) if exported.level else (exported.module or '')
                        for target_file in self.module_files(exports):
                            found.extend(s for s in self.definitions.get(symbol, []) if s.file == target_file)
            return found
        if len(parts) == 1:
            candidates = [s for s in self.definitions.get(name, []) if s.file == scope.file]
            # Prefer a sibling/local definition; do not merge same-named helpers
            # across unrelated modules.
            local = [s for s in candidates if s.parent is scope or s.parent is scope.parent]
            return local or [s for s in candidates if s.parent and isinstance(s.parent.node, ast.Module)]
        if parts[0] in {'self', 'cls'} and len(parts) == 2:
            current = scope
            while current and not isinstance(current.node, ast.ClassDef):
                current = current.parent
            return [s for s in self.definitions.get(parts[-1], []) if s.parent is current] if current else []
        return []

    def callers_for(self, definition: Scope) -> list[tuple[Scope, ast.Call]]:
        key = id(definition.node)
        if key not in self._callers_cache:
            self._callers_cache[key] = []
            for scope, original in self.calls:
                call = self.callback_bindings.invocation(original, scope) or original
                if any(item is definition for item in self.resolve(call.func, scope)):
                    self._callers_cache[key].append((scope, call))
        return self._callers_cache[key]

    @staticmethod
    def expansion_request(request: str) -> tuple[str, str]:
        text = request.strip()
        match = re.fullmatch(r'(?i)(field origin|template renderer|route binding|caller|callee|sanitizer)\s*:\s*(.+)', text)
        if not match:
            match = re.fullmatch(r'(?i)(caller|callee)\s+of\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)', text)
        return (match[1].lower(), match[2].strip()) if match else ('symbol', text)

    def infer_models(self, expr: ast.AST, scope: Scope, seen=None, depth: int = 0) -> set[str]:
        """Receiver identity clues without emitting evidence from unrelated code."""
        seen = set() if seen is None else seen
        key = (scope.file, id(expr))
        if key in seen or depth > self.max_depth:
            return set()
        if key in self._inference_cache:
            return self._inference_cache[key]
        seen = seen | {key}
        result = set()
        if isinstance(expr, ast.Name):
            result.update(self.model_key(s) for s in self.resolve(expr, scope) if isinstance(s.node, ast.ClassDef))
            for assignment in self.assignments(scope, expr.id, getattr(expr, 'lineno', self.end(scope.node) + 1)):
                result.update(self.infer_models(assignment.value, scope, seen, depth + 1))
        elif isinstance(expr, ast.Attribute):
            related = self.related_names.get(expr.attr, [])
            if related:
                result.update(self.model_key(s) for s in related)
            else:
                result.update(self.infer_models(expr.value, scope, seen, depth))
        elif isinstance(expr, ast.Call):
            for definition in self.resolve(expr.func, scope):
                if isinstance(definition.node, ast.ClassDef):
                    result.add(self.model_key(definition))
                else:
                    for node in ast.walk(definition.node):
                        if isinstance(node, ast.Return) and node.value and self.scopes.get(id(node)) is definition:
                            result.update(self.infer_models(node.value, definition, seen, depth + 1))
            if isinstance(expr.func, ast.Attribute):
                result.update(self.infer_models(expr.func.value, scope, seen, depth))
            if self.dotted(expr.func).split('.')[-1] in {'query', 'select'}:
                for arg in expr.args:
                    result.update(self.infer_models(arg, scope, seen, depth))
        self._inference_cache[key] = result
        return result

    def assignments(self, scope: Scope, name: str, before: int) -> list[ast.AST]:
        # The repository AST is immutable after build. Index lexical assignments
        # once instead of walking a module for every possible receiver call.
        if self._assignment_index is None:
            self._assignment_index = defaultdict(list)
            for tree in self.trees.values():
                for node in ast.walk(tree):
                    if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                        continue
                    owner = self.scopes[id(node)]
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    # Destructuring still identifies the producing expression.
                    # Collect its full return evidence; do not claim which
                    # element flows without reviewing the supplied code.
                    bound_targets = [n for target in targets for n in ast.walk(target)
                                     if isinstance(n, (ast.Name, ast.Attribute))
                                     and isinstance(n.ctx, ast.Store)]
                    for target_name in {self.dotted(target) for target in bound_targets}:
                        self._assignment_index[(id(owner.node), target_name)].append(node)
            for nodes in self._assignment_index.values():
                nodes.sort(key=lambda n: n.lineno, reverse=True)
        return [node for node in self._assignment_index.get((id(scope.node), name), [])
                if node.lineno < before]

    def context_items(self, expr: ast.AST, scope: Scope, before: int, seen=None) -> dict[str, list[ast.AST]]:
        seen = set() if seen is None else seen
        result: dict[str, list[ast.AST]] = defaultdict(list)
        if isinstance(expr, ast.Dict):
            for k, value in zip(expr.keys, expr.values):
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    result[k.value].append(value)
                elif k is None:
                    for key, values in self.context_items(value, scope, before, seen).items():
                        result[key].extend(values)
        elif isinstance(expr, ast.Name) and expr.id not in seen:
            seen = seen | {expr.id}
            for assignment in self.assignments(scope, expr.id, before):
                for key, values in self.context_items(assignment.value, scope, assignment.lineno, seen).items():
                    result[key].extend(values)
            # Include mutations rather than silently considering only the last
            # literal assignment to a context dictionary.
            for node in ast.walk(scope.node):
                if self.scopes.get(id(node)) is not scope or getattr(node, 'lineno', before) >= before:
                    continue
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and target.value.id == expr.id and isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
                            result[target.slice.value].append(node.value)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'update' and isinstance(node.func.value, ast.Name) and node.func.value.id == expr.id:
                    for arg in node.args:
                        for key, values in self.context_items(arg, scope, node.lineno, seen).items():
                            result[key].extend(values)
                    for kw in node.keywords:
                        if kw.arg:
                            result[kw.arg].append(kw.value)
        return result

    @staticmethod
    def template_name(file: str) -> str:
        for marker in ('templates/', 'template/'):
            if marker in file:
                return file.split(marker, 1)[1]
        return file

    def template_renderer_names(self, file: str) -> set[str]:
        """Reverse literal include/extends edges; possible renderers, not identity proof."""
        if self._template_dependencies is None:
            reverse: dict[str, set[str]] = defaultdict(set)
            for path in sorted(self.root.rglob("*")):
                if path.suffix.lower() not in self.TEMPLATE_SUFFIXES or not path.is_file():
                    continue
                if not path.resolve().is_relative_to(self.root):
                    continue
                try:
                    text = path.read_text(encoding="utf-8")
                except (OSError, UnicodeError):
                    continue
                text = re.sub(r"{#.*?#}|{%\s*comment\b.*?{%\s*endcomment\s*%}|{%\s*(?:raw|verbatim)\s*%}.*?{%\s*end(?:raw|verbatim)\s*%}", "", text, flags=re.S)
                child = self.template_name(path.relative_to(self.root).as_posix())
                for match in re.finditer(r"{%\s*(?:extends|include)\s+([\"'])(.*?)\1", text, re.S):
                    reverse[match[2]].add(child)
            self._template_dependencies = reverse
        names = {self.template_name(file), file}
        pending = list(names)
        while pending:
            for child in self._template_dependencies.get(pending.pop(), set()):
                if child not in names:
                    names.add(child)
                    pending.append(child)
        return names

    def render_bindings(self, file: str):
        names = self.template_renderer_names(file)
        name = self.template_name(file)
        for scope, call in self.calls:
            leaf = self.dotted(call.func).split('.')[-1]
            if leaf not in self.RENDER_NAMES:
                continue
            strings = [(index, arg.value) for index, arg in enumerate(call.args)
                       if isinstance(arg, ast.Constant) and isinstance(arg.value, str)]
            strings.extend((-1, kw.value.value) for kw in call.keywords
                           if kw.arg in {'template_name', 'template'} and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str))
            context_args: list[ast.AST] = []
            matched = [(i, value) for i, value in strings if value in names]
            if matched:
                for index, _ in matched:
                    if index >= 0:
                        context_args.extend(call.args[index + 1:index + 2])
            elif isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name) and leaf == 'render':
                for assignment in self.assignments(scope, call.func.value.id, call.lineno):
                    value = assignment.value
                    if isinstance(value, ast.Call) and self.dotted(value.func).split('.')[-1] in {'get_template', 'select_template'} and any(isinstance(arg, ast.Constant) and arg.value in names for arg in value.args):
                        matched = [(0, name)]
                        context_args.extend(call.args[:1])
            if not matched:
                continue
            items: dict[str, list[ast.AST]] = defaultdict(list)
            for arg in context_args:
                for key, values in self.context_items(arg, scope, call.lineno).items():
                    items[key].extend(values)
            for kw in call.keywords:
                if kw.arg in {'context', 'dictionary'} or kw.arg is None:
                    for key, values in self.context_items(kw.value, scope, call.lineno).items():
                        items[key].extend(values)
                elif kw.arg not in {'template_name', 'template', 'request', 'content_type', 'status', 'using'}:
                    items[kw.arg].append(kw.value)
            yield scope, call, items

    def collect(self, file: str, line: int, requests: list[str] | None = None) -> LinkResult:
        self.build()
        refs: list[Reference] = []
        events: list[dict] = []
        facts: list[str] = []
        seen_refs = set()
        seen_visits = set()
        seen_framework_scopes = set()
        framework_collector = FastAPIBindings(self)

        def add(scope: Scope, node: ast.AST, reason: str, key: str) -> None:
            reference = Reference(scope.file, self.start(node), self.end(node), reason, key)
            if reference not in seen_refs:
                refs.append(reference)
                seen_refs.add(reference)
            events.append({'kind': reason, 'target': key, 'status': 'located', 'file': reference.file, 'start_line': reference.start, 'end_line': reference.end, 'certainty': 'syntactic_possible'})

        def imports(scope: Scope) -> None:
            if id(scope.node) not in seen_framework_scopes:
                seen_framework_scopes.add(id(scope.node))
                receiver = scope
                while receiver and not isinstance(receiver.node, ast.ClassDef):
                    receiver = receiver.parent
                if receiver and any(framework_collector.qualified(base, receiver) ==
                                    'http.server.BaseHTTPRequestHandler'
                                    for base in receiver.node.bases):
                    # Preserve the receiver contract for reached callers too,
                    # not only when the candidate is inside the HTTP handler.
                    header = ast.Pass(lineno=self.start(receiver.node),
                        end_lineno=max(self.start(receiver.node), receiver.node.body[0].lineno - 1))
                    add(receiver, header, 'http_handler_binding', receiver.name)
                    fact = ('For a subclass of http.server.BaseHTTPRequestHandler, self.path contains '
                            'the client HTTP request path, including the query if present. Inspect any '
                            'supplied overrides or reassignment before the sink.')
                    events.append({'kind': 'http_handler_contract', 'target': receiver.name,
                        'status': 'located', 'certainty': 'documented_api_binding', 'fact': fact,
                        'required_ranges': [{'file': receiver.file, 'start_line': self.start(header),
                                             'end_line': self.end(header)}],
                        'documentation_url': 'https://docs.python.org/3/library/http.server.html'})
                    facts.append(fact)
                for parameter, fact, references in self.receiver_bindings.request_bindings(scope):
                    required = []
                    for bound_scope, node in references:
                        add(bound_scope, node, 'framework_binding_evidence', parameter)
                        required.append({'file': bound_scope.file, 'start_line': self.start(node), 'end_line': self.end(node)})
                    events.append({'kind': 'flask_restful_request_binding', 'target': parameter,
                        'status': 'located', 'certainty': 'documented_api_binding', 'fact': fact,
                        'required_ranges': required,
                        'documentation_url': 'https://flask-restful.readthedocs.io/en/latest/reqparse.html'})
                    facts.append(fact)
                for binding in framework_collector.collect(scope):
                    required = []
                    for bound_scope, node in binding.references:
                        add(bound_scope, node, 'framework_binding_evidence', binding.parameter)
                        required.append({'file': bound_scope.file, 'start_line': self.start(node), 'end_line': self.end(node)})
                    event = {'kind': 'fastapi_parameter_binding', 'target': binding.parameter,
                             'binding': binding.kind, 'status': 'located' if binding.fact else 'unresolved',
                             'certainty': 'documented_api_binding' if binding.fact else 'unresolved',
                             'required_ranges': required,
                             'documentation_url': ('https://fastapi.tiangolo.com/tutorial/dependencies/'
                                                   if binding.kind == 'dependency' else
                                                   'https://fastapi.tiangolo.com/tutorial/body/'
                                                   if binding.kind == 'body' else
                                                   'https://fastapi.tiangolo.com/tutorial/query-params/')}
                    if binding.fact:
                        event['fact'] = binding.fact
                        facts.append(binding.fact)
                    events.append(event)
            current = scope
            while current:
                for node in self._scope_imports[id(current.node)]:
                    add(current, node, 'import_binding', scope.name)
                current = current.parent

        def follow(expr: ast.AST | None, scope: Scope, depth: int = 0) -> set[str]:
            # Annotation-only assignments and bare returns have no expression.
            # They supply no value origin; never unparse or traverse None.
            if expr is None:
                return set()
            identity = (scope.file, id(expr))
            if identity in seen_visits:
                return set()
            seen_visits.add(identity)
            if depth > self.max_depth:
                events.append({'kind': 'value_origin', 'target': ast.unparse(expr), 'status': 'depth_limit', 'max_depth': self.max_depth})
                return set()
            models = set()
            if isinstance(expr, ast.Name):
                assignments = self.assignments(scope, expr.id, getattr(expr, 'lineno', self.end(scope.node) + 1))
                for assignment in assignments:
                    add(scope, assignment, 'assignment', expr.id)
                    models.update(follow(assignment.value, scope, depth))
                if not assignments:
                    models.update(self.model_key(s) for s in self.resolve(expr, scope) if isinstance(s.node, ast.ClassDef))
                    arguments = getattr(scope.node, 'args', None)
                    if arguments:
                        parameters = [a.arg for a in [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]]
                        if expr.id in parameters:
                            index = parameters.index(expr.id)
                            for caller, call in self.callers_for(scope):
                                decorators = {self.dotted(d) for d in scope.node.decorator_list}
                                receiver_proofs = self.receiver_bindings.proofs(call.func, caller, scope)
                                bound_receiver = isinstance(call.func, ast.Attribute) and (
                                    self.dotted(call.func.value) in {'self', 'cls'} or 'classmethod' in decorators
                                    or bool(receiver_proofs) and all(proof.instance for proof in receiver_proofs))
                                offset = int(parameters[:1] in (['self'], ['cls'])
                                             and bound_receiver and 'staticmethod' not in decorators)
                                values = [kw.value for kw in call.keywords if kw.arg == expr.id]
                                positional = index - offset
                                if not values and index < len(arguments.posonlyargs) + len(arguments.args) and 0 <= positional < len(call.args):
                                    values = [call.args[positional]]
                                if values:
                                    add(caller, caller.node, 'caller_argument_binding', f'{scope.name}.{expr.id}')
                                    imports(caller)
                                    receiver_ranges = []
                                    for proof in receiver_proofs:
                                        for proof_scope, proof_node in proof.references:
                                            add(proof_scope, proof_node, 'possible_receiver_binding', scope.name)
                                            imports(proof_scope)
                                            receiver_ranges.append({'file': proof_scope.file,
                                                'start_line': self.start(proof_node), 'end_line': self.end(proof_node)})
                                    if receiver_proofs and scope.parent and isinstance(scope.parent.node, ast.ClassDef):
                                        parent = scope.parent
                                        header = ast.Pass(lineno=self.start(parent.node),
                                            end_lineno=max(self.start(parent.node), parent.node.body[0].lineno - 1))
                                        add(parent, header, 'receiver_class_declaration', parent.name)
                                        receiver_ranges.append({'file': parent.file,
                                            'start_line': self.start(header), 'end_line': self.end(header)})
                                    for value in values:
                                        add(caller, call, 'call_argument_binding', f'{scope.name}.{expr.id}')
                                        conversion = ''
                                        if isinstance(value, ast.Call) and framework_collector.scalar(value.func, caller):
                                            name = self.dotted(value.func).rsplit('.', 1)[-1]
                                            if name in {'int', 'float', 'bool', 'str', 'bytes'}:
                                                conversion = 'builtins.' + name
                                            else:
                                                conversion = framework_collector.qualified(value.func, caller)
                                        contract = {
                                            'kind': 'call_argument_contract', 'status': 'located',
                                            'certainty': 'syntactic_possible',
                                            'caller': caller.name, 'caller_file': caller.file,
                                            'callee': scope.name, 'callee_file': scope.file,
                                            'parameter': expr.id, 'argument': ast.unparse(value),
                                            'builtin_conversion': conversion,
                                            'receiver_configuration_dependent': any(p.conditional for p in receiver_proofs),
                                            'required_ranges': [
                                                {'file': caller.file, 'start_line': self.start(call), 'end_line': self.end(call)},
                                                {'file': scope.file, 'start_line': self.start(scope.node), 'end_line': self.end(scope.node)},
                                            ] + receiver_ranges,
                                        }
                                        if contract['receiver_configuration_dependent']:
                                            contract['fact'] = ('This possible method receiver was selected through a factory or Flask application attribute. '
                                                'The supplied finite bindings do not prove the active application identity or configuration branch. '
                                                'Inspect the supplied factory and configuration before treating the call as a proven runtime edge.')
                                            facts.append(contract['fact'])
                                        events.append(contract)
                                        models.update(follow(value, caller, depth + 1))
            elif isinstance(expr, ast.Attribute):
                models.update(follow(expr.value, scope, depth))
                related = self.related_names.get(expr.attr, [])
                if related:
                    models = {self.model_key(model) for model in related}
                    for model in related:
                        for declaration in model.node.body:
                            if isinstance(declaration, (ast.Assign, ast.AnnAssign)) and any(isinstance(kw, ast.keyword) and kw.arg == 'related_name' and isinstance(kw.value, ast.Constant) and kw.value.value == expr.attr for kw in ast.walk(declaration)):
                                add(model, declaration, 'orm_related_name', expr.attr)
                for model in self.classes:
                    if self.model_key(model) not in models:
                        continue
                    for declaration in model.node.body:
                        if isinstance(declaration, (ast.Assign, ast.AnnAssign)):
                            targets = declaration.targets if isinstance(declaration, ast.Assign) else [declaration.target]
                            if any(self.dotted(target) == expr.attr for target in targets):
                                add(model, declaration, 'field_declaration', f'{model.name}.{expr.attr}')
            elif isinstance(expr, ast.Call):
                invocation = self.callback_bindings.invocation(expr, scope)
                if invocation:
                    add(scope, expr, 'callback_invocation', invocation._callback_api)
                    events[-1]['callback'] = ast.unparse(invocation.func)
                    events[-1]['forwarded_arguments'] = [ast.unparse(a) for a in invocation.args]
                for definition in self.resolve((invocation or expr).func, scope):
                    if isinstance(definition.node, ast.ClassDef):
                        models.add(self.model_key(definition))
                        # Field-level declarations are selected later; avoid
                        # reading an entire model class for a constructor.
                    else:
                        add(definition, definition.node, 'callee', self.dotted(expr.func))
                        imports(definition)
                        for node in ast.walk(definition.node):
                            if isinstance(node, ast.Return) and node.value and self.scopes.get(id(node)) is definition:
                                models.update(follow(node.value, definition, depth + 1))
                if isinstance(expr.func, ast.Attribute):
                    models.update(follow(expr.func.value, scope, depth))
                for arg in [*expr.args, *[kw.value for kw in expr.keywords]]:
                    models.update(follow(arg, scope, depth))
                if self.dotted(expr.func).split('.')[-1] in {'query', 'select'}:
                    for arg in expr.args:
                        models.update(self.model_key(s) for s in self.resolve(arg, scope) if isinstance(s.node, ast.ClassDef))
            else:
                for child in ast.iter_child_nodes(expr):
                    if isinstance(child, ast.expr):
                        models.update(follow(child, scope, depth))
            return models

        def field_origin(field: str, models: set[str]) -> None:
            classes = [s for s in self.classes if self.model_key(s) in models]
            if not classes:
                events.append({'kind': 'field_origin', 'target': field, 'status': 'unresolved_model_identity'})
                return
            for model in classes:
                for node in model.node.body:
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
                    if any(self.dotted(t) == field for t in targets) or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == field:
                        add(model, node, 'field_declaration', f'{model.name}.{field}')
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            function = self.scopes[id(node)]
                            for value in ast.walk(node):
                                if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name) and value.value.id == 'self':
                                    for declaration in model.node.body:
                                        if isinstance(declaration, ast.Assign) and any(self.dotted(t) == value.attr for t in declaration.targets):
                                            add(model, declaration, 'field_type', f'{model.name}.{value.attr}')
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name) and value.value.id == 'self' and value.attr == field and isinstance(value.ctx, ast.Store) for value in ast.walk(node)):
                        add(model, node, 'model_field_assignment', f'{model.name}.{field}')
                for scope, call in self.calls:
                    definitions = self.resolve(call.func, scope)
                    is_constructor = any(d is model for d in definitions)
                    is_update = self.dotted(call.func).split('.')[-1] == 'update' and isinstance(call.func, ast.Attribute) and self.model_key(model) in self.infer_models(call.func.value, scope)
                    values = [kw.value for kw in call.keywords if kw.arg == field] if is_constructor or is_update else []
                    if is_update:
                        for arg in call.args:
                            values.extend(self.context_items(arg, scope, call.lineno).get(field, []))
                    if values:
                        add(scope, scope.node, 'field_write', f'{model.name}.{field}')
                        imports(scope)
                        for value in values:
                            follow(value, scope)
                # Direct assignments require matching receiver identity.
                for tree in self.trees.values():
                    for node in ast.walk(tree):
                        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                            continue
                        scope = self.scopes[id(node)]
                        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                        for target in targets:
                            if isinstance(target, ast.Attribute) and target.attr == field and self.model_key(model) in self.infer_models(target.value, scope):
                                add(scope, scope.node, 'field_write', f'{model.name}.{field}')
                                follow(node.value, scope)

        def sql_provenance(scopes: list[Scope], field: str) -> None:
            tables = set()
            for scope in scopes:
                for node in ast.walk(scope.node):
                    if isinstance(node, ast.Constant) and isinstance(node.value, str):
                        tables.update(re.findall(r'\bFROM\s+["`\[]?([\w]+)', node.value, re.I))
            for scope, call in self.calls:
                if self.dotted(call.func).split('.')[-1] not in {'execute', 'executemany'}:
                    continue
                # SQL names are linking clues, not proof that two connections
                # reference the same database or row.
                strings = [node.value for node in ast.walk(scope.node) if isinstance(node, ast.Constant) and isinstance(node.value, str)]
                if any(re.search(r'\b(?:UPDATE|INTO)\s+["`\[]?' + re.escape(table) + r'\b', sql, re.I) and re.search(r'\b' + re.escape(field) + r'\b', sql) for table in tables for sql in strings):
                    add(scope, scope.node, 'sql_possible_field_write', field)
                    imports(scope)
                    for node in ast.walk(scope.node):
                        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None and any(isinstance(x, ast.Constant) and x.value == field for x in ast.walk(node.value)):
                            follow(node.value, scope)

        owner = self.owner(file, line)
        if owner:
            imports(owner)
            if self.include_call_chains:
                # Bidirectional possible-call evidence, never a taint-flow proof.
                # Add callers before deeper helpers so consumer and input contracts
                # compete for the budget before unrelated leaf definitions.
                queue = [(owner, 0)]
                visited = set()
                while queue:
                    related, depth = queue.pop(0)
                    if id(related.node) in visited:
                        continue
                    visited.add(id(related.node))
                    if depth >= 2:
                        events.append({'kind': 'possible_call_chain', 'target': related.name,
                                       'status': 'depth_limit', 'max_depth': 2})
                        continue
                    for caller, call in self.callers_for(related):
                        if caller is related:
                            continue
                        add(caller, caller.node, 'possible_call_consumer', related.name)
                        imports(caller)
                        queue.append((caller, depth + 1))
                    if related.parent and isinstance(related.parent.node, ast.ClassDef):
                        for initializer in self.definitions.get('__init__', []):
                            if initializer.parent is related.parent:
                                add(initializer, initializer.node, 'receiver_constructor', related.name)
                                imports(initializer)
                        for caller, call in self.callers_for(related.parent):
                            add(caller, caller.node, 'possible_constructor_input', related.parent.name)
                            imports(caller)
                    for called_scope, call in self.calls:
                        if called_scope is related:
                            for definition in self.resolve(call.func, related):
                                if not isinstance(definition.node, ast.ClassDef):
                                    add(definition, definition.node, 'possible_call_helper', self.dotted(call.func))
                                    imports(definition)
                                    queue.append((definition, depth + 1))
            if isinstance(owner.node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if owner.node.decorator_list:
                    add(owner, owner.node, 'route_or_decorator_binding', owner.name)
                    if any(self.dotted(call.func).split('.')[-1] in {'route', 'get', 'post', 'put', 'delete'} for decorator in owner.node.decorator_list for call in ast.walk(decorator) if isinstance(call, ast.Call)) and any(value.startswith('flask.') or value == 'flask' for value in self.imports(owner).values()):
                        facts.append('A Flask view bound by a route returns a string as an HTML response by default; inspect explicit response/content-type overrides in the supplied code.')
                # URL bindings are checked by qualified imported symbol, not
                # by the terminal function name alone.
                for scope, call in self.calls:
                    if self.dotted(call.func).split('.')[-1] in {'url', 'path', 're_path'} and any(owner in self.resolve(arg, scope) for arg in call.args[1:2]):
                        add(scope, call, 'django_url_binding', owner.name)
                        imports(scope)
                if owner.name.startswith('resolve_') and owner.parent and isinstance(owner.parent.node, ast.ClassDef):
                    field = owner.name.removeprefix('resolve_')
                    for node in owner.parent.node.body:
                        if isinstance(node, ast.Assign) and any(self.dotted(target) == field for target in node.targets):
                            add(owner.parent, node, 'graphql_argument_binding', owner.name)
                            facts.append('Graphene field argument declarations bind client-provided GraphQL arguments to the matching resolver parameters.')
            statements = [node for node in ast.walk(owner.node)
                          if isinstance(node, ast.stmt) and self.scopes.get(id(node)) is owner
                          and not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                          and node.lineno <= line <= node.end_lineno]
            if statements:
                statement = min(statements, key=lambda node: node.end_lineno - node.lineno)
                for child in ast.iter_child_nodes(statement):
                    if isinstance(child, ast.expr):
                        follow(child, owner)
            for node in ast.walk(owner.node):
                if isinstance(node, ast.Call) and self.scopes.get(id(node)) is owner:
                    for definition in self.resolve(node.func, owner):
                        if not isinstance(definition.node, ast.ClassDef):
                            add(definition, definition.node, 'callee', self.dotted(node.func))
                            imports(definition)

        if file.endswith(self.TEMPLATE_SUFFIXES):
            path = (self.root / file).resolve()
            if path.is_relative_to(self.root) and path.is_file():
                lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
                # An implicit framework queue provides possible producer links,
                # not proof of shared application/session or completeness.
                flash_bindings = []
                active_with = []
                for number, text in enumerate(lines[:line], 1):
                    for tag in re.findall(r'{%\s*(.*?)\s*%}', text):
                        if tag.startswith('with '):
                            match = re.match(r'with\s+([A-Za-z_]\w*)\s*=\s*get_flashed_messages\s*\(', tag)
                            active_with.append((number, match[1]) if match else None)
                        elif tag.startswith('endwith') and active_with:
                            active_with.pop()
                flash_bindings = [binding for binding in active_with if binding]
                if flash_bindings:
                    for number, variable in flash_bindings:
                        refs.append(Reference(file, number, number, 'template_flash_binding', variable))
                        events.append({'kind': 'template_flash_binding', 'target': variable,
                                       'status': 'located', 'file': file, 'start_line': number,
                                       'end_line': number, 'certainty': 'syntactic_possible'})
                    for producer, call in self.calls:
                        name = self.dotted(call.func)
                        first, _, rest = name.partition('.')
                        imported = self.imports(producer).get(first)
                        qualified = imported + ('.' + rest if rest else '') if imported else ''
                        if qualified != 'flask.flash' or self.resolve(call.func, producer):
                            continue
                        if self.assignments(producer, first, call.lineno):
                            continue
                        add(producer, call, 'flask_possible_flash_producer', name)
                        imports(producer)
                        for decorator in getattr(producer.node, 'decorator_list', []):
                            add(producer, decorator, 'flash_producer_decorator', producer.name)
                        values = call.args[:1] or [kw.value for kw in call.keywords if kw.arg == 'message']
                        for value in values:
                            follow(value, producer)
                    facts.append("If template get_flashed_messages is Flask's default binding, it reads messages placed by flask.flash. Supplied flash calls are possible repository producers; application/session identity and completeness are not proven. Inspect message values and overrides rather than assuming attacker control or safety.")
                # Track nested loop scopes up to the anchor. Do not bind an
                # alias from an already-ended or later loop.
                loops: list[dict[str, str]] = []
                loop_lines: list[int] = []
                for number, text in enumerate(lines[:line], 1):
                    for tag in re.findall(r'{%\s*(.*?)\s*%}', text):
                        match = re.match(r'for\s+([\w]+)\s+in\s+([\w.]+)', tag)
                        if match:
                            loops.append({match[1]: match[2]});loop_lines.append(number)
                        elif tag.startswith('endfor') and loops:
                            loops.pop();loop_lines.pop()
                expressions = re.findall(r'{{\s*(.*?)\s*}}', lines[line - 1]) if line <= len(lines) else []
                targets = []
                for request in requests or []:
                    match = re.match(r'(?i)^field origin\s*:\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)$', request.strip())
                    if match:
                        expressions.append(match[1])
                for expression in expressions:
                    first = re.match(r'([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)', expression)
                    if first:
                        value = first[1]
                        for mapping in reversed(loops):
                            root, _, rest = value.partition('.')
                            if root in mapping:
                                value = mapping[root] + ('.' + rest if rest else '')
                        targets.append((first[1], value))
                for number in loop_lines:
                    refs.append(Reference(file, number, number, 'template_loop_binding', 'loop'))
                    events.append({'kind': 'template_loop_binding', 'target': 'loop', 'status': 'located', 'file': file, 'start_line': number, 'end_line': number, 'certainty': 'syntactic_possible'})
                for original, target in dict.fromkeys(targets):
                    root, _, suffix = target.partition('.')
                    # ORM's .all is a collection operation, not a data field.
                    fields = [part for part in suffix.split('.') if part and part not in {'all', 'first', 'last'}]
                    found = False
                    for scope, call, items in self.render_bindings(file):
                        if root not in items:
                            continue
                        found = True
                        add(scope, scope.node, 'template_renderer', original)
                        imports(scope)
                        before = set(seen_refs)
                        models = set()
                        for expr in items[root]:
                            models.update(follow(expr, scope))
                            models.update(self.infer_models(expr, scope))
                        for field in fields:
                            field_origin(field, models)
                            # Queries returning DB rows have no Python model.
                            if not models:
                                related = [self.scopes[id(self.trees[r.file])] if r.start == 1 else self.owner(r.file, r.start) for r in seen_refs - before if r.file.endswith('.py')]
                                sql_provenance([s for s in related if s], field)
                        events.append({'kind': 'template_context_binding', 'target': original, 'context_key': root, 'models': sorted(models), 'status': 'located', 'file': scope.file, 'line': call.lineno, 'certainty': 'syntactic_possible'})
                    if not found:
                        events.append({'kind': 'template_context_binding', 'target': original, 'context_key': root, 'status': 'unresolved'})

        for request in dict.fromkeys(requests or []):
            # Keep legacy names valid, while adding explicit relationship kinds.
            kind, target = self.expansion_request(request)
            start = len(refs)
            if kind == 'template renderer' or target.endswith(self.TEMPLATE_SUFFIXES):
                for scope, call, _ in self.render_bindings(target):
                    add(scope, scope.node, 'requested_template_renderer', target)
                    imports(scope)
            elif re.fullmatch(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*', target):
                if owner:
                    for definition in self.resolve(ast.parse(target, mode='eval').body, owner):
                        add(definition, definition.node, 'requested_definition', target)
                        imports(definition)
                    root = target.split('.')[0]
                    for assignment in self.assignments(owner, root, owner.node.end_lineno + 1):
                        add(owner, assignment, 'requested_assignment', target)
                        models = follow(assignment.value, owner)
                        if '.' in target:
                            field_origin(target.rsplit('.', 1)[-1], models)
                if kind == 'caller' and owner:
                    definitions = self.resolve(ast.parse(target, mode='eval').body, owner)
                    for definition in definitions:
                        for scope, call in self.callers_for(definition):
                            add(scope, scope.node, 'requested_caller', target)
                            imports(scope)
                            for value in [*call.args, *[kw.value for kw in call.keywords]]:
                                follow(value, scope)
            located = len(refs) > start or any(event.get('target') == target and event.get('status') == 'located' for event in events)
            if kind == 'caller':
                located = any(event.get('kind') == 'requested_caller' and event.get('target') == target for event in events)
            events.append({'kind': 'expansion_request', 'request': request, 'request_kind': kind, 'target': target, 'status': 'located' if located else 'no_additional_relation'})
        if self.parse_errors:
            events.append({'kind': 'index_parse_errors', 'status': 'incomplete', 'files': self.parse_errors})
        return LinkResult(refs, events, list(dict.fromkeys(facts)))
