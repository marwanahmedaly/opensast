"""Conservative framework contracts tied to repository declarations.

This describes input binding, not exploitability or proven interprocedural flow.
No framework is imported or executed while inspecting repository code.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aisast.context.relationships import RepositoryRelationships, Scope


@dataclass
class Binding:
    parameter: str
    kind: str
    fact: str = ''
    # Every reference is necessary for the fact to survive packet budgeting.
    references: list[tuple[Scope, ast.AST]] = field(default_factory=list)


class FastAPIBindings:
    METHODS = {'get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace', 'api_route'}
    MARKERS = {'Query': 'query', 'Path': 'path', 'Body': 'body', 'Header': 'header',
               'Cookie': 'cookie', 'Form': 'form', 'File': 'file',
               'Depends': 'dependency', 'Security': 'dependency'}

    def __init__(self, index: RepositoryRelationships):
        self.index = index

    def qualified(self, node: ast.AST, scope: Scope) -> str:
        name = self.index.dotted(node)
        root, _, rest = name.partition('.')
        imported = self.index.imports(scope).get(root)
        if not imported:
            return ''
        # Imported names replaced anywhere in lexical scopes are ambiguous.
        current = scope
        while current:
            arguments = getattr(current.node, 'args', None)
            if arguments and any(a.arg == root for a in [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs,
                                                        *([arguments.vararg] if arguments.vararg else []),
                                                        *([arguments.kwarg] if arguments.kwarg else [])]):
                return ''
            if any(definition.parent is current for definition in self.index.definitions.get(root, [])):
                return ''
            for item in ast.walk(current.node):
                if self.index.scopes.get(id(item)) is not current:
                    continue
                if isinstance(item, ast.Name) and isinstance(item.ctx, (ast.Store, ast.Del)) and item.id == root:
                    return ''
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and item.name == root:
                    return ''
            current = current.parent
        return imported + ('.' + rest if rest else '')

    def receiver(self, node: ast.AST, scope: Scope, seen=None):
        """Resolve a single constructor assignment, including imported app variables."""
        seen = set() if seen is None else seen
        key = (scope.file, self.index.dotted(node))
        if not key[1] or key in seen:
            return []
        seen = seen | {key}
        name = self.index.dotted(node)
        qualified = self.qualified(node, scope)
        module, _, symbol = qualified.rpartition('.')
        if module:
            files = [f for f in (module.replace('.', '/') + '.py', module.replace('.', '/') + '/__init__.py')
                     if f in self.index.trees]
            if len(files) != 1:
                return []
            other = self.index.scopes[id(self.index.trees[files[0]])]
            result = self.receiver(ast.Name(id=symbol), other, seen)
            import_nodes = [n for n in self.index.trees[scope.file].body
                            if isinstance(n, (ast.Import, ast.ImportFrom))]
            return [*result, *[(scope, n) for n in import_nodes]] if result else []
        if not isinstance(node, ast.Name):
            return []
        current = scope
        while current:
            assignments = [n for n in ast.walk(current.node)
                           if self.index.scopes.get(id(n)) is current
                           and isinstance(n, (ast.Assign, ast.AnnAssign))
                           and any(self.index.dotted(t) == name for t in
                                   (n.targets if isinstance(n, ast.Assign) else [n.target]))]
            writes = [n for n in ast.walk(current.node) if self.index.scopes.get(id(n)) is current
                      and isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)) and n.id == name]
            arguments = getattr(current.node, 'args', None)
            if arguments and any(a.arg == name for a in [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs,
                                                       *([arguments.vararg] if arguments.vararg else []),
                                                       *([arguments.kwarg] if arguments.kwarg else [])]):
                return []
            if any(definition.parent is current for definition in self.index.definitions.get(name, [])):
                return []
            if assignments or writes:
                if len(assignments) != 1 or len(writes) != 1:
                    return []
                assignment = assignments[0]
                if not isinstance(assignment.value, ast.Call) or self.qualified(assignment.value.func, current) not in {
                    'fastapi.FastAPI', 'fastapi.APIRouter', 'fastapi.applications.FastAPI', 'fastapi.routing.APIRouter'
                }:
                    return []
                return [(current, assignment), *[(current, n) for n in self.index.trees[current.file].body
                                                if isinstance(n, (ast.Import, ast.ImportFrom))]]
            current = current.parent
        return []

    def annotation(self, node: ast.AST | None, scope: Scope):
        """Unwrap only known typing constructs, retaining Annotated metadata."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            try:
                node = ast.parse(node.value, mode='eval').body
            except SyntaxError:
                return None, []
        if isinstance(node, ast.Subscript):
            q = self.qualified(node.value, scope)
            parts = list(node.slice.elts) if isinstance(node.slice, ast.Tuple) else [node.slice]
            if q in {'typing.Annotated', 'typing_extensions.Annotated'}:
                base, metadata = self.annotation(parts[0], scope)
                return base, [*metadata, *parts[1:]]
            if q == 'typing.Optional':
                return self.annotation(parts[0], scope)
            if q == 'typing.Union':
                real = [p for p in parts if not (isinstance(p, ast.Constant) and p.value is None)]
                if len(real) == 1:
                    return self.annotation(real[0], scope)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            parts = [node.left, node.right]
            real = [p for p in parts if not (isinstance(p, ast.Constant) and p.value is None)]
            if len(real) == 1:
                return self.annotation(real[0], scope)
        return node, []

    def scalar(self, node: ast.AST | None, scope: Scope) -> bool:
        names = {'str', 'int', 'float', 'bool', 'bytes'}
        if node is None:
            return False
        qualified = self.qualified(node, scope)
        if qualified in {'builtins.' + name for name in names}:
            if any(isinstance(item, ast.Attribute) and isinstance(item.ctx, (ast.Store, ast.Del))
                   and self.qualified(item, self.index.scopes.get(id(item), scope)) == qualified
                   for item in ast.walk(self.index.trees[scope.file])):
                return False
            return True
        if not isinstance(node, ast.Name) or node.id not in names:
            return False
        current = scope
        while current:
            if node.id in self.index.imports(current):
                return False
            if any(d.parent is current for d in self.index.definitions.get(node.id, [])):
                return False
            args = getattr(current.node, 'args', None)
            if args and any(a.arg == node.id for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]):
                return False
            if any(isinstance(n, ast.Name) and n.id == node.id and isinstance(n.ctx, (ast.Store, ast.Del))
                   and self.index.scopes.get(id(n)) is current for n in ast.walk(current.node)):
                return False
            current = current.parent
        return True

    def collect(self, scope: Scope) -> list[Binding]:
        owner = scope.node
        if not isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return []
        results = []
        for decorator in owner.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute) or decorator.func.attr not in self.METHODS:
                continue
            refs = self.receiver(decorator.func.value, scope)
            if not refs:
                results.append(Binding('<route>', 'unresolved_receiver'))
                continue
            paths = [a.value for a in decorator.args[:1] if isinstance(a, ast.Constant) and isinstance(a.value, str)]
            paths += [kw.value.value for kw in decorator.keywords if kw.arg == 'path' and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str)]
            if len(paths) != 1:
                results.append(Binding('<route>', 'unresolved_route_path'))
                continue
            route = paths[0]
            # Signature and full handler preserve constraints and overriding assignments.
            shared = [*refs, (scope, owner)]
            args = owner.args
            positional = [*args.posonlyargs, *args.args]
            defaults = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
            for param, default in zip([*positional, *args.kwonlyargs], [*defaults, *args.kw_defaults]):
                base, metadata = self.annotation(param.annotation, scope)
                markers = [n for n in [default, *metadata] if isinstance(n, ast.Call)
                           and self.qualified(n.func, scope) in {prefix + name for prefix in ('fastapi.', 'fastapi.params.')
                                                                                 for name in self.MARKERS}]
                if len(markers) > 1:
                    results.append(Binding(param.arg, 'ambiguous_markers'))
                    continue
                if not markers and isinstance(default, ast.Call):
                    results.append(Binding(param.arg, 'unresolved_default_factory'))
                    continue
                references = list(shared)
                marker = markers[0] if markers else None
                marker_name = self.qualified(marker.func, scope).rsplit('.', 1)[-1] if marker else ''
                kind = self.MARKERS.get(marker_name, '')
                if kind == 'dependency':
                    provider = marker.args[0] if marker.args else next((k.value for k in marker.keywords if k.arg == 'dependency'), None)
                    if provider:
                        for definition in self.index.resolve(provider, scope):
                            references.append((definition, definition.node))
                            references.extend((definition, n) for n in self.index.trees[definition.file].body
                                              if isinstance(n, (ast.Import, ast.ImportFrom)))
                    fact = f'FastAPI {scope.file}:{owner.lineno} {owner.name}.{param.arg} is supplied by {ast.unparse(marker)}; it is not a direct query input. Inspect the provider before assigning trust.'
                else:
                    models = self.index.resolve(base, scope) if base is not None else []
                    body_models = [m for m in models if isinstance(m.node, ast.ClassDef) and any(
                        self.qualified(b, m) in {'pydantic.BaseModel', 'pydantic.main.BaseModel'} for b in m.node.bases)]
                    if len(body_models) == 1:
                        model = body_models[0]
                        references.append((model, model.node))
                        references.extend((model, n) for n in self.index.trees[model.file].body
                                          if isinstance(n, (ast.Import, ast.ImportFrom)))
                    scalar = self.scalar(base, scope)
                    if not kind:
                        if any(piece.split(':', 1)[0] == param.arg for piece in re.findall(r'\{([^{}]+)\}', route)):
                            kind = 'path'
                        elif len(body_models) == 1:
                            kind = 'body'
                        elif scalar:
                            kind = 'query'
                        else:
                            results.append(Binding(param.arg, 'unresolved_parameter_type'))
                            continue
                    annotation = ast.unparse(param.annotation) if param.annotation else 'unannotated'
                    detail = ast.unparse(default) if default else 'required'
                    fact = (f'FastAPI {scope.file}:{owner.lineno} route {route!r} binds {owner.name}.{param.arg} '
                            f'to client {kind} input; annotation={annotation}; default={detail}. '
                            'Apply the supplied type conversion, validation metadata, guards and later assignments. '
                            'A default is used when absent; it does not prevent a client from supplying an accepted value. '
                            'This binding does not establish that the input reaches or exploits the reported sink.')
                results.append(Binding(param.arg, kind, fact, references))
        return results
