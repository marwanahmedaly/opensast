"""Prove one narrow SQLite quoted-identifier escaping pattern at a sink."""
from __future__ import annotations

import ast
from pathlib import Path


def _same_block_prefix(tree: ast.Module, statement: ast.stmt) -> list[ast.stmt]:
    for node in ast.walk(tree):
        for _, value in ast.iter_fields(node):
            if isinstance(value, list) and statement in value:
                index = value.index(statement)
                return [item for item in value[:index] if isinstance(item, ast.stmt)]
    return []


def _lexical_prefix(tree: ast.Module, statement: ast.stmt) -> list[ast.stmt]:
    """Collect prior statements in enclosing blocks, outermost first."""
    parents = {child: parent for parent in ast.walk(tree)
               for child in ast.iter_child_nodes(parent)}
    groups: list[list[ast.stmt]] = []
    current: ast.AST = statement
    while current in parents:
        parent = parents[current]
        for _, value in ast.iter_fields(parent):
            if isinstance(value, list) and current in value:
                groups.append([item for item in value[:value.index(current)]
                               if isinstance(item, ast.stmt)])
                break
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            break
        current = parent
    return [statement for group in reversed(groups) for statement in group]


def _quote_double_assignment(statement: ast.stmt, name: str) -> bool:
    if not isinstance(statement, ast.Assign):
        return False
    if not any(isinstance(target, ast.Name) and target.id == name for target in statement.targets):
        return False
    value = statement.value
    return (isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute) and
            value.func.attr == "replace" and len(value.args) == 2 and
            all(isinstance(item, ast.Constant) for item in value.args) and
            value.args[0].value == '"' and value.args[1].value == '""')


def _writes_name(statement: ast.stmt, name: str) -> bool:
    for node in ast.walk(statement):
        if isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Store):
            return True
    return False


def _sqlite_cursor_for_call(tree: ast.Module, call: ast.Call, preceding: list[ast.stmt]) -> bool:
    """Require the sink receiver to come from a sqlite3 connection in this block."""
    if not isinstance(call.func, ast.Attribute) or not isinstance(call.func.value, ast.Name):
        return False
    cursor_name = call.func.value.id
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    owner = call
    while owner in parents and not isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
        owner = parents[owner]
    if not isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    sqlite_aliases: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            sqlite_aliases.update(alias.asname or alias.name for alias in node.names
                                  if alias.name == "sqlite3")
    sqlite_aliases = {name for name in sqlite_aliases
                      if not any(_writes_name(statement, name) for statement in owner.body)}
    def connection(expr: ast.expr, seen: frozenset[str] = frozenset()) -> bool:
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
            if (expr.func.attr == "connect" and isinstance(expr.func.value, ast.Name) and
                    expr.func.value.id in sqlite_aliases):
                return True
        if isinstance(expr, ast.Name):
            if expr.id in seen:
                return False
            definitions = [item for item in preceding
                           if _writes_name(item, expr.id)]
            return bool(definitions and isinstance(definitions[-1], ast.Assign) and
                        connection(definitions[-1].value, seen | {expr.id}))
        return False

    cursor_definitions = [item for item in preceding
                          if _writes_name(item, cursor_name)]
    if not cursor_definitions or not isinstance(cursor_definitions[-1], ast.Assign):
        return False
    cursor_value = cursor_definitions[-1].value
    return (isinstance(cursor_value, ast.Call) and
            isinstance(cursor_value.func, ast.Attribute) and
            cursor_value.func.attr == "cursor" and connection(cursor_value.func.value))


def prove_quoted_sqlite_identifier(repository: Path, file: str, sink_line: int) -> dict | None:
    """Return evidence only when every f-string value is quote-doubled in one block.

    The assignment and SQL call must be sequential statements in the same
    block. The proof does not apply to string values, other SQL dialects,
    unquoted substitutions, or sanitizers conditionally assigned elsewhere.
    """
    path = repository / file
    if not path.is_file():
        return None
    try:
        tree = ast.parse(path.read_text(errors="replace"))
    except SyntaxError:
        return None
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call) and
                 node.lineno == sink_line and isinstance(node.func, ast.Attribute) and
                 node.func.attr in {"execute", "executemany"} and node.args):
        query = call.args[0]
        if not isinstance(query, ast.JoinedStr):
            continue
        parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        statement: ast.AST = call
        while statement in parents and not isinstance(statement, ast.stmt):
            statement = parents[statement]
        if not isinstance(statement, ast.stmt):
            continue
        preceding = _same_block_prefix(tree, statement)
        if not preceding or not _sqlite_cursor_for_call(
                tree, call, _lexical_prefix(tree, statement)):
            continue
        values = query.values
        assignments = []
        proved = True
        for index, value in enumerate(values):
            if not isinstance(value, ast.FormattedValue):
                continue
            if (not isinstance(value.value, ast.Name) or value.conversion != -1 or
                    value.format_spec is not None or index == 0 or
                    index == len(values) - 1 or
                    not isinstance(values[index - 1], ast.Constant) or
                    not isinstance(values[index + 1], ast.Constant) or
                    not isinstance(values[index - 1].value, str) or
                    not isinstance(values[index + 1].value, str) or
                    not values[index - 1].value.endswith('"') or
                    not values[index + 1].value.startswith('"')):
                proved = False
                break
            name = value.value.id
            definitions = [(offset, item) for offset, item in enumerate(preceding)
                           if _writes_name(item, name)]
            if not definitions:
                proved = False
                break
            offset, latest = definitions[-1]
            if not _quote_double_assignment(latest, name):
                proved = False
                break
            assignments.append(latest.lineno)
        if proved and assignments:
            return {"file": file, "sink_line": sink_line,
                    "sanitizer_lines": sorted(set(assignments)),
                    "reason": "Every dynamic SQL identifier is double quoted and its embedded double quotes are doubled before use."}
    return None
