from __future__ import annotations

import ast
import tokenize
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Symbol:
    file: str
    name: str
    start_line: int
    end_line: int
    kind: str


class ASTIndex:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.symbols: list[Symbol] = []
        self._by_name: dict[str, list[Symbol]] = {}
        self.build()

    def build(self) -> None:
        for path in sorted(self.root.rglob("*.py")):
            try:
                with tokenize.open(path) as source:
                    tree = ast.parse(source.read(), filename=str(path))
            except (OSError, SyntaxError, UnicodeError, LookupError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    start = min([node.lineno, *[decorator.lineno for decorator in getattr(node, "decorator_list", [])]])
                    symbol = Symbol(str(path.relative_to(self.root)), node.name, start, getattr(node, "end_lineno", node.lineno), type(node).__name__)
                    self.symbols.append(symbol); self._by_name.setdefault(node.name, []).append(symbol)

    def containing(self, file: str, line: int) -> Symbol | None:
        candidates = [s for s in self.symbols if s.file == file and s.start_line <= line <= s.end_line]
        return min(candidates, key=lambda s: s.end_line - s.start_line, default=None)

    def find(self, name: str) -> list[Symbol]:
        return self._by_name.get(name, [])
