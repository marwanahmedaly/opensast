"""High recall CWE-79 candidates for Python responses and Jinja templates.

These are candidate locations for the verifier, not confirmed findings.
"""
from __future__ import annotations

import ast
import bisect
import hashlib
import os
import re
from pathlib import Path

from aisast.models import Candidate, Location

TEMPLATE_SUFFIXES = {".html", ".htm", ".jinja", ".jinja2", ".j2"}
JAVASCRIPT_SUFFIXES = {".js", ".jsx", ".ts", ".tsx"}
_JINJA_EXPR = re.compile(r"{{\s*(.*?)\s*}}")
_UNSAFE = re.compile(r"\|\s*safe\b|\bMarkup\s*\(")
_AUTOESCAPE_OFF = re.compile(r"{%\s*autoescape\s+(?:false|off)\s*%}", re.I)
_REQUEST_FIELDS = {"args", "form", "values", "cookies", "headers", "json", "data", "query_params", "GET", "POST", "body"}
_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "vendor", "dist", "build", "site-packages", "__pycache__"}


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_name(node.value)}.{node.attr}"
    return ""


def _request_nodes(node: ast.AST) -> list[ast.Attribute]:
    return [item for item in ast.walk(node) if isinstance(item, ast.Attribute) and item.attr in _REQUEST_FIELDS and _name(item.value) == "request"]


def _candidate(repo_sha: str, rule: str, root: Path, path: Path, line: int, source: Location | None = None) -> Candidate:
    file = path.relative_to(root).as_posix()
    sink = Location(file=file, line=line)
    identity = f"{repo_sha}\0{rule}\0{file}\0{line}\0{source.file if source else ''}\0{source.line if source else ''}"
    return Candidate(candidate_id=hashlib.sha256(identity.encode()).hexdigest(), repository_sha=repo_sha,
                     rule_id=rule, cwe=79, title="Potential unescaped HTML response",
                     primary_location=sink, source=source, sink=sink,
                     properties={"engine": "xss-model", "provenance": [{"engine": "xss-model", "rule_id": rule}]},
                     engines=["xss-model"], rules=[rule])


def _python_candidates(root: Path, path: Path, repo_sha: str) -> tuple[list[Candidate], dict[str, Location]]:
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (OSError, UnicodeError, SyntaxError):
        return [], {}
    results: list[Candidate] = []
    templates: dict[str, Location] = {}
    relative = path.relative_to(root).as_posix()
    django_render_names = {alias.asname or alias.name for node in tree.body
                           if isinstance(node, ast.ImportFrom) and node.module == "django.shortcuts"
                           for alias in node.names if alias.name == "render"}
    for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
        nodes = list(ast.walk(function))
        source_nodes = [node for node in nodes if isinstance(node, ast.Attribute) and node.attr in _REQUEST_FIELDS and _name(node.value) == "request"]
        if not source_nodes:
            continue
        source_line = min(node.lineno for node in source_nodes if hasattr(node, "lineno"))
        source_loc = Location(file=relative, line=source_line)
        tainted: set[str] = set()
        assignments = [node for node in nodes if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr))]
        for _ in range(min(8, len(assignments) + 1)):
            previous = len(tainted)
            for node in assignments:
                value = node.value
                if value is None:
                    continue
                if _request_nodes(value) or any(isinstance(child, ast.Name) and child.id in tainted for child in ast.walk(value)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    tainted.update(child.id for target in targets for child in ast.walk(target) if isinstance(child, ast.Name))
            if len(tainted) == previous:
                break
        for node in nodes:
            if isinstance(node, ast.Call) and _name(node.func).endswith("render_template") and node.args:
                template = node.args[0]
                if isinstance(template, ast.Constant) and isinstance(template.value, str):
                    templates.setdefault(template.value, source_loc)
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id in django_render_names and len(node.args) >= 2):
                template = node.args[1]
                if isinstance(template, ast.Constant) and isinstance(template.value, str):
                    templates.setdefault(template.value, source_loc)
            if not isinstance(node, ast.Return) or node.value is None:
                continue
            if (isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                    and node.value.func.id in django_render_names):
                # Django render() autoescapes context values unless the template
                # explicitly disables it; the template scanner handles that case.
                continue
            if _request_nodes(node.value) or any(isinstance(child, ast.Name) and child.id in tainted for child in ast.walk(node.value)):
                # A route return is a response body, including values passed through
                # local helpers and assignments. The verifier resolves actual flow.
                results.append(_candidate(repo_sha, "aisast/python-response-xss", root, path, node.lineno, source_loc))
    return results, templates


_TEMPLATE_TOKEN = re.compile(r"{#.*?#}|{%.*?%}|{{.*?}}|</?script\b[^>]*>", re.I | re.S)
_URI_ATTRIBUTES = {"href", "src", "action", "formaction", "data", "xlink:href"}


def _output_context(text: str, offset: int, script: bool) -> str:
    if script:
        return "javascript"
    # This is a lexical context hint, not an HTML parse or an exploit proof.
    start = text.rfind("<", 0, offset)
    closed = text.rfind(">", 0, offset)
    if start >= 0 and start > closed:
        attribute = re.search(r"([\w:-]+)\s*=\s*([\"']?)([^\"'<>]*)$", text[start:offset])
        if attribute:
            name = attribute[1].lower()
            if name.startswith("on"):
                return "event_attribute"
            if name in _URI_ATTRIBUTES:
                return "uri_attribute"
            if not attribute[2]:
                return "unquoted_attribute"
    return "html"


def _template_candidates(root: Path, path: Path, repo_sha: str,
                         routes: dict[str, list[Location]]) -> list[Candidate]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return []
    line_starts = [0, *(m.end() for m in re.finditer("\n", text))]
    # Mask template syntax once, preserving offsets. Per-expression context
    # lookup then reads only its enclosing tag rather than the entire prefix.
    context_text = re.sub(r"{{.*?}}|{%.*?%}|{#.*?#}",
                          lambda m: "V" + " " * (len(m.group()) - 1), text, flags=re.S)
    result: list[Candidate] = []
    escaping: list[str] = ["on"]
    script = False
    comment_depth = 0
    raw_depth = 0
    filter_blocks: list[bool] = []
    for token in _TEMPLATE_TOKEN.finditer(text):
        value = token.group()
        if value.startswith("{#"):
            continue
        if value.startswith("{%"):
            tag = value[2:-2].strip().strip("-").strip()
            words = tag.split()
            if not words:
                continue
            verb = words[0].lower()
            if verb == "endcomment":
                comment_depth = max(0, comment_depth - 1)
            elif verb == "comment":
                comment_depth += 1
            elif comment_depth:
                continue
            elif verb in {"endraw", "endverbatim"}:
                raw_depth = max(0, raw_depth - 1)
            elif raw_depth:
                continue
            elif verb in {"raw", "verbatim"}:
                raw_depth += 1
            elif verb == "filter":
                filter_blocks.append(bool(re.search(r"(?:^|\|)\s*safe\b", tag[len(words[0]):].strip())))
            elif verb == "endfilter" and filter_blocks:
                filter_blocks.pop()
            elif verb == "autoescape":
                mode = words[1].lower() if len(words) > 1 else "unknown"
                escaping.append("off" if mode in {"off", "false"} else "on" if mode in {"on", "true"} else "unknown")
            elif verb == "endautoescape" and len(escaping) > 1:
                escaping.pop()
            continue
        if comment_depth or raw_depth:
            continue
        if value.lower().startswith("<script"):
            script = True
            continue
        if value.lower().startswith("</script"):
            script = False
            continue
        expression = value[2:-2].removeprefix("-").removeprefix("+").removesuffix("-").removesuffix("+").strip()
        context = _output_context(context_text, token.start(), script)
        reasons: list[str] = []
        if _UNSAFE.search(expression) or any(filter_blocks):
            reasons.append("explicit_safe_output")
        if re.search(r"\bsafe_columns\s*=", expression):
            reasons.append("extension_safe_columns_option")
        if escaping[-1] != "on":
            reasons.append("autoescape_" + escaping[-1])
        if context in {"javascript", "event_attribute", "uri_attribute", "unquoted_attribute"}:
            reasons.append(context)
        if not reasons:
            continue
        line = bisect.bisect_right(line_starts, token.start())
        end_line = bisect.bisect_right(line_starts, token.end() - 1)
        candidate = _candidate(repo_sha, "aisast/template-output-suspect", root, path, line)
        renderer_refs = []
        for name, locations in routes.items():
            if path.as_posix().endswith("/" + name):
                renderer_refs.extend(loc.model_dump(mode="json") for loc in locations)
        candidate.properties.update({
            "suspect_only": True, "expression": expression, "output_context": context,
            "output_reasons": reasons, "end_line": end_line,
            "evidence_locations": renderer_refs,
            "evidence_certainty": "syntactic_possible",
            "flow_proven": False,
        })
        # Keep separate output expressions even on the same line. They may be
        # different fields or different browser execution contexts.
        candidate.candidate_id = hashlib.sha256((candidate.candidate_id + "\0" + str(token.start())).encode()).hexdigest()
        candidate.primary_location.column = token.start() - line_starts[line - 1] + 1
        candidate.sink.column = candidate.primary_location.column
        result.append(candidate)
    return result


def scan_xss_candidates(repository: Path, repository_sha: str = "unknown", *,
                        include_python_responses: bool = True,
                        diagnostics: list[dict] | None = None) -> list[Candidate]:
    """Collect suspects without opening labels, caps, or asserting source flow.

    The default pipeline uses the template companion plus CodeQL Python rules.
    Legacy request/return heuristics remain available through --xss-candidates.
    """
    root = repository.resolve()
    candidates: list[Candidate] = []
    routes: dict[str, list[Location]] = {}
    template_paths: list[Path] = []
    for directory, subdirectories, filenames in os.walk(root):
        subdirectories[:] = sorted(name for name in subdirectories if name not in _SKIP_DIRS
                                  and (Path(directory) / name).resolve().is_relative_to(root))
        for filename in sorted(filenames):
            path = Path(directory) / filename
            if not path.resolve().is_relative_to(root):
                continue
            if path.suffix == ".py":
                try:
                    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
                except (OSError, UnicodeError, SyntaxError) as exc:
                    if diagnostics is not None:
                        diagnostics.append({"file": path.relative_to(root).as_posix(),
                                            "status": "parse_error", "reason": type(exc).__name__,
                                            "line": getattr(exc, "lineno", None)})
                    continue
                # Retain every literal renderer, even one reading stored data
                # or constants. A renderer is an evidence hint, not a source.
                for node in ast.walk(tree):
                    if not isinstance(node, ast.Call):
                        continue
                    leaf = _name(node.func).rsplit(".", 1)[-1]
                    if leaf not in {"render", "render_template", "render_to_string", "render_to_response", "TemplateResponse"}:
                        continue
                    names = [arg.value for arg in node.args if isinstance(arg, ast.Constant) and isinstance(arg.value, str)]
                    names.extend(kw.value.value for kw in node.keywords if kw.arg in {"template_name", "template"} and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str))
                    for name in names:
                        if name.endswith(tuple(TEMPLATE_SUFFIXES)):
                            routes.setdefault(name, []).append(Location(file=path.relative_to(root).as_posix(), line=node.lineno))
                if include_python_responses:
                    found, _ = _python_candidates(root, path, repository_sha)
                    candidates.extend(found)
            elif path.suffix.lower() in TEMPLATE_SUFFIXES:
                template_paths.append(path)
    for path in template_paths:
        found = _template_candidates(root, path, repository_sha, routes)
        candidates.extend(found)
        if diagnostics is not None:
            diagnostics.append({"file": path.relative_to(root).as_posix(), "status": "scanned", "candidates": len(found)})
    return candidates


def client_code_paths(repository: Path) -> list[Path]:
    """Find JavaScript and HTML files with inline client code for CodeQL."""
    found: list[Path] = []
    for directory, subdirectories, filenames in os.walk(repository):
        subdirectories[:] = sorted(name for name in subdirectories if name not in _SKIP_DIRS)
        for filename in filenames:
            path = Path(directory) / filename
            if path.suffix.lower() in JAVASCRIPT_SUFFIXES:
                found.append(path)
            elif path.suffix.lower() in TEMPLATE_SUFFIXES:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if "<script" in text.lower() or re.search(r"\bon[a-z]+\s*=|javascript:", text, re.I):
                    found.append(path)
    return found
