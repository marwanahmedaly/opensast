"""Conservative change planning: extra work is preferable to stale results."""
from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import stat
import tempfile
from pathlib import Path

EXCLUDED = {".git", ".opensast", ".venv", "venv", "env", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "node_modules"}


def file_hash(path: Path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def inventory(root: Path):
    files = {}
    for directory, children, names in os.walk(root, followlinks=False):
        parent = Path(directory)
        children[:] = sorted(n for n in children if n not in EXCLUDED and not (parent / n).is_symlink())
        for name in sorted(names):
            path = parent / name
            if path.is_symlink() or not path.is_file():
                continue
            if name.endswith((".pyc", ".pyo")):
                continue
            files[path.relative_to(root).as_posix()] = file_hash(path)
    return files


def identity(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def atomic_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def snapshot(root: Path, destination: Path, files):
    destination.mkdir(parents=True, exist_ok=False)
    for relative, expected in files.items():
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        # Resolve each component through a directory fd; reject symlink replacement
        # even if it happens between inventory and copying.
        directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            parts = Path(relative).parts
            for component in parts[:-1]:
                child_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = child_fd
            source_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
            with os.fdopen(source_fd, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise RuntimeError("Checkout path is no longer a regular file: " + relative)
                with target.open("wb") as output:
                    shutil.copyfileobj(stream, output)
        finally:
            os.close(directory_fd)
        if file_hash(target) != expected:
            raise RuntimeError("Checkout changed while snapshotting: " + relative)
    if inventory(root) != files:
        raise RuntimeError("Checkout changed during snapshot creation; queue another scan")


def module_name(relative):
    parts = list(Path(relative).with_suffix("").parts)
    if parts and parts[0] == "src":
        parts = parts[1:]
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def relationships(root: Path, files):
    modules = {}
    reasons = []
    for name in files:
        if name.endswith(".py"):
            mod = module_name(name)
            if mod in modules:
                reasons.append("ambiguous Python module: " + mod)
            modules[mod] = name
    graph = {name: set() for name in modules.values()}
    for mod, name in modules.items():
        try:
            tree = ast.parse((root / name).read_text(encoding="utf-8-sig"))
        except (SyntaxError, UnicodeError, OSError):
            reasons.append("unparsed Python file: " + name)
            continue
        package = mod if Path(name).name == "__init__.py" else mod.rpartition(".")[0]
        for node in ast.walk(tree):
            imports = []
            if isinstance(node, ast.Import):
                imports = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ""
                if node.level:
                    parts = package.split(".") if package else []
                    if node.level > len(parts):
                        reasons.append("unresolved relative import: " + name)
                        continue
                    base = ".".join(parts[:len(parts) - node.level + 1] + ([base] if base else []))
                imports = [base] + [base + "." + alias.name for alias in node.names if alias.name != "*"]
            elif isinstance(node, ast.Call):
                fn = node.func
                if (isinstance(fn, ast.Name) and fn.id in {"__import__", "exec", "eval"}) or (isinstance(fn, ast.Attribute) and fn.attr in {"import_module", "load_module", "exec_module"}):
                    reasons.append("dynamic execution/import: " + name)
            for target in imports:
                pieces = target.split(".")
                for index in range(1, len(pieces) + 1):
                    prefix = ".".join(pieces[:index])
                    if prefix in modules:
                        graph[name].add(modules[prefix])
    return {name: sorted(deps) for name, deps in graph.items()}, sorted(set(reasons))


def plan(files, previous, graph, reasons, full=False):
    old_files = previous.get("files", {}) if previous else {}
    changed = sorted(name for name in set(files) | set(old_files) if files.get(name) != old_files.get(name))
    fallback = list(reasons)
    if not previous:
        fallback.append("first successful scan")
    if full:
        fallback.append("full scan requested")
    if any(not name.endswith(".py") for name in changed):
        fallback.append("template, dependency, configuration or other non-Python file changed")
    old_graph = previous.get("graph", {}) if previous else {}
    if previous and changed:
        fallback.extend(previous.get("graph_reasons", []))
    affected = set(changed)
    reverse = {}
    for mapping in (old_graph, graph):
        for consumer, producers in mapping.items():
            for producer in producers:
                reverse.setdefault(producer, set()).add(consumer)
    pending = list(affected)
    while pending:
        for consumer in reverse.get(pending.pop(), set()):
            if consumer not in affected:
                affected.add(consumer)
                pending.append(consumer)
    if fallback and changed or full or not previous:
        affected = set(files) | set(old_files)
    return {"changed_files": changed, "affected_files": sorted(affected), "fallback_reasons": sorted(set(fallback)),
            "mode": "full" if (full or not previous or (fallback and changed)) else "incremental",
            "excluded_directory_names": sorted(EXCLUDED)}
