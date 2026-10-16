"""Deterministic, atomic serialization helpers for corpus artifacts."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Iterable


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_json(value: Any) -> str:
    return digest_bytes(canonical_json(value))


def digest_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def stable_id(*parts: Any) -> str:
    return digest_json(list(parts))


def jsonable(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "dict"):
        return value.dict()
    return value


def atomic_write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def atomic_write_json(path: Path, value: Any) -> None:
    content = json.dumps(
        jsonable(value), ensure_ascii=False, indent=2, sort_keys=True
    ) + "\n"
    atomic_write_bytes(path, content.encode("utf-8"))


def atomic_write_jsonl(path: Path, values: Iterable[Any]) -> None:
    """Atomically write JSONL without holding the full file in memory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            for value in values:
                line = json.dumps(
                    jsonable(value), ensure_ascii=False, sort_keys=True
                ) + "\n"
                stream.write(line.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def append_jsonl(path: Path, value: Any) -> None:
    """Durably append one JSONL event before returning to the caller."""
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(
        jsonable(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8") + b"\n"
    with path.open("ab") as stream:
        stream.write(line)
        stream.flush()
        os.fsync(stream.fileno())


def read_jsonl_journal(path: Path, *, repair_partial_tail: bool = False) -> list[dict[str, Any]]:
    """Read an append-only JSONL journal, optionally dropping a torn final line.

    Only a non-newline-terminated final fragment is repairable. Any malformed
    complete line remains a hard integrity error.
    """
    if not path.exists():
        return []
    content = path.read_bytes()
    if content and not content.endswith(b"\n"):
        if not repair_partial_tail:
            raise ValueError(f"JSONL journal has a partial final row: {path}")
        boundary = content.rfind(b"\n") + 1
        with path.open("r+b") as stream:
            stream.truncate(boundary)
            stream.flush()
            os.fsync(stream.fileno())
        content = content[:boundary]
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(content.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid journal JSON at {path}:{number}: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"journal row must be an object at {path}:{number}")
        rows.append(value)
    return rows


def iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    """Yield JSONL objects one row at a time without holding the file in memory."""
    if not path.exists():
        return
    # Iterate by physical newline bytes. str.splitlines() also splits on
    # Unicode U+2028/U+2029, which are legal characters inside JSON strings.
    with path.open("r", encoding="utf-8", newline="") as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at {path}:{number}: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"JSONL row must be an object at {path}:{number}")
            yield value


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return list(iter_jsonl(path))
