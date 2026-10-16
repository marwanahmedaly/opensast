"""Git metadata supplements file hashes; it never narrows CodeQL's scope."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path, PurePosixPath

from .incremental import EXCLUDED


def git(root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True)
    if result.returncode:
        raise RuntimeError("Git operation failed: " + result.stderr.decode(errors="replace").strip())
    return result.stdout


def revision(root: Path, ref: str) -> str:
    return git(root, "rev-parse", "--verify", "--end-of-options", ref + "^{commit}").decode().strip()


def changes(root: Path, base: str | None = None) -> dict:
    top = Path(git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    if root.resolve() != top:
        raise RuntimeError("Run Git-aware scans from the repository root")
    head = revision(root, "HEAD")
    comparison = revision(root, base) if base else head
    merge_base = git(root, "merge-base", comparison, head).decode().strip()
    # Diff against the working tree includes staged and unstaged modifications.
    paths = git(root, "diff", "--no-ext-diff", "--no-textconv", "--name-only", "-z", merge_base, "--").split(b"\0")
    untracked = git(root, "ls-files", "--others", "--exclude-standard", "-z").split(b"\0")
    return {"head": head, "requested_base": comparison if base else None,
            "merge_base": merge_base, "comparison": "merge-base to working tree",
            "changed_files": sorted({p.decode(errors="surrogateescape") for p in paths + untracked if p}),
            "untracked_files": sorted(p.decode(errors="surrogateescape") for p in untracked if p),
            "ignored_files": "not listed by Git; scanner file inventory remains authoritative"}


def working_tree_metadata(root: Path):
    if not (root / ".git").exists():
        return None
    try:
        return changes(root)
    except RuntimeError as exc:
        # Git is optional for dashboard scanning, e.g. a newly initialized repo
        # with no first commit. Hash-based scanning continues normally.
        return {"available": False, "reason": str(exc)}


def export_revision(root: Path, commit: str, destination: Path):
    # Submodule sources are not in a superproject archive. Do not claim a complete
    # baseline comparison while silently dropping them.
    tree = git(root, "ls-tree", "-r", "-z", commit).split(b"\0")
    if any(line.startswith(b"160000 ") for line in tree):
        raise RuntimeError("Git baseline comparison does not yet support submodules")
    destination.mkdir(parents=True, exist_ok=False)
    # Read tree blobs directly: git archive would respect export-ignore and could
    # silently remove source files. No checkout hooks, filters, or project code run.
    process = subprocess.Popen(["git", "-C", str(root), "cat-file", "--batch"],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        for entry in tree:
            if not entry:
                continue
            metadata, name = entry.split(b"\t", 1)
            mode, kind, oid = metadata.split()
            if kind != b"blob" or mode == b"120000":
                continue
            path = PurePosixPath(name.decode(errors="surrogateescape"))
            if path.is_absolute() or ".." in path.parts:
                raise RuntimeError("Unsafe path in Git tree")
            if any(part in EXCLUDED for part in path.parts) or path.suffix in {".pyc", ".pyo"}:
                continue
            target = destination.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            process.stdin.write(oid + b"\n")
            process.stdin.flush()
            header = process.stdout.readline().split()
            if len(header) != 3 or header[1] != b"blob":
                raise RuntimeError("Cannot read Git baseline blob")
            remaining = int(header[2])
            with target.open("wb") as output:
                while remaining:
                    chunk = process.stdout.read(min(remaining, 1024 * 1024))
                    if not chunk:
                        raise RuntimeError("Incomplete Git baseline blob")
                    output.write(chunk)
                    remaining -= len(chunk)
            if process.stdout.read(1) != b"\n":
                raise RuntimeError("Invalid Git blob separator")
        process.stdin.close()
        if process.wait():
            raise RuntimeError("Git baseline export failed")
    except BaseException:
        shutil.rmtree(destination)
        raise
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()
        if not process.stdin.closed:
            process.stdin.close()
