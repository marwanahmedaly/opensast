from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import uuid
from pathlib import Path
import yaml


class CodeQLError(RuntimeError):
    pass


class CodeQLRunner:
    def __init__(self, executable: str = "codeql", log_dir: Path | None = None) -> None:
        self.executable = executable
        self.log_dir = log_dir

    def version(self) -> str:
        if not shutil.which(self.executable):
            raise CodeQLError("CodeQL CLI was not found on PATH")
        result = subprocess.run([self.executable, "version"], text=True, capture_output=True, check=False)
        if result.returncode:
            raise CodeQLError(result.stderr.strip() or "CodeQL version failed")
        return result.stdout.strip()

    def create_database(self, repository: Path, database: Path, language: str = "python") -> None:
        if language not in {"python", "javascript"}:
            raise ValueError(f"unsupported CodeQL language: {language}")
        self._run(["database", "create", str(database), f"--language={language}", "--build-mode=none", f"--source-root={repository}"])

    def _locked_suite_dependency_packs(self, suite: str, search_path: Path | None) -> list[Path]:
        """Resolve a local query pack's locked dependencies to exact installed pack roots."""
        if not search_path:
            return []
        suite_path = Path(suite)
        if not suite_path.is_file():
            return []
        pack_dir = next(
            (parent for parent in (suite_path.parent, *suite_path.parents)
             if (parent / "codeql-pack.lock.yml").is_file()),
            None,
        )
        if pack_dir is None:
            return []
        lock = yaml.safe_load((pack_dir / "codeql-pack.lock.yml").read_text()) or {}
        roots: list[Path] = []
        search_roots = [Path(part) for part in str(search_path).split(os.pathsep) if part]
        for name, metadata in (lock.get("dependencies") or {}).items():
            version = metadata.get("version") if isinstance(metadata, dict) else None
            if not version:
                continue
            for root in search_roots:
                candidate = root / name / version
                if (candidate / "qlpack.yml").is_file():
                    roots.append(candidate)
                    break
        return list(dict.fromkeys(roots))

    def analyze(self, database: Path, output: Path, suite: str = "codeql/python-queries:codeql-suites/python-security-extended.qls", max_paths: int = 4, search_path: Path | None = None, model_packs: list[Path] | None = None, *, no_database_extension_packs: bool = False) -> None:
        output.parent.mkdir(parents=True, exist_ok=True)
        # Model-on/off ablations may query the same immutable database with
        # different extension packs. CodeQL caches BQRS results by query and
        # can otherwise reuse the stock result in the modeled arm.
        args = ["database", "analyze", str(database), suite, "--format=sarifv2.1.0", f"--output={output}", "--sarif-add-snippets", f"--max-paths={max_paths}", "--rerun"]
        if no_database_extension_packs:
            args.append("--no-database-extension-packs")
        if search_path:
            # Installed versioned dependencies belong on the ordinary search
            # path. Treating them as additional packs makes multiple installed
            # versions of codeql/python-all ambiguous during query resolution.
            args.append(f"--search-path={search_path}")
            # CodeQL ignores --search-path for dependencies of modern query
            # packs. Add only the exact versions pinned by a local suite pack's
            # lock file so multiple installed versions remain unambiguous.
            dependency_packs = self._locked_suite_dependency_packs(str(suite), search_path)
            if dependency_packs:
                args.append(f"--additional-packs={os.pathsep.join(map(str, dependency_packs))}")
        for pack in model_packs or []:
            args.append(f"--additional-packs={pack.parent}")
            args.append(f"--model-packs={yaml.safe_load((pack / 'qlpack.yml').read_text())['name']}")
        if not search_path:
            args.append("--download")
        self._run(args)

    def scan(self, repository: Path, workdir: Path, suite: str, max_paths: int = 4, search_path: Path | None = None, language: str = "python", model_packs: list[Path] | None = None, *, no_database_extension_packs: bool = False) -> Path:
        workdir.mkdir(parents=True, exist_ok=True)
        database = workdir / "codeql-db"
        sarif = workdir / "codeql.sarif"
        self.create_database(repository, database, language)
        self.analyze(database, sarif, suite, max_paths, search_path, model_packs,
                     no_database_extension_packs=no_database_extension_packs)
        return sarif

    def _run(self, args: list[str]) -> None:
        if not shutil.which(self.executable):
            raise CodeQLError("CodeQL CLI was not found on PATH")
        command = [self.executable, *args]
        started = time.monotonic()
        prefix = None
        if self.log_dir is not None:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            prefix = self.log_dir / uuid.uuid4().hex
            prefix.with_suffix(".command.json").write_text(json.dumps(command, indent=2) + "\n")
        try:
            result = subprocess.run(command, text=True, capture_output=True, check=False)
        except OSError as exc:
            if prefix:
                prefix.with_suffix(".result.json").write_text(json.dumps({"error":str(exc), "elapsed_seconds":time.monotonic()-started}) + "\n")
            raise
        if prefix:
            prefix.with_suffix(".stdout.log").write_text(result.stdout)
            prefix.with_suffix(".stderr.log").write_text(result.stderr)
            prefix.with_suffix(".result.json").write_text(json.dumps({"returncode":result.returncode, "elapsed_seconds":time.monotonic()-started}) + "\n")
        if result.returncode:
            raise CodeQLError(result.stderr.strip() or json.dumps(args))
