from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


class ScannerError(RuntimeError):
    """Raised when a scanner is unavailable or exits unsuccessfully."""


class _SarifRunner:
    name = "scanner"

    def __init__(self, executable: str | None = None) -> None:
        self.executable = executable or self.name

    def version(self) -> str:
        self._check()
        result = subprocess.run([self.executable, "--version"], text=True, capture_output=True, check=False)
        if result.returncode:
            raise ScannerError(result.stderr.strip() or f"{self.name} version failed")
        return result.stdout.strip()

    def scan(self, repository: Path, output: Path, config: str = "p/python") -> Path:
        self._check()
        output.parent.mkdir(parents=True, exist_ok=True)
        command = self._command(repository, output, config)
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        if result.returncode:
            detail = result.stderr.strip() or result.stdout.strip() or "scanner failed"
            raise ScannerError(f"{self.name}: {detail}")
        if not output.exists():
            raise ScannerError(f"{self.name} did not produce {output}")
        return output

    def _check(self) -> None:
        if not shutil.which(self.executable):
            raise ScannerError(f"{self.name} CLI was not found on PATH: {self.executable}")

    def _command(self, repository: Path, output: Path, config: str) -> list[str]:
        raise NotImplementedError


class SemgrepRunner(_SarifRunner):
    name = "semgrep"

    def _command(self, repository: Path, output: Path, config: str) -> list[str]:
        command = [self.executable, "scan", "--config", config]
        if Path(config).is_file():
            command.append("--no-rewrite-rule-ids")
        return [*command, "--sarif", "--output", str(output), str(repository)]


class OpenGrepRunner(_SarifRunner):
    name = "opengrep"

    def _command(self, repository: Path, output: Path, config: str) -> list[str]:
        command = [self.executable, "scan", "--config", config]
        if Path(config).is_file():
            command.append("--no-rewrite-rule-ids")
        return [*command, "--sarif", "--output", str(output), str(repository)]
