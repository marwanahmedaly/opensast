from __future__ import annotations

import platform
import shutil
import subprocess
from pathlib import Path


def tool_version(executable: str, *args: str) -> str | None:
    if not shutil.which(executable):
        return None
    result = subprocess.run([executable, *args], text=True, capture_output=True, check=False)
    if result.returncode:
        return None
    return (result.stdout.strip() or result.stderr.strip()).splitlines()[0] if (result.stdout.strip() or result.stderr.strip()) else "unknown"


def environment_report() -> dict[str, object]:
    tools = {
        "codeql": tool_version("codeql", "version"),
        "semgrep": tool_version("semgrep", "--version"),
        "opengrep": tool_version("opengrep", "--version"),
    }
    return {"os": platform.platform(), "python": platform.python_version(), "tools": tools, "available": [name for name, version in tools.items() if version]}


def write_environment_versions(output: Path) -> dict[str, object]:
    report = environment_report()
    output.mkdir(parents=True, exist_ok=True)
    (output / "python.txt").write_text(f"{report['python']}\n")
    (output / "os.txt").write_text(f"{report['os']}\n")
    for name, version in report["tools"].items():
        (output / f"{name}.txt").write_text(f"{version or 'unavailable'}\n")
    return report
