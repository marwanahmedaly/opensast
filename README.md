# OpenSAST

OpenSAST is a local-first, AI-assisted static application security testing (SAST) tool for Python. CodeQL identifies suspected findings, a Python context collector assembles referenced code evidence, and an LLM verifier reviews that evidence.

## Scope

- CWE-22: path traversal
- CWE-78: OS command injection
- CWE-79: cross-site scripting
- CWE-89: SQL injection

Findings require review. The tool does not guarantee complete detection or coverage of the entire OWASP Top 10. Source code and inference can remain on your own infrastructure.

## Source integration status

The scanner core is available here. The product CLI, installer, dashboard and GitHub Action are being integrated through separate component PRs. Until those merge, use the `aisast` core command below; `opensast` product commands are not available in this checkout. The shared package metadata already declares the product entry point for that integration.

## Install the core

Use Python 3.11 or newer and an isolated environment:

```bash
git clone https://github.com/marwanahmedaly/opensast.git
cd opensast
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
aisast --help
```

Repository access is required while this repository is private. Full scanning requires a separate CodeQL installation, preinstalled compatible query packs, and a local or company-hosted OpenAI-compatible inference service. Neither model weights nor CodeQL binaries are included.

See [Scanning](docs/scanning.md), [Architecture](docs/architecture.md), [Configuration](docs/configuration.md), and [Contributing](CONTRIBUTING.md).

## Third-party assets

Bundled guided prompt assets retain their original LGPL-2.1 license and attribution under `src/aisast/verifier/assets/`. CodeQL binaries, query packs and model weights have their own licenses and are obtained separately. The project does not currently declare a license for the original OpenSAST code; do not infer one from the bundled asset license.
