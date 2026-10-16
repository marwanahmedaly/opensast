# Install OpenSAST

These instructions apply to the main OpenSAST repository after the CLI and dashboard components are merged. This component repository is not independently installable.

## 1. Get the integrated source

```bash
git clone https://github.com/marwanahmedaly/opensast.git
cd opensast
```

Repository access is required while the source is private. Git and Python must already be available.

## 2. Start the installer

```bash
bash scripts/install.sh
```

The installer creates an isolated Python environment and starts the setup wizard. It does not require sudo. To use a reviewed release, select its tag or branch with `--ref RELEASE_TAG_OR_BRANCH` when installing remotely. The default `main` follows source updates and is not an immutable release pin.

For remote distribution after the installer is available in the main repository, download and inspect its script before running it. While the repository is private, an authenticated GitHub CLI can retrieve it:

```bash
gh api repos/marwanahmedaly/opensast/contents/scripts/install.sh -H 'Accept: application/vnd.github.raw+json' > install.sh
bash install.sh
```

The command needs repository access. A public raw-download URL will only work once the main repository is public.

## 3. Check requirements and complete setup

Automatic provisioning targets **Linux x86-64**, Python **3.11.8+ or 3.12+**, Python
venv, and Linux `flock`. Online source installation needs Git and access to the
repository/Python package index. The small installer is not a standalone Python
runtime. It reports missing prerequisites rather than silently running privileged
package-manager commands.

The wizard:

1. Reports RAM, available disk and detected NVIDIA GPU memory.
2. Installs or uses CodeQL **2.27.1** and the exact required packs, including
   `codeql/python-queries` **1.8.11** and `codeql/python-all` **7.2.6**.
3. Offers three inference choices:
   - download the pinned local Qwen GGUF;
   - use an existing local GGUF;
   - connect an existing company-internal llama.cpp endpoint.
4. Creates the initial administrator/workspace, with a password supplied privately.
   Existing accounts and project history are preserved.
5. Starts the dashboard and, for local inference, the configured llama-server.
6. Checks model listing, template and tokenizer APIs. These are readiness checks,
   not vulnerability-detection measurements.

The CodeQL Python bundle is about **111 MB**. Setup requires at least **2 GiB**
free for CodeQL provisioning; the CLI installer first requires **256 MiB** for its
Python environment. Actual dependencies, pack extraction and scan databases need
additional space.

The optional default Qwen model is **17,379,990,688 bytes**. Its SHA-256 is:

```text
cf9ea0572e8759348ef7f8cd899fbfecba5110929fc1aa620d18bb6d91e62700
```

The immutable Hugging Face source revision and download hashes are in
`src/aisast/install/manifest.json`.
The installer uses one 16,384-token model slot and a 400-token completion budget.
The 24 GiB memory check for the default model is a provisioning heuristic, not a
universal minimum or a guarantee of usable speed. CPU inference can be slow.

Local runtime downloads pin llama.cpp **b11070**. CPU and NVIDIA CUDA 12.8
variants are provided; the CUDA option also downloads its runtime libraries.
These are upstream Ubuntu binary builds. System-library and GPU-driver
compatibility can still prevent startup on some Linux distributions. An operator
can supply a compatible `--llama-server` binary. Native Windows, ARM64 automatic
provisioning and every Linux/GPU combination are not validated by this work.

Downloads use HTTPS, immutable versions and SHA-256 verification. Interrupted
large downloads retain `.part` files and can resume. Archives are extracted with
Python's `data` filter into staging directories. Only setup downloads tools and
weights; scans continue to use preinstalled local assets.

## 4. Register and scan a project

```bash
cd /path/to/python-project
opensast init
opensast scan
```

On an installation configured by the wizard, `init` provisions a project worker
credential when the user has permission and starts that project's local worker.
The worker uses saved engine settings. `init --no-worker` registers only.
The first newly created administrator is logged into the CLI privately; an
existing installation may require `opensast login --username YOUR_USERNAME`.

The dashboard opens at `http://127.0.0.1:8765`. On a headless host, use an SSH
forward or configure the existing HTTPS reverse-proxy deployment described in
[the product guide](opensast.md). Automatic setup binds the dashboard and local
model to loopback; it does not expose a company service to the public network.
Use `opensast init --no-browser` when no GUI is available.

```bash
opensast doctor     # Report readiness; exit 1 when an engine/API is unavailable
opensast stop       # Stop managed workers/model/dashboard; preserve all data
opensast start      # Start the configured services and remembered workers
opensast restart    # Apply changed application/configuration to managed services
```

These commands manage only recorded user-local processes, checking Linux process
start identity before stopping them. They do not stop independently launched
services. They are not a boot-time service supervisor; after restarting the
machine, run `opensast start` or provision your organization's supervisor.
A failed project-worker startup leaves registration intact and reports the manual
credential/worker steps. Workspace membership and project roles still apply.

Saved settings remove repeated flags from `opensast worker` and `opensast ci`.
Explicit flags override saved settings. `worker --suspect-only` omits the saved
model; its results are unresolved suspects, not verified vulnerabilities. CI still
requires a pinned model revision and explicit project/state/output arguments.
An internal endpoint must expose llama.cpp-compatible `/apply-template` and
`/tokenize` in addition to `/v1/models` and chat completions. An ordinary chat-only
API is insufficient for the existing token-budget integration.

## Existing internal endpoint

Example guided setup using already provisioned tools:

```bash
opensast setup \
  --codeql /opt/codeql/codeql \
  --query-search-path /opt/codeql-packs \
  --endpoint https://inference.company.internal/v1 \
  --allow-model-host inference.company.internal \
  --model YOUR_SERVED_MODEL \
  --model-revision IMMUTABLE_WEIGHT_REVISION
```

The operator must ensure an allowed inference host is internal. The installer
cannot infer a company's network boundary. Code, prompts and inference stay on
that infrastructure; downloads fetch dependencies/model bytes, not repository
uploads. No telemetry or external inference default is added.

## Offline and internal distribution

Build an OpenSAST wheel from this implementation and supply a wheelhouse containing
its runtime dependencies and build requirements when installing from source. Use
an isolated connected build machine to assemble these artifacts before transferring
them into the company network. The wheel contains the selected current queries,
helpers/lock, optional XSS model pack, guided prompt assets and provisioning manifest;
it excludes research reports, corpora, model weights and CodeQL binaries.

```bash
bash install.sh --offline \
  --wheel /internal/packages/evidence_grounded_aisast-0.2.0-py3-none-any.whl \
  --wheelhouse /internal/packages/wheelhouse -- \
  --codeql /internal/codeql/codeql \
  --query-search-path /internal/codeql-packs \
  --gguf /internal/models/qwen.gguf \
  --llama-server /internal/llama/llama-server \
  --backend cpu
```

Alternatively place the exact pinned archives in `OPENSAST_HOME/downloads`, the
model in `OPENSAST_HOME/models`, and installed packs in `OPENSAST_HOME/tools/packs`.
Offline setup may extract these checksum-matching archives but never fetches missing
ones. Missing packs/files produce an explicit error.

For an internal HTTPS artifact mirror, set `OPENSAST_DOWNLOAD_MIRROR` to the base
URL containing the manifest's filenames. Hashes remain pinned and are still
verified. Use `OPENSAST_REPOSITORY` for an internal source mirror and normal pip
index configuration for a company Python index. URLs must not embed credentials.

For unattended provisioning, add `--non-interactive --yes`, select the model/tools
explicitly, and provide `--password-file /private/initial-password` on the first
setup. The password is not a command-line value or logged. Protect the file using
company policy. No default password is supplied. `--no-start` provisions configuration
and the initial account without launching services.

## Storage, updates and debugging

Application environments default to `~/.local/share/opensast-app`; the command is
linked into `~/.local/bin`. If needed, the installer adds a marked PATH line to
`.profile` and `.bashrc`; open a new terminal to use it. `--prefix` and `--bin-dir`
customize these locations. Existing non-installer `opensast` executables are preserved
by refusing to overwrite them; choose another bin directory.

Data defaults to `~/.local/share/opensast` or `OPENSAST_HOME`. It stays separate
from Python environments and registered source repositories. Reinstalling creates
a fresh environment and promotes it only after package installation succeeds.
Old environments and the `previous` symlink are retained for rollback; no automatic
cleanup removes projects, models or scan history. Setup failures are reported and
can be retried. Existing processes continue using their original environment until
`opensast restart`; rerunning setup does not reset accounts. Use `setup --reconfigure`
to change engine choices.

Installation events and CodeQL provisioning output are under `OPENSAST_HOME/logs`.
Managed service output/process records are under `OPENSAST_HOME/services`.
Saved engine defaults are `OPENSAST_HOME/installation.json`; credentials remain in
private client/worker directories. Logs do not record bootstrap passwords or tokens.
Ordinary scan evidence retains its existing worker-side logging.

## Primary references

- [CodeQL CLI use and availability](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli)
- [CodeQL pack download](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli-manual/pack-download)
- [CodeQL terms](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md)
- [llama.cpp b11070 binaries](https://github.com/ggml-org/llama.cpp/releases/tag/b11070)

CodeQL's terms still govern use; installing it does not grant additional rights for
private/proprietary analysis. The company must have applicable authorization for
its use. OpenSAST does not redistribute CodeQL or model weights inside its wheel.
