# OpenSAST: local CLI and dashboard

These instructions apply after the dashboard and CLI components are merged into the main OpenSAST repository.

Git-aware local/PR scans and the company-runner Actions integration are described
in [GitHub Actions](github-actions.md). Use `opensast ci` for a standalone pipeline
scan; normal dashboard workers also record Git changes when a checkout has Git metadata.

## What is implemented

- The `opensast` product CLI and `aisast` scanner CLI.
- A self-hosted HTTP API and browser dashboard with locally packaged assets.
- Password login/logout/change, expiring/revocable sessions, HttpOnly browser cookies, CSRF/origin/host checks and login throttling.
- Workspaces, admin/member/viewer membership, authorized project registration, project-scoped worker credentials.
- Durable scan queue, atomic job claim, progress/heartbeats, cancellation, failed lease handling, history and audit log.
- Finding evidence, verdict filtering, persistent review state/notes and JSON export.
- Immutable checkout snapshots, file hashes, import-based affected-file planning, configuration/template invalidation, exact verifier-decision caching, full-scan override and unchanged-result reuse.
- Current stock CodeQL + current custom query profile + template companion + current ContextBuilder + VerificationPipeline. No detector/context/prompt changes for this product work.

## Guided installation

From a checkout containing the new installer:

```bash
bash scripts/install.sh
```

The wizard packages the current query assets, provisions pinned CodeQL/Python
packs, offers local GGUF or internal inference, creates the first account and
starts the dashboard. `opensast init` can then provision and start a project
worker from saved settings. Use `opensast doctor`, `start`, `stop` and `restart`
for the managed installation. Repository access is required while the main source remains private.

See [the installation guide](installation.md) for requirements, hashes, offline
installation, mirrors, upgrade/rollback behavior and publication status.

## Manual installation from the source checkout

Python 3.11+ and a Linux/macOS worker host are required; the worker uses POSIX process groups and directory descriptors. Native Windows workers are not implemented. The package bundles the selected query profile/helpers/lock and prompt assets; CodeQL binaries, stock packs and model weights are provisioned separately. Manual setup below remains available.

```bash
git clone https://github.com/marwanahmedaly/opensast.git
cd opensast
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[web]"
opensast bootstrap --username admin --workspace "My team"
opensast serve
```

Bootstrap prompts for a password; it never accepts a default password. It only works on an empty installation. Open `http://127.0.0.1:8765` in the browser. Initial accounts are provisioned on the backend machine; there is no public signup.

Use the same `--data /private/path` for bootstrap and serve if customizing storage. `OPENSAST_HOME` changes the default product storage root. It defaults to `~/.local/share/opensast`, separate from registered repositories.

Guided prompt assets are bundled with their third-party license and attribution. CodeQL binaries, query packs and inference weights are separate dependencies. Recursive submodule initialization is not required. Prompt-asset hashes contribute to the verifier cache identity.

## Register a checkout

```bash
opensast login --server http://127.0.0.1:8765 --username admin
cd /path/to/python-project
opensast init
opensast worker-token
```

`init` registers the project and opens the dashboard. It does not start a scan. With saved guided-installation settings, it can provision and start a local project worker; `--no-worker` skips that step. Without saved settings, use the manual worker steps below. If multiple workspaces are available, it displays a numbered list and accepts its number, name, or ID. `--workspace "Personal"` or `--workspace WORKSPACE_ID` avoids the prompt. Duplicate names require a displayed number or exact ID. Workspace admins can create projects. A member can connect an existing project using `opensast init --project PROJECT_ID`.

The repository contains only `.opensast/config.json` (backend URL/project ID), plus ignore rules. User and worker tokens are stored in private files outside the checkout. Existing registrations are reused rather than creating another project.

## Start the local project worker

All CodeQL packs and model weights/inference must be provisioned before scanning, manually or through the new setup wizard. Scanning does not download them or add telemetry. Guided installations save these flags so `opensast worker` can use them automatically.

```bash
opensast worker \
  --codeql /path/to/codeql/codeql \
  --query-search-path /path/to/installed/codeql/packages \
  --endpoint http://127.0.0.1:8000/v1 \
  --model YOUR_LOCAL_MODEL_NAME \
  --model-revision SHA256_OF_MODEL_WEIGHTS
```

The worker runs in the foreground. Keep it running in another terminal or supervise it as a company service. `--once` handles one queued job and exits; if nothing is queued, it exits immediately. One worker process can serve a project on this machine. Different projects have independent worker state and credentials.

Non-loopback inference requires an explicit internal hostname allowlist:

```bash
opensast worker \
  --query-search-path /path/to/installed/codeql/packages \
  --endpoint https://inference.company.internal/v1 \
  --allow-model-host inference.company.internal \
  --model YOUR_LOCAL_MODEL_NAME \
  --model-revision SHA256_OF_MODEL_WEIGHTS
```

The operator is responsible for identifying company-internal hosts; the allowlist does not infer the organization's network boundaries. Internal firewall/egress policy must prevent external model traffic. The current token budgeting uses the inference server's llama.cpp-compatible `/apply-template` and `/tokenize` endpoints; generic chat-only servers need a separate budget integration.

The default budget is 16,384 context tokens and 400 output tokens. Without a pinned `--model-revision`, LLM decision/result caching is disabled. Changing the actual weights while retaining the same claimed revision is unsupported: the operator must update the digest/revision. Start the worker without both `--endpoint` and `--model` for detector-only runs; their verdicts remain UNRESOLVED and are not claimed as verified vulnerabilities.

## Run and review scans

From the registered checkout:

```bash
opensast scan
opensast status
opensast scan --full
opensast status --job JOB_ID
opensast findings JOB_ID
opensast review JOB_ID FINDING_ID confirmed --note "Reviewed evidence"
opensast export JOB_ID --output /private/path/results.json
opensast cancel JOB_ID
opensast dashboard
```

`scan --wait` waits for a terminal state; it does not launch a worker. Dashboard scans use the same queue. Offline workers leave scans queued, with the last worker contact visible. A project permits one queued/running scan at a time.

All candidates are retained; there is no 60-API or other candidate-count cap. `VULNERABLE` is the verifier's finding, `NOT_VULNERABLE` its rejection, and UNRESOLVED/SYSTEM_ERROR remain separate. Human triage never changes the saved model verdict.

The dashboard provides the same API actions: workspaces, membership, projects, worker-token rotation, incremental/full scans, status, cancellation, results, review, exports and audit. Bootstrap, filesystem registration, and launching the worker are local CLI operations.

## Incremental behavior and current limits

The first successful scan creates a full baseline. Later scans compare content hashes, including untracked regular files. Added/deleted/renamed files are handled (renames as delete/add). Imports in old and new snapshots identify affected consumers. Changed templates, dependency/configuration files, unresolved relative imports, parse failures and dynamic imports/execution cause broader invalidation.

**CodeQL still extracts and queries the full snapshot on changed scans. Context packets are also built fresh.** Incremental savings currently come from skipping unchanged scans and avoiding repeat LLM verification for exact unchanged, unaffected evidence. This preserves cross-file flow analysis. We do not claim changed-files-only execution in every stage or a measured speedup yet.

The importer is conservative and syntactic; it is not a proof of Python's complete runtime dependency graph. Current packet equality is checked in addition to dependency invalidation. Context-expanded, unresolved and failed model decisions are not cached. Configuration/code/query/model identity changes invalidate reuse. Hashing installed query packs can add startup cost.

The manifest records actual snapshot identity separately from stable project-based candidate IDs. `repository_sha` in detector output is the stable project identity used for incremental evidence IDs, not a claim of a Git revision. Source identity in the product summary hashes the complete inventoried checkout.

Directory exclusions are `.git`, `.opensast`, virtualenv/cache folders and `node_modules`; symlinks and bytecode are excluded. Other regular files are snapshotted, including large data/build artifacts; configurable ignore rules and repository-size optimization are follow-up work. Keep the backend/worker storage outside the registered checkout. Snapshot consistency is checked before analysis; edits during a scan are included in the next scan.

Completed results retain the current candidate set. `closed_finding_ids` means candidates disappeared from the new scan; it does not independently prove an exploit was fixed. Failed/cancelled jobs do not overwrite the baseline. A cancelled subprocess group is terminated, including its CodeQL child process.

## Company installation

Deploy one backend inside the company network and keep workers close to their checkouts. Serve the backend through an internal TLS reverse proxy:

```bash
opensast serve --host 127.0.0.1 --port 8765 \
  --public-url https://opensast.company.internal
```

The proxy must preserve/set `Host: opensast.company.internal`, keep the root URL prefix, and provide a company-trusted TLS certificate. The application validates the exact configured Host/Origin, uses secure cookies for HTTPS, and does not trust forwarded authentication or client-IP headers. Proxy rate limiting may complement application throttling. Bind on a private interface only when necessary and use firewall restrictions; a non-loopback bind requires an explicit HTTPS public origin.

No CDN, external fonts, cloud accounts, hosted database, remote model provider, or hosted scan service is required. Source snippets/results remain sensitive internal data; keep server storage and worker logs in company-controlled access-restricted directories.

Workspace membership currently grants access to every project in that workspace. Separate sensitive projects into different workspaces. Project-specific restricted ACLs, corporate SSO/MFA, recovery/reset administration, multi-server HA, retention/cleanup policies, resource scheduling across multiple workers sharing a GPU, and tamper-resistant external audit storage are future work.

An operator with access to the installation database/worker token can access or alter its data; this is the infrastructure trust boundary. Run workers as dedicated non-root users, not as system administrators. The server accepts worker-reported results, so trusted worker hosts are required.

## Team management

```bash
opensast workspace list
opensast workspace create "Security team"
opensast members WORKSPACE_ID
opensast members WORKSPACE_ID --username alice --role member --new-user
opensast members WORKSPACE_ID --username alice --role viewer
opensast members WORKSPACE_ID --username alice --role remove
opensast password
opensast audit WORKSPACE_ID
```

New-user creation prompts for an initial password. Existing users can be added without replacing their password. Users can change their own passwords, revoking all their sessions. The last workspace admin cannot be removed/demoted. Admins manage membership/projects/worker credentials, members scan/review/cancel, viewers read/export.

If the admin rotates a worker credential in the dashboard, paste it privately on the worker machine:

```bash
opensast worker-token --import
```

It prompts without echoing the credential. Rotation revokes the old project token and running workers must restart. Reconnecting an existing project on another machine is possible, but its local baseline is independent. The server prevents simultaneous running jobs; initial scanning on the new machine is full.

## Storage, diagnostics and recovery

- Backend: `OPENSAST_HOME/server/opensast.sqlite3`, including result payloads, session hashes and audit records.
- User credentials: `OPENSAST_HOME/client/credentials.json`.
- Project worker: `OPENSAST_HOME/workers/PROJECT_ID/credentials.json`, `baseline.json`, `runs/JOB_ID/`.
- Each worker run retains source snapshot, incremental plan, detector commands/stdout/stderr, query snapshots, normalized candidates, evidence packets, verifier wire events/result logs, progress and final result.

The database uses WAL. Back up using SQLite's online backup facility or stop the service and preserve the database plus WAL/SHM consistently. Back up worker state separately. Job leases expire after 180 seconds without a heartbeat, then become failed/cancelled on the next job access/claim. Failed jobs require a new explicitly queued scan; no endless automatic retry loop. If a successful result reaches the backend but local baseline commit fails, the next scan safely does extra work rather than silently assuming a baseline exists.

Diagnostics contain source/evidence and stay local. Browser/CLI result export includes code excerpts, while detailed engine and inference wire logs are currently available on the worker host. No retention cleanup runs automatically in this first release.

## Private Tailscale browser access

For private Tailscale access, replace `TAILSCALE_IP` below with your scan machine’s actual Tailscale IPv4 address. Keep the API on loopback and configure your private forwarding path separately:

```bash
opensast serve --trusted-origin http://TAILSCALE_IP:8765
```

This is intended for an existing private Tailscale forwarding path, including userspace networking. `--trusted-origin` adds exact Host/Origin entries; it does not itself configure networking or disable host checks. Additional plain HTTP origins are restricted to explicitly selected addresses in `100.64.0.0/10`; ordinary company/public origins use HTTPS. The operator must ensure this address is actually reached over the private tailnet. Local `127.0.0.1`/`localhost` access remains available. See [Tailscale userspace networking](https://tailscale.com/docs/concepts/userspace-networking).

## Scan result pages

Each completed scan has a **View results** link. It opens a dedicated `/scans/JOB_ID` page with the project name, scan metadata, verdict filter, evidence and JSON export. Use **Back to scan history** to return to the project. Saved scan URLs require the same authenticated project access as the dashboard.


## Dashboard navigation and review

### Project overview

Choose a workspace and project to see the latest scan status, last completed scan, AI-flagged candidates and unresolved candidates from the latest completed report. Start with **Scan changes**. The first scan is full; subsequent changed snapshots reuse eligible verification decisions. **Full scan** bypasses reuse. Both scan buttons are disabled while a scan is queued, running or being submitted.

If the worker is offline, start `opensast worker` from the registered checkout. Queued scans wait until that worker is available. The dashboard shows the real stages (queued, code analysis, AI review, completed), elapsed time, and candidate-review counts once available. It does not estimate overall completion percentages during code analysis. Failed scans keep the previous completed report and offer a retry; retries create a new job.

### Scan reports

Use **View results** or **View latest results** to open a dedicated report. Its leading counts are **Flagged by AI**, **Dismissed by AI**, **Needs review**, and total candidates. These labels describe model decisions, not human-confirmed ground truth. Missing evidence, unconfigured inference and execution errors remain unresolved. Timing, reuse and technical identifiers are available in an expandable details section.

Search by file, CWE, rule or explanation, and filter AI decisions separately from human review states. Lists show 25 findings per page. Search, filters and page are retained in the URL when opening a finding and returning to the report.

### Finding review

**Review finding** opens `/scans/JOB_ID/findings/FINDING_ID`. Referenced evidence appears beside the AI explanation, with source line numbers and the reported location highlighted when present. Missing or truncated evidence is explicitly labeled.

Workspace members and administrators can **Confirm finding**, **Dismiss finding**, **Reopen**, and save a review note. These actions update the existing project finding-review record; they never rewrite the AI verdict. Viewers can read the evidence and review notes but cannot change them. Review states apply to the same finding within its project, including when it appears in another scan.

Use breadcrumbs or **Back to scan results** and **Back to scan history** to navigate. Previous/next finding links follow the current filters. Scan and finding URLs require authenticated access to their project.
