# Git-aware scans and GitHub Actions

## What this implementation does

`opensast ci` runs the existing product detector, ContextBuilder and verifier
without requiring a dashboard account or a worker credential. It processes every
candidate, uses the same pinned-model cache and dependency invalidation as the
product worker, and writes the complete JSON report to company-local storage.
It does not submit results to a dashboard project or change its scan history.

After code changes, CodeQL still analyzes the whole repository. Git supplies
revision metadata and a PR comparison baseline; it does not limit detection to
changed lines. The existing file-hash inventory remains authoritative, including
regular ignored files that the scanner already includes. Staged, unstaged and
untracked changes are included in a local Git-aware scan.

## Local invocation

Run from the Git repository root with the trusted OpenSAST source installation
and preinstalled CodeQL/query packs. State and report paths must be outside the
scanned checkout:

```bash
opensast ci \
  --project-key my-team/my-project \
  --state "$HOME/.local/share/opensast/ci" \
  --output /tmp/opensast-my-project/report.json \
  --base origin/main \
  --codeql /opt/codeql/codeql \
  --query-search-path /opt/codeql/packages \
  --endpoint http://127.0.0.1:8000/v1 \
  --model qwen3-coder \
  --model-revision WEIGHTS_SHA256
```

`--base` resolves the merge-base between the supplied target and HEAD, then scans
that immutable revision and the current working tree. Fetch the target and enough
history first; a missing ref/history fails explicitly rather than giving a false
clean comparison. No project checkout hooks or setup scripts are used to export
the baseline: files are read directly from Git blobs.

The first comparison needs two scans. Base revision results are retained by commit
and configuration identity for subsequent comparisons. Unchanged snapshots skip
CodeQL and inference; changed snapshots run whole-repository CodeQL and reuse only
valid unaffected verifier decisions. A PR scan cannot overwrite its base cache.
A project lock prevents concurrent cache updates. Failed scans do not commit a new
baseline; incomplete decisions are not cached. An unpinned model is not accepted.
Repeated scans of the same PR head and comparison base retain their own head cache,
so an unchanged PR reuses both revisions rather than verifying its changes again.

Omit `--base` for a normal branch scan with a persistent incremental baseline.
All current alerts are then reported for the gate; they are not described as newly
introduced. `--full` bypasses result reuse for both comparison revisions.
Clean branch/push scans also warm the exact commit cache for later PR comparisons
when the scanned file inventory exactly matches the committed tree. Local or
ignored-file additions cannot be published as that immutable commit baseline.

## Report and gate behavior

The JSON retains **every current finding**, its evidence, verdict, scan timings,
changed/affected files, Git revision metadata and cache accounting. The
`pull_request` section additionally lists:

- `new_alert_ids`: current `VULNERABLE` decisions without a matching positive
  baseline alert.
- `existing_alert_ids`: positive alerts already present in the baseline.
- `no_longer_reported_alert_ids`: baseline alerts absent from current positive
  decisions. This does not prove a fix.

`summary.changed_files` describes changes since that scan cache's previous snapshot;
`git.changed_files` describes differences from the PR merge-base. On a repeated PR,
the first list can be empty while the second still lists the PR's edits.

Matching compares CWE, rule and primary/source/sink locations. Unchanged lines are
mapped between snapshots so inserting lines above a finding does not make it new.
Modified operations and renamed files conservatively count as new; this can
produce extra PR alerts. A baseline suspect or negative verdict becoming positive
counts as new. Existing baseline alerts are still suspected findings, not ground
truth or confirmed vulnerabilities.

Exit status is 0 on a completed passing scan, 1 for execution failure or new alerts,
and 2 for incomplete verification in either comparison revision. `--fail-on none`
disables the alert gate, but still fails incomplete verification. Zero candidates
does not establish the absence of vulnerabilities. Detector-layer gaps remain.

## Company-local GitHub Actions

Use the [workflow template](examples/opensast-github-actions.yml.example) and
[composite action](../.github/actions/opensast/action.yml). After the action is merged into the main repository, replace
`REPLACE_WITH_REVIEWED_COMMIT_SHA` with a reviewed commit containing the action.
Configure runner paths and model digest before enabling the workflow. The example
is not active until you copy it into the target repository's workflows directory.

Provision a trusted OpenSAST source installation outside the target checkout;
the scanner requires its bundled query and prompt assets.
Do not install or execute code from the scanned PR as the scanner itself. Use an
isolated company runner provisioned with CodeQL, query packs and internal inference.
The example selects the actual PR head commit, fetches full history, grants only
repository read permission, and excludes fork PRs from the internal runner. Team
runner access policies must determine which internal contributors may run jobs.

Source snapshots, prompts, verdict caches and detailed reports stay on the runner.
The action prints only an exit status to GitHub logs. It does not upload reports,
use GitHub cache storage, or contact external inference. GitHub still receives
workflow/check status. A private OpenSAST action requires repository/organization
access configuration. This is an Actions integration, not an offline substitute
for GitHub itself.

GitHub caches reside in GitHub-owned storage even for self-hosted runners, so they
are deliberately not used for evidence caches. See GitHub's
[cache documentation](https://docs.github.com/en/actions/concepts/workflows-and-actions/dependency-caching)
and [runner security guidance](https://docs.github.com/en/actions/reference/security/secure-use).
Change detection uses Git's documented
[diff behavior](https://git-scm.com/docs/git-diff).

## Operational limits

- Git baseline comparison rejects repositories with submodules; it cannot silently
  omit their sources and claim a complete comparison.
- Dependency invalidation uses the existing conservative Python import graph,
  with full invalidation for uncertain imports or non-Python changes.
- Renames and modified operation lines can increase new-alert counts. Alert
  matching is a reporting heuristic and does not bypass current verification.
- Saved runs include source/evidence and can grow over time. Store them on private
  company disks and apply retention externally; automatic pruning is not implemented.
- This change does not provide SARIF upload, PR comments, dashboard publication,
  authentication through GitHub, or edited-files-only CodeQL execution.
