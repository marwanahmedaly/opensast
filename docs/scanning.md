# Run a scan

## 1. Install the source package

Follow the root README. Activate the virtual environment before running commands.

## 2. Prepare analysis dependencies

Install CodeQL and its Python query packs according to their distribution instructions. Keep the compatible `codeql/python-all` version declared in `config/plan7/current-queries.json` available in your query search path. For model verification, start your chosen local or company inference service and note its OpenAI-compatible base URL and served model name.

## 3. Generate candidates and context

Replace each example path with your installation:

```bash
aisast scan /path/to/python-project   --repo-sha YOUR_SOURCE_REVISION   --codeql /path/to/codeql   --query-search-path /path/to/codeql-packs   --output /path/to/private-results   --dry-run
```

`--dry-run` performs candidate generation and evidence collection without LLM verification. It does not establish whether the candidates are true vulnerabilities.

## 4. Include LLM verification

Use the same command, remove `--dry-run`, and add:

```text
--endpoint http://127.0.0.1:8000/v1 --model YOUR_SERVED_MODEL
```

Runtime depends on repository size, candidate count, model and serving configuration. Keep results outside the analyzed repository to avoid including them in later scans.

## 5. Inspect output

The output directory contains normalized candidates, evidence packets, a scan manifest, verifier attempt records, and final findings. Inspect unresolved results and execution errors before treating a scan as complete. Review the evidence behind a reported vulnerability.

Use `aisast scan --help` for the complete command options. Product onboarding, dashboard and CI instructions will be supplied by their component PRs.
