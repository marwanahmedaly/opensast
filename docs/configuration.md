# Configuration

## Current query profile

`config/plan7/current-queries.json` is the active custom-query list, not a research run ledger. Its `query_count` must match its query entries. Historical directory names are retained because the scanner and packaging code refer to those paths.

The package includes only the selected custom queries, their local QL helpers, the required dependency lock and the XSS extension model pack. `hatch_build.py` bundles these assets into the Python wheel.

## Model and evidence policy

Core scan options configure the inference endpoint, model, output token budget and context window. Use `aisast scan --help` to inspect supported options. Bundled question templates and routing live in `src/aisast/verifier/assets/`; acceptance policy is implemented in `src/aisast/verifier/policy.py` and pipeline code.

No model weights, user credentials, dashboard databases or private scan outputs are included in this repository. Configure deployment-specific values on your own infrastructure.

## Supported patterns

The tool targets the four CWEs listed in the README. Support concerns specific code patterns, rather than every behavior of a framework.

| Technology or mechanism | Support boundary |
|---|---|
| Native Python file, process, SQL, and generated HTML operations | Primary patterns; coverage remains partial. |
| Flask input, routing, and response behavior | Primary selected patterns; not all Flask applications or versions. |
| Jinja2, SQLAlchemy, and Django | Partial, pattern-dependent coverage; validate the particular integration. |
| FastAPI/Starlette and Django REST Framework | Exploratory integrations; not established primary coverage. |
| Other integrations or unknown versions | Require separate evidence; an unrelated framework import does not invalidate a native Python mechanism. |

This matches the report's Table 4.2. Historical evaluations retain their recorded scope and configurations; these boundaries do not retrospectively exclude missed cases or improve scores. An import alone is not evidence of complete support.
