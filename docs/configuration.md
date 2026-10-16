# Configuration

## Current query profile

`config/plan7/current-queries.json` is the active custom-query list, not a research run ledger. Its `query_count` must match its query entries. Historical directory names are retained because the scanner and packaging code refer to those paths.

The package includes only the selected custom queries, their local QL helpers, the required dependency lock and the XSS extension model pack. `hatch_build.py` bundles these assets into the Python wheel.

## Model and evidence policy

Core scan options configure the inference endpoint, model, output token budget and context window. Use `aisast scan --help` to inspect supported options. Bundled question templates and routing live in `src/aisast/verifier/assets/`; acceptance policy is implemented in `src/aisast/verifier/policy.py` and pipeline code.

No model weights, user credentials, dashboard databases or private scan outputs are included in this repository. Configure deployment-specific values on your own infrastructure.

## Supported patterns

The tool targets the four CWEs listed in the README. Python and framework handling depends on the recognized code pattern; the presence of a Flask, Django, FastAPI, Starlette, Jinja2 or SQLAlchemy import does not establish complete support for that framework or all versions.
