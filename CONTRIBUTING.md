# Contributing

Create a feature branch, make focused changes and open a pull request. Include a description of the change and checks actually performed. Preserve existing third-party notices.

## Component integration

The dashboard/API/worker component is integrated first. The CLI/installer/GitHub Actions component follows, because it imports shared client and storage helpers supplied by the dashboard component. Full product checks require both components.

Use the exact assigned file paths from your component handoff. Do not replace the main README with a handoff README or include handoff manifests in your PR. The shared scan bridge and package metadata already live here.

## Tests

Existing tests are under `tests/`. In an isolated development environment, install the development dependencies with `python -m pip install -e '.[dev]'` and use `pytest` when validating your change. Product tests require the product PRs and web dependencies. Never describe a check as passing unless it was actually run against the relevant revision.

## Publication

Keep deployment credentials, scan evidence, model weights and private repositories outside Git. Release packaging and installation references must target a reviewed, verified release. The repository remains private until the intended publication and product integration are complete.
