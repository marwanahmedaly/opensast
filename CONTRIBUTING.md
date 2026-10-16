# Contributing

Create a feature branch, make focused changes and open a pull request. Include a description of the change and checks actually performed. Preserve existing third-party notices.

## Integrated components

The scanner, dashboard/API/worker, and CLI/installer/GitHub Action are integrated in this repository. Keep changes to their shared interfaces coordinated. Do not include private handoff instructions, credentials, or scan evidence in pull requests.

## Tests

Existing tests are under `tests/`. In an isolated development environment, install the development dependencies with `python -m pip install -e '.[dev]'` and use `pytest` when validating your change. Product tests require the web dependencies (`.[web,dev]`). Never describe a check as passing unless it was actually run against the relevant revision.

## Publication

Keep deployment credentials, scan evidence, model weights and private repositories outside Git. Release packaging and installation references must target a reviewed, verified release. The repository is public; review new files and history for private data before publishing.
