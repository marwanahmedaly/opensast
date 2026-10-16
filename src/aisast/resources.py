"""Resolve scanner configuration in both source installations and wheel installs."""
from pathlib import Path


def scanner_root() -> Path:
    bundled = Path(__file__).resolve().parent / 'assets/scanner'
    if (bundled / 'config/plan7/current-queries.json').is_file():
        return bundled
    checkout = Path(__file__).resolve().parents[2]
    if (checkout / 'config/plan7/current-queries.json').is_file():
        return checkout
    raise RuntimeError('Scanner assets are missing. Reinstall the complete OpenSAST package.')
