"""Compatibility entry point for SARIF parsing and normalization."""

from .normalizer import load_and_normalize, normalize_sarif

__all__ = ["load_and_normalize", "normalize_sarif"]
