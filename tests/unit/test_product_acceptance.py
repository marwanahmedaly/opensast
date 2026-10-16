"""Release checks for terminal CLI outcomes and worker process cleanup."""
import subprocess
import sys
from types import SimpleNamespace

import pytest

from aisast.product import cli
from aisast.product.worker import terminate


@pytest.mark.parametrize('status,verdict,expected', [
    ('completed', 'VULNERABLE', 0),
    ('completed', 'NOT_VULNERABLE', 0),
    ('completed', 'SYSTEM_ERROR', 2),
    ('completed', 'UNRESOLVED', 2),
    ('failed', None, 1),
    ('cancelled', None, 1),
])
def test_wait_reports_terminal_outcome(monkeypatch, status, verdict, expected):
    class API:
        def request(self, method, path, body=None):
            if method == 'POST': return {'id': 'job', 'status': 'queued'}
            if path.endswith('/results'):
                return {'summary': {'verifier_configured': True}, 'findings': [{'verdict': verdict}]}
            return {'id': 'job', 'status': status}
    monkeypatch.setattr(cli, 'client', lambda *args, **kwargs: API())
    monkeypatch.setattr(cli, 'project_config', lambda: {'project_id': 'project'})
    monkeypatch.setattr(sys, 'argv', ['opensast', 'scan', '--wait'])
    assert cli.main() == expected


def test_suspect_only_wait_does_not_claim_verifier_failure(monkeypatch):
    class API:
        def request(self, method, path, body=None):
            if method == 'POST': return {'id': 'job', 'status': 'queued'}
            if path.endswith('/results'):
                return {'summary': {'verifier_configured': False}, 'findings': [{'verdict': 'UNRESOLVED'}]}
            return {'id': 'job', 'status': 'completed'}
    monkeypatch.setattr(cli, 'client', lambda *args, **kwargs: API())
    monkeypatch.setattr(cli, 'project_config', lambda: {'project_id': 'project'})
    monkeypatch.setattr(sys, 'argv', ['opensast', 'scan', '--wait'])
    assert cli.main() == 0


def test_terminate_stops_child_group(tmp_path):
    import os
    import signal
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True)
    try:
        terminate(child)
        assert child.poll() is not None
        with pytest.raises(ProcessLookupError): os.killpg(child.pid, 0)
    finally:
        if child.poll() is None: os.killpg(child.pid, signal.SIGKILL); child.wait()


def test_guided_assets_are_part_of_analysis_identity(tmp_path, monkeypatch):
    from aisast.verifier import prompts
    from aisast.product.scan_job import analysis_identity
    questions = tmp_path / 'questions.yaml'; questions.write_bytes(prompts.QUESTION_FILE.read_bytes())
    routing = tmp_path / 'routing.yaml'; routing.write_bytes(prompts.PROFILE_FILE.read_bytes())
    monkeypatch.setattr(prompts, 'QUESTION_FILE', questions)
    monkeypatch.setattr(prompts, 'PROFILE_FILE', routing)
    settings = {'codeql': 'missing-test-codeql'}
    original = analysis_identity(settings)
    questions.write_text(questions.read_text() + '\n# Changed asset\n')
    assert analysis_identity(settings) != original
    previous = analysis_identity(settings)
    routing.write_text(routing.read_text() + '\n# Changed routing\n')
    assert analysis_identity(settings) != previous


def test_missing_guided_assets_fail_before_analysis(tmp_path, monkeypatch):
    from aisast.verifier import prompts
    from aisast.product.scan_job import analysis_identity
    monkeypatch.setattr(prompts, 'QUESTION_FILE', tmp_path / 'missing.yaml')
    with pytest.raises(RuntimeError, match='Bundled prompt assets are missing'):
        analysis_identity({'codeql': 'missing-test-codeql'})


def test_bundled_asset_provenance_hashes():
    import hashlib
    import json
    from aisast.verifier.prompts import ASSET_ROOT
    record = json.loads((ASSET_ROOT / 'provenance.json').read_text())
    for name, digest in record['files'].items():
        assert hashlib.sha256((ASSET_ROOT / name).read_bytes()).hexdigest() == digest
    assert 'LGPL-2.1-only' in (ASSET_ROOT / 'python_questions.yaml').read_text()
