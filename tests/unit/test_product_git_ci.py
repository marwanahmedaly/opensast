"""Git and CI orchestration regression tests; model/scanner calls are mocked here."""
import copy
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from aisast.product import ci
from aisast.product.git_changes import changes, export_revision, git, revision, working_tree_metadata
from aisast.product.incremental import atomic_json, identity, inventory, snapshot


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    git(root, 'init', '-b', 'main')
    git(root, 'config', 'user.name', 'Test')
    git(root, 'config', 'user.email', 'test@example.invalid')
    (root / 'app.py').write_text('value = 1\nprint(value)\n')
    git(root, 'add', '.')
    git(root, 'commit', '-m', 'base')
    return root


def test_git_includes_committed_staged_unstaged_and_untracked(repo):
    base = revision(repo, 'HEAD')
    (repo / 'committed.py').write_text('x = 1\n')
    git(repo, 'add', '.'); git(repo, 'commit', '-m', 'head')
    (repo / 'app.py').write_text('value = 2\n')
    git(repo, 'add', 'app.py')
    (repo / 'app.py').write_text('value = 3\n')
    (repo / 'new space\nfile.py').write_text('x = 4\n')
    result = changes(repo, base)
    assert result['merge_base'] == base
    assert result['changed_files'] == ['app.py', 'committed.py', 'new space\nfile.py']
    assert result['untracked_files'] == ['new space\nfile.py']
    assert changes(repo)['changed_files'] == ['app.py', 'new space\nfile.py']


def test_merge_base_uses_common_ancestor(repo):
    ancestor = revision(repo, 'HEAD')
    git(repo, 'checkout', '-b', 'feature')
    (repo / 'feature.py').write_text('x=1\n')
    git(repo, 'add', '.'); git(repo, 'commit', '-m', 'feature')
    git(repo, 'checkout', 'main')
    (repo / 'main.py').write_text('x=2\n')
    git(repo, 'add', '.'); git(repo, 'commit', '-m', 'main')
    git(repo, 'checkout', 'feature')
    result = changes(repo, 'main')
    assert result['merge_base'] == ancestor
    assert result['changed_files'] == ['feature.py']


def test_missing_revision_and_subdirectory_fail(repo):
    with pytest.raises(RuntimeError): changes(repo, 'missing')
    nested = repo / 'nested'; nested.mkdir()
    with pytest.raises(RuntimeError): changes(nested)


def test_unborn_repository_keeps_optional_git_metadata(tmp_path):
    git(tmp_path, 'init')
    assert working_tree_metadata(tmp_path)['available'] is False
    assert working_tree_metadata(tmp_path / 'missing') is None


def test_export_reads_committed_blobs_and_ignores_export_ignore(repo, tmp_path):
    (repo / '.gitattributes').write_text('app.py export-ignore\n')
    (repo / 'binary.bin').write_bytes(b'\x00\xff\n')
    (repo / 'link.py').symlink_to('/etc/passwd')
    git(repo, 'add', '.'); git(repo, 'commit', '-m', 'attributes')
    commit = revision(repo, 'HEAD')
    (repo / 'app.py').write_text('local edit\n')
    target = tmp_path / 'export'
    export_revision(repo, commit, target)
    assert (target / 'app.py').read_text() == 'value = 1\nprint(value)\n'
    assert (target / 'binary.bin').read_bytes() == b'\x00\xff\n'
    assert not (target / 'link.py').exists()


def test_submodules_rejected_before_export(repo, tmp_path):
    git(repo, 'update-index', '--add', '--cacheinfo', '160000,' + revision(repo, 'HEAD') + ',submodule')
    git(repo, 'commit', '-m', 'gitlink')
    with pytest.raises(RuntimeError, match='submodules'):
        export_revision(repo, revision(repo, 'HEAD'), tmp_path / 'export')
    assert not (tmp_path / 'export').exists()


def finding(label='old', verdict='VULNERABLE', line=2):
    loc = {'file': 'app.py', 'line': line, 'column': None}
    return {'finding_id': label, 'verdict': verdict, 'candidate': {'cwe': 78, 'rule_id': 'r',
            'primary_location': loc, 'source': None, 'sink': loc}}


@pytest.mark.parametrize('old_verdict,new_line,new_text,expected', [
    ('VULNERABLE', 3, '# inserted\na = 1\nrun(a)\n', 'existing'),
    ('VULNERABLE', 2, 'a = 1\nrun(other)\n', 'new'),
    ('NOT_VULNERABLE', 2, 'a = 1\nrun(a)\n', 'new'),
    ('UNRESOLVED', 2, 'a = 1\nrun(a)\n', 'new'),
])
def test_alert_matching(tmp_path, old_verdict, new_line, new_text, expected):
    base = tmp_path / 'base'; base.mkdir(); (base / 'app.py').write_text('a = 1\nrun(a)\n')
    head = tmp_path / 'head'; head.mkdir(); (head / 'app.py').write_text(new_text)
    result = ci.comparison({'findings': [finding('head', line=new_line)]},
                           {'findings': [finding(verdict=old_verdict)]}, head, base)
    assert result[expected + '_alert_ids'] == ['head']


def test_removed_alert_not_called_fixed(tmp_path):
    result = ci.comparison({'findings': []}, {'findings': [finding()]}, tmp_path, tmp_path)
    assert result['no_longer_reported_alert_ids'] == ['old']
    assert 'does not establish' in result['note']


@pytest.fixture
def mocked_ci(repo, tmp_path, monkeypatch):
    monkeypatch.chdir(repo)
    calls = []
    def execute(root, state, job, settings, full=False):
        previous = ci.load(state / 'baseline.json', {})
        files = inventory(root)
        source = state / 'runs' / job / 'source'
        snapshot(root, source, files)
        reused = not full and files == previous.get('files')
        payload = {'summary': {'analysis_identity': 'test-config', 'verified': 0 if reused else 1,
                              'scanner_scope': 'unchanged snapshot reused' if reused else 'full', 'reused': int(reused)},
                   'findings': [finding(verdict=settings.get('verdict', 'VULNERABLE'))],
                   'git': working_tree_metadata(root)}
        atomic_json(state / 'runs' / job / 'result.json', payload)
        atomic_json(state / 'runs' / job / 'next-baseline.json', {'job_id': job, 'files': files, 'cache': {}})
        calls.append((root, reused))
    monkeypatch.setattr(ci, 'execute', execute)
    args = SimpleNamespace(base=None, state=tmp_path / 'state', output=tmp_path / 'report.json', full=False, fail_on='new')
    settings = {'project_id': 'test/repo'}
    return args, settings, calls


def test_clean_push_warms_base_cache(repo, mocked_ci):
    args, settings, calls = mocked_ci
    assert ci.run(args, settings) == 1
    args.base = revision(repo, 'HEAD')
    assert ci.run(args, settings) == 0
    assert calls[-2][1] is True and calls[-1][1] is True
    result = json.loads(args.output.read_text())
    assert result['pull_request']['existing_alert_ids'] == ['old']


def test_local_ignored_files_cannot_warm_commit_cache(repo, mocked_ci):
    args, settings, calls = mocked_ci
    (repo / '.git/info/exclude').write_text('private.py\n')
    (repo / 'private.py').write_text('secret = 1\n')
    assert changes(repo)['changed_files'] == []
    ci.run(args, settings)
    base = args.state / identity(settings['project_id']) / 'bases' / revision(repo, 'HEAD')
    assert not (base / 'baseline.json').exists()


@pytest.mark.parametrize('verdict', ['UNRESOLVED', 'SYSTEM_ERROR', 'NEEDS_MORE_CONTEXT'])
def test_incomplete_scan_fails_even_report_only(mocked_ci, verdict):
    args, settings, _ = mocked_ci
    settings['verdict'] = verdict; args.fail_on = 'none'
    assert ci.run(args, settings) == 2


def test_cache_inside_checkout_rejected(repo, mocked_ci):
    args, settings, _ = mocked_ci
    args.state = repo / 'state'
    with pytest.raises(RuntimeError, match='outside'): ci.run(args, settings)
    assert not args.state.exists()


def test_scanner_failure_does_not_publish_baseline(mocked_ci, monkeypatch):
    args, settings, _ = mocked_ci
    def fail(*args, **kwargs): raise RuntimeError('detector failed')
    monkeypatch.setattr(ci, 'execute', fail)
    with pytest.raises(RuntimeError): ci.run(args, settings)
    assert not list(args.state.rglob('baseline.json'))


def test_repeated_pr_reuses_head_cache(repo, mocked_ci):
    args, settings, calls = mocked_ci
    args.base = revision(repo, 'HEAD')
    (repo / 'app.py').write_text('value = 2\n')
    ci.run(args, settings)
    ci.run(args, settings)
    assert calls[-1][1] is True


def test_action_shell_preserves_arguments_and_exit_status(tmp_path):
    action = yaml.safe_load(Path('.github/actions/opensast/action.yml').read_text())
    script = action['runs']['steps'][0]['run']
    executable = tmp_path / 'fake opensast'
    executable.write_text('#!/usr/bin/env python3\nimport sys,json\nprint(json.dumps(sys.argv[1:]))\nsys.exit(2)\n')
    executable.chmod(0o700)
    output = tmp_path / 'private report.json'
    env = dict(os.environ, OPENSAST_EXECUTABLE=str(executable), OPENSAST_PROJECT='team/repo',
               OPENSAST_BASE='main; harmless', OPENSAST_STATE=str(tmp_path / 'state'),
               OPENSAST_OUTPUT=str(output), OPENSAST_CODEQL='/local/codeql', OPENSAST_PACKS='/local/packs',
               OPENSAST_ENDPOINT='http://localhost:8000/v1', OPENSAST_MODEL='qwen', OPENSAST_REVISION='digest',
               OPENSAST_MODEL_HOST='', OPENSAST_FAIL_ON='new', GITHUB_OUTPUT=str(tmp_path / 'github-output'))
    result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script], env=env, capture_output=True, text=True)
    assert result.returncode == 2
    assert 'exit-code=2' in (tmp_path / 'github-output').read_text()
    arguments = json.loads(Path(str(output) + '.console.log').read_text())
    assert arguments[arguments.index('--base') + 1] == 'main; harmless'
    assert arguments[arguments.index('--output') + 1] == str(output)
    assert 'team/repo' not in result.stdout


def test_full_override_disables_reuse(repo, mocked_ci):
    args, settings, calls = mocked_ci
    ci.run(args, settings)
    args.base = revision(repo, 'HEAD'); args.full = True
    ci.run(args, settings)
    assert not calls[-2][1] and not calls[-1][1]


def test_project_cache_lock(mocked_ci):
    import fcntl
    args, settings, _ = mocked_ci
    project = args.state / identity(settings['project_id']); project.mkdir(parents=True)
    with (project / 'ci.lock').open('w') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(RuntimeError, match='Another CI scan'):
            ci.run(args, settings)


def test_incomplete_base_also_fails_gate(repo, mocked_ci, monkeypatch):
    args, settings, _ = mocked_ci
    args.base = revision(repo, 'HEAD'); args.fail_on = 'none'
    original = ci.scan
    def scan(root, state, settings, full=False):
        payload, source = original(root, state, settings, full)
        if root.name == 'checkout':
            payload = copy.deepcopy(payload)
            payload['findings'][0]['verdict'] = 'UNRESOLVED'
        return payload, source
    monkeypatch.setattr(ci, 'scan', scan)
    assert ci.run(args, settings) == 2
    result = json.loads(args.output.read_text())
    assert result['pull_request']['incomplete_decisions_both_revisions'] == 1


def test_renamed_operation_is_conservatively_new(tmp_path):
    base = tmp_path / 'base'; base.mkdir(); (base / 'app.py').write_text('a=1\nrun(a)\n')
    head = tmp_path / 'head'; head.mkdir(); (head / 'renamed.py').write_text('a=1\nrun(a)\n')
    new = finding('new')
    new['candidate']['primary_location']['file'] = 'renamed.py'
    result = ci.comparison({'findings': [new]}, {'findings': [finding()]}, head, base)
    assert result['new_alert_ids'] == ['new']


def test_workflow_template_keeps_data_internal():
    workflow = yaml.load(Path('docs/examples/opensast-github-actions.yml.example').read_text(), Loader=yaml.BaseLoader)
    assert 'pull_request_target' not in workflow['on']
    job = workflow['jobs']['scan']
    assert 'self-hosted' in job['runs-on']
    assert 'head.repo.full_name == github.repository' in job['if']
    assert workflow['permissions'] == {'contents': 'read'}
    for step in job['steps']:
        assert 'upload-artifact' not in step.get('uses', '') and 'actions/cache' not in step.get('uses', '')
    assert job['steps'][0]['with']['fetch-depth'] == '0'
    assert job['steps'][0]['with']['persist-credentials'] == 'false'
