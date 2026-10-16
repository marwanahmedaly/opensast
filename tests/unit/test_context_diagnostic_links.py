from pathlib import Path
from aisast.context.context_builder import ContextBuilder
from aisast.models import Candidate, Location


def packet(root, file, line, chains=False):
    c = Candidate(candidate_id='diagnostic', repository_sha='r', rule_id='r', cwe=89,
                  title='suspect', primary_location=Location(file=file, line=line))
    return ContextBuilder(root, include_call_chains=chains).packet(c)


def write(root, name, text):
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def test_local_relative_import_in_nested_view(tmp_path):
    write(tmp_path, 'pkg/views.py', 'def factory(bp):\n    @bp.route("/<name>")\n    def view(name):\n        from flask import request\n        from .guard import validate\n        valid = validate(request)\n        return name\n')
    write(tmp_path, 'pkg/guard.py', 'def validate(request):\n    return request.args.get("token") == "secret"\n')
    p = packet(tmp_path, 'pkg/views.py', 7)
    assert any(e.file == 'pkg/guard.py' for e in p.evidence)
    assert any('HTML response' in f for f in p.framework_facts)


def test_monorepo_absolute_import_and_consumer(tmp_path):
    write(tmp_path, 'libs/storage/pkg/helper.py', 'def build(keys):\n    return "SELECT " + keys\n')
    write(tmp_path, 'libs/storage/pkg/api.py', 'from pkg.helper import build\ndef fetch(db, keys):\n    return db.execute(build(keys))\n')
    p = packet(tmp_path, 'libs/storage/pkg/helper.py', 2, True)
    assert any('db.execute(build(keys))' in e.code for e in p.evidence)
    assert any(e['kind'] == 'possible_call_consumer' for e in p.context_resolution)
    p = packet(tmp_path, 'libs/storage/pkg/api.py', 3)
    assert any('"SELECT " + keys' in e.code for e in p.evidence)


def test_same_named_unrelated_helper_is_not_resolved(tmp_path):
    write(tmp_path, 'src/pkg/helper.py', 'def build(x):\n    return x\n')
    write(tmp_path, 'src/other/helper.py', 'def build(x):\n    return "unrelated"\n')
    write(tmp_path, 'src/pkg/api.py', 'from pkg.helper import build\ndef fetch(x):\n    return build(x)\n')
    p = packet(tmp_path, 'src/pkg/api.py', 3, True)
    assert all(e.file != 'src/other/helper.py' for e in p.evidence)


def test_constructor_input_and_budget_are_visible(tmp_path):
    write(tmp_path, 'app.py', 'class Entry:\n    def __init__(self, data):\n        self.value = data["default"]\n    def expand(self):\n        return self.value\ndef parse(data):\n    return Entry(data)\n')
    p = packet(tmp_path, 'app.py', 5, True)
    assert any('self.value = data["default"]' in e.code for e in p.evidence)
    assert any('return Entry(data)' in e.code for e in p.evidence)
    c = p.candidate
    small = ContextBuilder(tmp_path, include_call_chains=True, max_chars=60).packet(c)
    assert small.context_truncated
    assert any(e.get('status') == 'omitted_by_budget' for e in small.context_resolution)
