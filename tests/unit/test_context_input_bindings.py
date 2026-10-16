"""General controls for the context-input stage, independent of benchmark names."""
from pathlib import Path

import pytest

from aisast.context.context_builder import ContextBuilder
from aisast.models import Candidate, Location


def packet(root: Path, file: str, text: str, extra=None, budget=24000):
    path = root / file
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    line = next(i for i, s in enumerate(text.splitlines(), 1) if '# alert' in s)
    loc = Location(file=file, line=line)
    c = Candidate(candidate_id='fixture', repository_sha='fixture', rule_id='fixture',
                  cwe=89, title='fixture', primary_location=loc, sink=loc)
    return ContextBuilder(root, max_chars=budget).packet(c, extra)


def contents(p):
    return '\n'.join(e.code for e in p.evidence)


def test_aliased_optional_query_default_and_numeric_constraint(tmp_path):
    p = packet(tmp_path, 'api.py', '''from fastapi import FastAPI as API
from typing import Optional
service = API()
@service.get('/search')
async def search(name: Optional[str] = 'fixed', count: int = 3):
    db.execute(name) # alert
''')
    assert any('search.name' in f and 'client query' in f and 'default' in f for f in p.framework_facts)
    assert any('search.count' in f and 'annotation=int' in f for f in p.framework_facts)
    assert all(e['included'] and e['evidence_ids'] for e in p.context_resolution if e.get('fact'))


def test_imported_router_body_model_and_explicit_header(tmp_path):
    (tmp_path / 'router.py').write_text('from fastapi import APIRouter\nrouter = APIRouter()\n')
    (tmp_path / 'models.py').write_text('from pydantic import BaseModel as Model\nclass Input(Model):\n    text: str\n')
    p = packet(tmp_path, 'api.py', '''from router import router as api
from models import Input
from fastapi import Header
from typing import Annotated
@api.post('/save')
def save(data: Input, token: Annotated[str, Header(max_length=30)]):
    db.execute(data.text) # alert
''')
    assert 'text: str' in contents(p)
    assert any('save.data' in f and 'client body' in f for f in p.framework_facts)
    assert any('save.token' in f and 'client header' in f for f in p.framework_facts)
    assert any(e.file == 'router.py' for e in p.evidence)


def test_path_and_dependency_provider_are_separate(tmp_path):
    (tmp_path / 'storage.py').write_text('def connection():\n    return open_db()\n')
    p = packet(tmp_path, 'api.py', '''import fastapi as web
from storage import connection
app = web.FastAPI()
@app.get('/record/{number}')
def view(number: int, db = web.Depends(connection)):
    db.execute(number) # alert
''')
    assert any('view.number' in f and 'client path' in f for f in p.framework_facts)
    assert any('view.db' in f and 'not a direct query input' in f for f in p.framework_facts)
    assert 'return open_db()' in contents(p)


@pytest.mark.parametrize('prefix', [
    'class Fake:\n    def get(self, path): pass\napp = Fake()',
    'from fastapi import FastAPI\napp = FastAPI()\napp = other',
    'from fastapi import FastAPI\ndef FastAPI(): pass\napp = FastAPI()',
    'from fastapi import FastAPI\nFastAPI = fake\napp = FastAPI()',
])
def test_unresolved_or_shadowed_receiver_has_no_input_fact(tmp_path, prefix):
    p = packet(tmp_path, 'api.py', prefix + "\n@app.get('/record')\ndef view(name: str):\n    db.execute(name) # alert\n")
    assert not p.framework_facts


def test_unknown_default_factory_does_not_become_query_input(tmp_path):
    p = packet(tmp_path, 'api.py', '''from fastapi import FastAPI
app = FastAPI()
@app.get('/record')
def view(name: str = custom_dependency()):
    db.execute(name) # alert
''')
    assert not p.framework_facts
    assert any(e.get('binding') == 'unresolved_default_factory' for e in p.context_resolution)


def test_budget_drops_fact_when_required_evidence_is_absent(tmp_path):
    p = packet(tmp_path, 'api.py', '''from fastapi import FastAPI
app = FastAPI()
@app.get('/record')
def view(name: str):
    db.execute(name) # alert
''', budget=60)
    assert not p.framework_facts
    assert p.context_truncated
    assert any(e.get('fact') and not e['included'] for e in p.context_resolution)


def test_direct_keyword_only_argument_caller_and_guard_are_collected(tmp_path):
    (tmp_path / 'view.py').write_text('from worker import execute as run\nfrom flask import request\ndef view():\n    text = request.args["text"]\n    if len(text) < 40:\n        run(text=text)\n')
    p = packet(tmp_path, 'worker.py', 'def execute(*, text):\n    db.execute(text) # alert\n')
    assert 'request.args' in contents(p)
    assert 'if len(text) < 40' in contents(p)
    assert any(e['kind'] == 'caller_argument_binding' for e in p.context_resolution)


@pytest.mark.parametrize('expansion', ['Caller: helper', 'Caller of helper'])
def test_expansion_uses_requested_target_not_current_owner(tmp_path, expansion):
    p = packet(tmp_path, 'worker.py', '''def helper():
    return 'fixed'
def caller():
    return helper()
def different(value):
    db.execute(value) # alert
''', extra=[expansion])
    assert 'return helper()' in contents(p)
    assert any(e.get('kind') == 'expansion_request' and e['request_kind'] == 'caller' and e['target'] == 'helper' and e['status'] == 'located'
               for e in p.context_resolution)


def test_missing_caller_is_not_reported_located_just_for_definition(tmp_path):
    p = packet(tmp_path, 'worker.py', 'def helper(value):\n    db.execute(value) # alert\n', extra=['Caller of helper'])
    assert any(e.get('kind') == 'expansion_request' and e['status'] == 'no_additional_relation' for e in p.context_resolution)
