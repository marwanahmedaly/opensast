import pytest
from aisast.context.context_builder import ContextBuilder
from aisast.models import Candidate, Location


def packet(root, text, line):
    (root/'app.py').write_text(text)
    loc=Location(file='app.py',line=line)
    return ContextBuilder(root).packet(Candidate(candidate_id='callback-test',
        repository_sha='fixture',rule_id='fixture',cwe=22,title='fixture',
        primary_location=loc,sink=loc))


@pytest.mark.parametrize('import_line,call', [
    ('import anyio','anyio.to_thread.run_sync(guard, value)'),
    ('from anyio.to_thread import run_sync as run','run(guard, value, limiter=None)'),
    ('import asyncio','asyncio.to_thread(guard, value)'),
    ('from starlette.concurrency import run_in_threadpool as run','run(guard, path=value)'),
    ('from fastapi.concurrency import run_in_threadpool as run','run(guard, path=value)'),
    ('import anyio\nfrom functools import partial','anyio.to_thread.run_sync(partial(guard, path=value))'),
])
def test_callback_return_includes_guard(tmp_path,import_line,call):
    text=f'{import_line}\ndef guard(path):\n    if ".." in path:\n        raise ValueError()\n    return path\nasync def route(value):\n    safe = await {call}\n    return open(safe).read()\n'
    p=packet(tmp_path,text,len(text.splitlines()))
    assert any('raise ValueError()' in e.code for e in p.evidence)
    assert any(e['kind']=='callback_invocation' for e in p.context_resolution)


def test_callback_caller_binds_bound_method_parameter(tmp_path):
    text='import anyio\nclass Service:\n    def guard(self, path):\n        return open(path).read()\n    async def route(self, request):\n        return await anyio.to_thread.run_sync(self.guard, request.args["path"])\n'
    p=packet(tmp_path,text,4)
    assert any('request.args["path"]' in e.code for e in p.evidence)
    assert any(e['kind']=='call_argument_contract' and e['parameter']=='path'
               and e['argument']=='request.args[\'path\']' for e in p.context_resolution)


@pytest.mark.parametrize('prefix,expression', [
    ('def run_sync(func, value):\n    return "constant"','run_sync(guard, value)'),
    ('import anyio','anyio.to_thread.run_sync(*callbacks)'),
    ('import anyio','anyio.to_thread.run_sync(guard, **options)'),
    ('import anyio','anyio.to_thread.run_sync(factory(), value)'),
])
def test_unknown_wrapper_never_invents_invocation(tmp_path,prefix,expression):
    text=f'{prefix}\ndef guard(path):\n    return path\nasync def route(value):\n    safe = await {expression}\n    return open(safe).read()\n'
    p=packet(tmp_path,text,len(text.splitlines()))
    assert not any(e['kind']=='callback_invocation' for e in p.context_resolution)


def test_wrapper_parameter_shadowing_rejected(tmp_path):
    text='import anyio\ndef guard(path):\n    return path\nasync def route(anyio, value):\n    safe = await anyio.to_thread.run_sync(guard, value)\n    return open(safe).read()\n'
    p=packet(tmp_path,text,6)
    assert not any(e['kind']=='callback_invocation' for e in p.context_resolution)


def test_destructured_result_reaches_consumer_with_guard(tmp_path):
    text='import anyio\nclass Service:\n    def guard(self, path):\n        if ".." in path:\n            raise ValueError()\n        return path, True\n    async def route(self, value):\n        path, valid = await anyio.to_thread.run_sync(self.guard, value)\n        return self.respond(path)\n    def respond(self, filename):\n        return open(filename).read()\n'
    p=packet(tmp_path,text,11)
    assert any('raise ValueError()' in e.code for e in p.evidence)
    assert any('path, valid = await' in e.code for e in p.evidence)


def test_local_normalization_chain_does_not_exhaust_call_depth(tmp_path):
    text='import anyio\nimport os\nclass Service:\n    def lookup(self, path):\n        joined = os.path.join("root", path)\n        real = os.path.realpath(joined)\n        return os.stat(real)\n    async def route(self, request):\n        return await anyio.to_thread.run_sync(self.lookup, request.args["path"])\n'
    p=packet(tmp_path,text,7)
    assert any('request.args["path"]' in e.code for e in p.evidence)


def test_monkey_patched_wrapper_is_not_assumed(tmp_path):
    text='import anyio\ndef guard(path):\n    return path\nasync def route(value):\n    anyio.to_thread.run_sync = custom\n    path = await anyio.to_thread.run_sync(guard, value)\n    return open(path).read()\n'
    p=packet(tmp_path,text,7)
    assert not any(e['kind']=='callback_invocation' for e in p.context_resolution)


def test_reached_native_http_caller_includes_receiver_contract(tmp_path):
    (tmp_path/'helper.py').write_text('def read(value):\n    return open(value).read()\n')
    (tmp_path/'app.py').write_text('from http.server import BaseHTTPRequestHandler as Base\nfrom helper import read\nclass Handler(Base):\n    def do_GET(self):\n        return read(self.path)\n')
    loc=Location(file='helper.py',line=2)
    p=ContextBuilder(tmp_path).packet(Candidate(candidate_id='native-handler',repository_sha='fixture',
        rule_id='fixture',cwe=22,title='fixture',primary_location=loc,sink=loc))
    assert any('class Handler(Base)' in e.code for e in p.evidence)
    assert any('self.path contains the client HTTP request path' in fact for fact in p.framework_facts)
