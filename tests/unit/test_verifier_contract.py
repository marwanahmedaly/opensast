from pathlib import Path
from aisast.context.context_builder import ContextBuilder
from aisast.models import Candidate, Location
from aisast.verifier.prompts import guided_profiles, render_prompt


def test_guided_questions_allow_safety_before_missing_source():
    for questions in guided_profiles().values():
        last = questions[-1]
        assert 'NOT_VULNERABLE' in last and 'concrete defense' in last
        assert 'parameter binding' in last
        assert 'verdict False Positive.' not in last


def test_framework_contract_has_actual_evidence_ids(tmp_path: Path):
    (tmp_path/'api.py').write_text('from fastapi import FastAPI\napp = FastAPI()\n@app.get("/")\ndef read(uid: int = 1):\n    return db.execute(f"SELECT * FROM t WHERE id={uid}")\n')
    loc=Location(file='api.py',line=5)
    c=Candidate(candidate_id='contract',repository_sha='fixture',rule_id='fixture',cwe=89,
                title='fixture',primary_location=loc,sink=loc)
    packet=ContextBuilder(tmp_path).packet(c)
    event=next(row for row in packet.context_resolution if row.get('fact'))
    prompt=render_prompt(packet)
    fact_line=next(line for line in prompt.splitlines() if event['fact'] in line)
    assert all(eid in fact_line for eid in event['evidence_ids'])
    assert 'exact reported operation' in prompt
    assert 'Selecting a database row does not establish' in prompt
    assert 'parameterized values alone do not protect dynamic keys' in prompt


def test_omitted_binding_cannot_become_citable_fact(tmp_path: Path):
    (tmp_path/'api.py').write_text('from fastapi import FastAPI\napp = FastAPI()\n@app.get("/")\ndef read(name: str):\n    return db.execute(name)\n')
    loc=Location(file='api.py',line=5)
    c=Candidate(candidate_id='budget',repository_sha='fixture',rule_id='fixture',cwe=89,
                title='fixture',primary_location=loc,sink=loc)
    packet=ContextBuilder(tmp_path,max_chars=50).packet(c)
    assert not packet.framework_facts
    assert 'FRAMEWORK SEMANTICS' not in render_prompt(packet)


def test_decision_contract_requires_feasible_input_and_real_validation(tmp_path: Path):
    (tmp_path/'api.py').write_text('def read(name):\n    return db.execute(name)\n')
    loc=Location(file='api.py',line=2)
    c=Candidate(candidate_id='domain',repository_sha='fixture',rule_id='fixture',cwe=89,
                title='fixture',primary_location=loc,sink=loc)
    prompt=render_prompt(ContextBuilder(tmp_path).packet(c))
    assert 'ordinary Python type annotations alone do not enforce conversion' in prompt
    assert 'Do not invent a bypass' in prompt
    assert 'External input reaching dynamic text alone is insufficient' in prompt
    assert prompt.index('FINAL DECISION CHECK') > prompt.index('EVIDENCE:')


def test_call_contract_exposes_runtime_conversion_and_parameter(tmp_path: Path):
    (tmp_path/'api.py').write_text('def lookup(uid: int):\n    return db.execute(uid)\ndef route(text):\n    return lookup(int(text))\n')
    loc=Location(file='api.py',line=2)
    c=Candidate(candidate_id='conversion',repository_sha='fixture',rule_id='fixture',cwe=89,
                title='fixture',primary_location=loc,sink=loc)
    packet=ContextBuilder(tmp_path).packet(c)
    event=next(row for row in packet.context_resolution if row.get('kind')=='call_argument_contract')
    assert event['parameter']=='uid' and event['argument']=='int(text)'
    assert event['builtin_conversion']=='builtins.int' and event['included']
    assert 'converted result, not the original input' in render_prompt(packet)


def test_shadowed_conversion_cannot_claim_builtin_type(tmp_path: Path):
    (tmp_path/'api.py').write_text('def int(value):\n    return value\ndef lookup(uid):\n    return db.execute(uid)\ndef route(text):\n    return lookup(int(text))\n')
    loc=Location(file='api.py',line=4)
    c=Candidate(candidate_id='shadow',repository_sha='fixture',rule_id='fixture',cwe=89,
                title='fixture',primary_location=loc,sink=loc)
    packet=ContextBuilder(tmp_path).packet(c)
    events=[r for r in packet.context_resolution if r.get('kind')=='call_argument_contract' and r['argument']=='int(text)']
    assert events and not events[0]['builtin_conversion']


def test_call_contract_is_not_rendered_when_budget_omits_binding(tmp_path: Path):
    (tmp_path/'api.py').write_text('def lookup(uid):\n    return db.execute(uid)\ndef route(text):\n    return lookup(int(text))\n')
    loc=Location(file='api.py',line=2)
    c=Candidate(candidate_id='limited',repository_sha='fixture',rule_id='fixture',cwe=89,
                title='fixture',primary_location=loc,sink=loc)
    packet=ContextBuilder(tmp_path,max_chars=55).packet(c)
    assert 'CALL ARGUMENT RELATIONSHIPS' not in render_prompt(packet)
