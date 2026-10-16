from copy import deepcopy

import jsonschema
import pytest

from aisast.models import Candidate, EvidenceBlock, EvidencePacket, Location
from aisast.verifier.contracts import DECISION_CONTRACT, bound_schema, decision_prompt
from aisast.verifier.prompts import render_prompt


def packet(cwe=79, evidence=True):
    loc = Location(file='app.py', line=1)
    c = Candidate(candidate_id='case', repository_sha='fixture', rule_id='fixture',
                  cwe=cwe, title='fixture', primary_location=loc, sink=loc)
    return EvidencePacket(candidate=c, profile=f'CWE-{cwe}', prompt_version='test',
                          evidence=[EvidenceBlock(id='E1', file='app.py', start_line=1,
                                                 end_line=1, code='value')] if evidence else [])


def result():
    return dict(candidate_id='case', cwe=79, verdict='VULNERABLE', source_evidence=['E1'],
                sink_evidence=['E1'], sanitizer_evidence=[], explanation='mechanism', missing_symbols=[])


def test_vulnerable_requires_source_and_sink_without_relaxing_ids():
    schema = bound_schema(packet(), True)
    jsonschema.validate(result(), schema)
    for key, bad in [('source_evidence', []), ('sink_evidence', []), ('source_evidence', ['invented'])]:
        data = result(); data[key] = bad
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(data, schema)


def test_nonvulnerable_and_unknown_are_still_possible_without_source():
    for verdict in ['NOT_VULNERABLE', 'NEEDS_MORE_CONTEXT', 'UNRESOLVED']:
        data = result(); data.update(verdict=verdict, source_evidence=[])
        jsonschema.validate(data, bound_schema(packet(), True))


def test_missing_packet_evidence_cannot_force_a_vulnerable_citation():
    data = result()
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, bound_schema(packet(evidence=False), True))
    data.update(verdict='NEEDS_MORE_CONTEXT', source_evidence=[], sink_evidence=[])
    jsonschema.validate(data, bound_schema(packet(evidence=False), True))


def test_complete_objects_and_identity_constraints_survive_alternatives():
    schema = bound_schema(packet(), True)
    assert set(schema) == {'oneOf'}
    for branch in schema['oneOf']:
        assert branch['additionalProperties'] is False
        assert branch['properties']['candidate_id']['const'] == 'case'
        assert branch['properties']['cwe']['const'] == 79
    for key, value in [('candidate_id', 'other'), ('cwe', 89)]:
        data = result();data[key] = value
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(data, schema)


def test_prompt_insertion_preserves_original_packet_and_default_instructions():
    p = packet();original = p.model_dump();base = render_prompt(p)
    revised = decision_prompt(p)
    assert revised.replace(DECISION_CONTRACT + '\n\n', '', 1) == base
    assert revised.index(DECISION_CONTRACT) > revised.index('EVIDENCE:')
    assert p.model_dump() == original
    assert 'EVIDENCE DECISION CONTRACT' not in render_prompt(p)


@pytest.mark.parametrize('cwe', [22, 78, 79, 89])
def test_same_contract_applies_to_all_supported_cwes(cwe):
    p = packet(cwe)
    assert 'fixed seed/test' in decision_prompt(p)
    assert 'hypothetical validation' in decision_prompt(p)
    assert bound_schema(p, True)['oneOf'][0]['properties']['cwe']['const'] == cwe


def test_client_opt_in_uses_the_same_tested_prompt_and_schema():
    import json
    import httpx
    from aisast.verifier.client import VerifierClient
    requests = []

    def handler(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={'choices': [{'message': {'content': json.dumps(result())}}]})

    p = packet()
    client = VerifierClient('http://test/v1', 'model', citation_contract=True,
                            decision_contract=True, transport=httpx.MockTransport(handler))
    client.verify(p)
    assert requests[0]['messages'][1]['content'] == decision_prompt(p)
    assert requests[0]['response_format']['schema'] == bound_schema(p, True)


def test_default_client_retains_original_prompt_and_schema():
    import json
    import httpx
    from aisast.verifier.client import VerifierClient
    requests = []

    def handler(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={'choices': [{'message': {'content': json.dumps(result())}}]})

    p = packet()
    VerifierClient('http://test/v1', 'model', transport=httpx.MockTransport(handler)).verify(p)
    assert requests[0]['messages'][1]['content'] == render_prompt(p)
    assert requests[0]['response_format']['schema'] == bound_schema(p, False)
