import httpx
import pytest
from aisast.models import Candidate, EvidenceBlock, EvidencePacket, Location
from aisast.verifier.budget import fit_packet
from aisast.verifier.client import VerifierClient
from aisast.verifier.prompts import render_prompt
from aisast.verifier.schemas import VerificationError


def packet():
    c=Candidate(candidate_id='c',repository_sha='r',rule_id='r',cwe=89,title='t',
                primary_location=Location(file='app.py',line=2),source=Location(file='app.py',line=1),sink=Location(file='app.py',line=2))
    es=[EvidenceBlock(id='source',file='app.py',start_line=1,end_line=1,code='value = request.args["q"]',kind='source'),
        EvidenceBlock(id='sink',file='app.py',start_line=2,end_line=2,code='db.execute(value)',kind='sink'),
        EvidenceBlock(id='extra',file='helpers.py',start_line=1,end_line=2,code='x'*12000,kind='relation')]
    return EvidencePacket(candidate=c,evidence=es,profile='cwe_89',prompt_version='v1')


def test_complete_prompt_fit_keeps_anchors_and_logs_whole_omissions():
    p=packet();original=p.model_dump_json();limit=len(render_prompt(p))-5000
    fitted=fit_packet(p,len,limit)
    assert len(render_prompt(fitted))<=limit
    assert {e.id for e in fitted.evidence}=={'source','sink'}
    assert fitted.context_truncated
    assert fitted.context_resolution[-1]['omitted_blocks'][0]['id']=='extra'
    assert p.model_dump_json()==original


def test_already_fitting_prompt_does_not_change_rendering():
    p=packet();fitted=fit_packet(p,len,len(render_prompt(p)))
    assert render_prompt(p)==render_prompt(fitted)


def test_removed_fact_and_call_contract_cannot_keep_stale_evidence_ids():
    p=packet();p.framework_facts=['framework input fact']
    p.context_resolution=[{'kind':'input_binding','fact':p.framework_facts[0], 'included':True,'evidence_ids':['extra'],
        'required_ranges':[{'file':'helpers.py','start_line':1,'end_line':2}]},
        {'kind':'call_argument_contract','included':True,'evidence_ids':['extra'],'caller':'a','callee':'b','caller_file':'helpers.py','callee_file':'helpers.py','parameter':'x','argument':'int(x)',
         'required_ranges':[{'file':'helpers.py','start_line':1,'end_line':2}]}]
    fitted=fit_packet(p,len,len(render_prompt(p))-5000)
    assert not fitted.framework_facts
    assert all(not row['included'] and not row['evidence_ids'] for row in fitted.context_resolution[:2])
    assert 'CALL ARGUMENT RELATIONSHIPS' not in render_prompt(fitted)


def test_anchor_or_instruction_overflow_is_an_explicit_error():
    with pytest.raises(VerificationError,match='anchors'):
        fit_packet(packet(),lambda _: 100,99)
    with pytest.raises(VerificationError,match='no prompt budget'):
        fit_packet(packet(),len,0)


def test_local_tokenizer_counts_chat_template_and_reserves_completion():
    requests=[]
    def handle(request):
        requests.append(request.url.path)
        if request.url.path=='/apply-template':
            return httpx.Response(200,json={'prompt':'chat-template-prefix'})
        if request.url.path=='/tokenize':
            assert b'chat-template-prefix' in request.content
            return httpx.Response(200,json={'tokens':list(range(100))})
        raise AssertionError(request.url)
    client=VerifierClient('http://local/v1','m',max_tokens=400,context_window=10240,transport=httpx.MockTransport(handle))
    fitted=client.prepare_packet(packet())
    assert fitted.evidence==packet().evidence
    assert requests==['/apply-template','/tokenize']


def test_tokenizer_failure_does_not_silently_submit_oversized_prompt():
    client=VerifierClient('http://local/v1','m',context_window=10240,
        transport=httpx.MockTransport(lambda _:httpx.Response(404)))
    with pytest.raises(VerificationError,match='measurement failed'):
        client.prepare_packet(packet())
