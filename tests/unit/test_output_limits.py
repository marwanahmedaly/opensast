import json
import httpx
import pytest
from aisast.models import Candidate, EvidenceBlock, EvidencePacket, Location
from aisast.verifier.client import VerifierClient
from aisast.verifier.contracts import bound_schema
from aisast.verifier.schemas import VerificationError


def packet():
 return EvidencePacket(candidate=Candidate(candidate_id='C',repository_sha='r',rule_id='r',cwe=89,title='t',primary_location=Location(file='x.py',line=1)),profile='CWE-89',prompt_version='v1',evidence=[EvidenceBlock(id='E1',file='x.py',start_line=1,end_line=1,code='x')])


def response(finish='stop',tokens=20):
 return {'choices':[{'finish_reason':finish,'message':{'content':json.dumps({'candidate_id':'C','cwe':89,'verdict':'UNRESOLVED','source_evidence':[],'sink_evidence':[],'sanitizer_evidence':[],'explanation':'Missing caller','missing_symbols':['Caller: f']})}}], 'usage':{'prompt_tokens':tokens,'completion_tokens':400}}


def transport(requests, window=16384, finish_first='length', prompt_tokens=20):
 def handler(req):
  if req.url.path=='/apply-template':return httpx.Response(200,json={'prompt':'wrapped'})
  if req.url.path=='/tokenize':return httpx.Response(200,json={'tokens':[0]*20})
  requests.append(json.loads(req.content));return httpx.Response(200,json=response(finish_first if len(requests)==1 else 'stop',prompt_tokens))
 return httpx.MockTransport(handler)


def test_json_schema_bounds_volume_without_rejecting_empty_fields():
 for citation in [False,True]:
  s=bound_schema(packet(),citation)
  for arm in s.get('oneOf',[s]):
   for field in ['source_evidence','sink_evidence','sanitizer_evidence']:assert arm['properties'][field]['maxItems']==3
   assert arm['properties']['explanation']['maxLength']==384
   assert arm['properties']['missing_symbols']['maxItems']==3
   assert arm['properties']['missing_symbols']['items']['maxLength']==96
  if not citation:assert 'minItems' not in s['properties']['sanitizer_evidence']


def test_length_finish_retries_even_when_json_parses():
 requests=[]
 client=VerifierClient('http://test/v1','qwen',max_tokens=400,context_window=16384,transport=transport(requests))
 result,trace=client.verify(packet())
 assert [r['max_tokens'] for r in requests]==[400,800]
 assert requests[0]['messages']==requests[1]['messages']
 assert trace['attempt_log'][0]['finish_reason']=='length'
 assert trace['attempt_log'][0]['retry_max_tokens']==800
 assert trace['attempt']==2


def test_retry_cannot_exceed_measured_context_space():
 requests=[]
 client=VerifierClient('http://test/v1','qwen',max_tokens=400,context_window=1024,transport=transport(requests,prompt_tokens=550))
 client.verify(packet())
 assert [r['max_tokens'] for r in requests]==[400,410]


def test_unknown_window_does_not_invent_larger_budget():
 requests=[]
 client=VerifierClient('http://test/v1','qwen',max_tokens=400,transport=transport(requests))
 client.verify(packet())
 assert [r['max_tokens'] for r in requests]==[400,400]


def test_persistent_cutoff_is_operational_error_with_raw_response():
 requests=[]
 def handler(req):
  requests.append(json.loads(req.content));return httpx.Response(200,json=response('length'))
 client=VerifierClient('http://test/v1','qwen',max_tokens=400,transport=httpx.MockTransport(handler))
 with pytest.raises(VerificationError) as e:client.verify(packet())
 assert len(e.value.attempt_log)==2
 assert all(a['finish_reason']=='length' and a['raw_response'] for a in e.value.attempt_log)
