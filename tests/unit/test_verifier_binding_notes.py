from pathlib import Path
import json
import pytest
from aisast.models import Candidate,EvidenceBlock,EvidencePacket,Location
from aisast.verifier.binding_notes import framework_lines
from aisast.verifier.prompts import render_prompt

FACT='This documented parser reads the current request.'

def packet(cwe=89):
 return EvidencePacket(candidate=Candidate(candidate_id='test',repository_sha='test',rule_id='test',cwe=cwe,title='test',primary_location=Location(file='one.py',line=1)),profile=f'CWE-{cwe}',prompt_version='v1',evidence=[EvidenceBlock(id='EA',file='one.py',start_line=1,end_line=1,code='parser = Parser()'),EvidenceBlock(id='EB',file='two.py',start_line=2,end_line=2,code='parser = Parser()')],framework_facts=[FACT],context_resolution=[{'kind':'request_binding','target':'parser','certainty':'documented_api_binding','fact':FACT,'included':True,'evidence_ids':['EA'],'required_ranges':[{'file':'one.py','start_line':1,'end_line':1}]},{'kind':'request_binding','target':'parser','certainty':'documented_api_binding','fact':FACT,'included':True,'evidence_ids':['EB'],'required_ranges':[{'file':'two.py','start_line':2,'end_line':2}]}])

@pytest.mark.parametrize('cwe',[22,78,79,89])
def test_same_text_different_bindings_keep_own_ids(cwe):
 p=packet(cwe);before=p.model_dump();lines=framework_lines(p)
 assert len(lines)==2
 assert lines[0].startswith('[EA] ') and 'one.py:1-1' in lines[0] and 'EB' not in lines[0]
 assert lines[1].startswith('[EB] ') and 'two.py:2-2' in lines[1] and 'EA' not in lines[1]
 assert p.model_dump()==before

def test_unincluded_binding_not_rendered():
 p=packet();p.context_resolution[1]['included']=False
 assert len(framework_lines(p))==1 and 'EB' not in framework_lines(p)[0]

def test_unknown_ids_filtered_and_duplicates_deduplicated():
 p=packet();p.context_resolution[0]['evidence_ids']+=['foreign','EA'];p.context_resolution.append(dict(p.context_resolution[0]))
 lines=framework_lines(p)
 assert len(lines)==2 and lines[0].startswith('[EA] ') and 'foreign' not in '\n'.join(lines)

def test_generic_uncertainty_grouping_preserved():
 p=packet()
 for r in p.context_resolution:r['certainty']='syntactic_possible'
 assert framework_lines(p)==['[EA, EB] '+FACT]

def test_generic_references_not_lost_if_documented_binding_exists():
 p=packet();p.context_resolution[1]['certainty']='syntactic_possible'
 lines=framework_lines(p)
 assert any(line.startswith('[EB] ') for line in lines)
 assert any(line.startswith('[EA] ') for line in lines)

def test_missing_anchor_does_not_crash_or_invent_location():
 p=packet();p.context_resolution[0]['required_ranges']=[{}]
 assert 'context supplied binding.' in framework_lines(p)[0]

def test_actual_sql_prompt_matches_measured_scoped_variant():
 root=Path(__file__).resolve().parents[2];out=root/'runs/verifier-binding-scope-20261006'
 if not (out/'scoped-request.json').exists():pytest.skip('local measured run artifact unavailable')
 p=EvidencePacket.model_validate_json((out/'packet.json').read_text())
 expected=json.loads((out/'scoped-request.json').read_text())['messages'][1]['content']
 assert render_prompt(p)==expected

def test_historical_unstable_requests_unchanged():
 root=Path(__file__).resolve().parents[2];out=root/'runs/verifier-repeatability-20261006/inputs'
 if not out.exists():pytest.skip('local measured run artifacts unavailable')
 for key in ['R01','F25','F35']:
  p=EvidencePacket.model_validate_json((out/key/'packet.json').read_text());request=json.loads((out/key/'request.json').read_text())
  assert render_prompt(p)==request['messages'][1]['content']
