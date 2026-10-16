import tempfile, unittest
from pathlib import Path
from aisast.context.relationships import RepositoryRelationships

def index(files):
 temp=tempfile.TemporaryDirectory();root=Path(temp.name)
 for name,text in files.items():
  p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
 r=RepositoryRelationships(root);r.build();b=r.receiver_bindings
 return temp,r,b

class ReceiverTests(unittest.TestCase):
 def result(self,files,call):
  temp,r,b=index(files);self.addCleanup(temp.cleanup)
  scope,node=next((scope,node) for scope,node in r.calls if r.dotted(node.func)==call)
  return r,b,scope,node,b.methods(node.func,scope)
 def test_local_constructor_receiver(self):
  r,b,scope,node,methods=self.result({'app.py':'class Writer:\n def send(self,x): return x\ndef view(x):\n service=Writer()\n return service.send(x)\n'},'service.send')
  self.assertEqual([m.parent.name for m in methods],['Writer'])
  self.assertTrue(b.proofs(node.func,scope,methods[0])[0].instance)
 def test_factory_registry_and_unrelated_method(self):
  files={'services.py':'class One:\n def send(self,x): return x\nclass Two:\n def send(self,x): return x\nclass Unrelated:\n def send(self,x): return x\n', 'app.py':'from services import One, Two\nMAP={"one":One,"two":Two}\ndef factory(key): return MAP[key]()\ndef view(x):\n service=factory(x)\n return service.send(x)\n'}
  r,b,scope,node,methods=self.result(files,'service.send')
  self.assertEqual({m.parent.name for m in methods},{'One','Two'})
  self.assertTrue(all(b.proofs(node.func,scope,m)[0].conditional for m in methods))
 def test_literal_registry_selection(self):
  r,b,scope,node,methods=self.result({'app.py':'class One:\n def send(self,x): return x\nclass Two:\n def send(self,x): return x\nMAP={"one":One,"two":Two}\ndef view(x):\n service=MAP["one"]()\n return service.send(x)\n'},'service.send')
  self.assertEqual([m.parent.name for m in methods],['One'])
 def test_registry_mutation_is_not_closed(self):
  r,b,scope,node,methods=self.result({'app.py':'class One:\n def send(self,x): return x\nMAP={"one":One}\nMAP.update(dynamic)\ndef view(x):\n service=MAP[x]()\n return service.send(x)\n'},'service.send')
  self.assertEqual(methods,[])
 def test_flask_proxy_attribute_binding(self):
  files={'app.py':'from flask import Flask, current_app as active\nclass Service:\n def send(self,x): return x\ndef factory(): return Service()\ndef initialize():\n app=Flask(__name__)\n app.mailer=factory()\n return app\ndef view(x): return active.mailer.send(x)\n'}
  r,b,scope,node,methods=self.result(files,'active.mailer.send')
  self.assertEqual([m.parent.name for m in methods],['Service'])
  self.assertTrue(b.proofs(node.func,scope,methods[0])[0].conditional)
 def test_shadowed_flask_proxy_not_bound(self):
  files={'app.py':'from flask import Flask, current_app\nclass Service:\n def send(self,x): return x\ndef initialize():\n app=Flask(__name__)\n app.mailer=Service()\ndef view(current_app,x): return current_app.mailer.send(x)\n'}
  self.assertEqual(self.result(files,'current_app.mailer.send')[-1],[])
 def test_unknown_receiver_no_method_name_fallback(self):
  self.assertEqual(self.result({'app.py':'class Service:\n def send(self,x): return x\ndef view(other,x): return other.send(x)\n'},'other.send')[-1],[])
 def test_unbound_class_receiver(self):
  r,b,scope,node,methods=self.result({'app.py':'class Service:\n def send(self,x): return x\ndef view(instance,x): return Service.send(instance,x)\n'},'Service.send')
  self.assertFalse(b.proofs(node.func,scope,methods[0])[0].instance)
 def test_registry_cycle_terminates(self):
  self.assertEqual(self.result({'app.py':'def factory(): return factory()\ndef view(x):\n service=factory()\n return service.send(x)\n'},'service.send')[-1],[])
 def test_registry_mutated_from_function_is_not_closed(self):
  files={'app.py':'class Service:\n def send(self,x): return x\nMAP={"service":Service}\ndef change(x): MAP.update(x)\ndef view(x):\n service=MAP[x]()\n return service.send(x)\n'}
  self.assertEqual(self.result(files,'service.send')[-1],[])
 def test_multiple_flask_apps_keep_possible_receivers(self):
  files={'app.py':'from flask import Flask, current_app\nclass One:\n def send(self,x): return x\nclass Two:\n def send(self,x): return x\ndef first():\n app=Flask(__name__)\n app.worker=One()\ndef second():\n app=Flask(__name__)\n app.worker=Two()\ndef view(x): return current_app.worker.send(x)\n'}
  r,b,scope,node,methods=self.result(files,'current_app.worker.send')
  self.assertEqual({m.parent.name for m in methods},{'One','Two'})
  self.assertTrue(all(p.conditional for m in methods for p in b.proofs(node.func,scope,m)))

from aisast.context.context_builder import ContextBuilder
from aisast.models import Candidate, Location

def packet(root, line):
 return ContextBuilder(root).packet(Candidate(candidate_id='test',repository_sha='test',rule_id='test',
     cwe=89,title='test',primary_location=Location(file='app.py',line=line)))

def test_bound_instance_method_maps_argument(tmp_path):
 (tmp_path/'app.py').write_text('from flask import request\nclass Service:\n def run(self,query):\n  return db.execute(query)\ndef endpoint():\n service=Service()\n return service.run(request.args["query"])\n')
 p=packet(tmp_path,4)
 assert any('request.args["query"]' in e.code for e in p.evidence)
 assert any(r.get('parameter')=='query' and r.get('argument')=='request.args[\'query\']' for r in p.context_resolution)

def test_unbound_method_does_not_shift_instance(tmp_path):
 (tmp_path/'app.py').write_text('from flask import request\nclass Service:\n def run(self,query):\n  return db.execute(query)\ndef endpoint():\n return Service.run(object(),request.args["query"])\n')
 p=packet(tmp_path,4)
 assert any(r.get('parameter')=='query' and r.get('argument')=='request.args[\'query\']' for r in p.context_resolution)

def test_static_method_has_no_receiver_offset(tmp_path):
 (tmp_path/'app.py').write_text('from flask import request\nclass Service:\n @staticmethod\n def run(query):\n  return db.execute(query)\ndef endpoint():\n service=Service()\n return service.run(request.args["query"])\n')
 p=packet(tmp_path,5)
 assert any(r.get('parameter')=='query' and r.get('argument')=='request.args[\'query\']' for r in p.context_resolution)

def test_reqparse_fact_has_declaration_evidence(tmp_path):
 (tmp_path/'app.py').write_text('from flask_restful import reqparse\ndef endpoint():\n parser=reqparse.RequestParser()\n parser.add_argument("q",required=True,type=str)\n args=parser.parse_args()\n return db.execute(args["q"])\n')
 p=packet(tmp_path,6)
 rows=[r for r in p.context_resolution if r['kind']=='flask_restful_request_binding']
 assert rows and rows[0]['included'] and rows[0]['evidence_ids']
 assert any('default Flask request' in f for f in p.framework_facts)
 small=ContextBuilder(tmp_path,max_chars=50).packet(p.candidate)
 assert not any('default Flask request' in f for f in small.framework_facts)

def test_custom_req_object_has_no_request_fact(tmp_path):
 (tmp_path/'app.py').write_text('from flask_restful import reqparse\ndef helper(fake):\n parser=reqparse.RequestParser()\n args=parser.parse_args(req=fake)\n return db.execute(args["q"])\n')
 assert not any('default Flask request' in f for f in packet(tmp_path,5).framework_facts)

def test_shadowed_reqparse_has_no_fact(tmp_path):
 (tmp_path/'app.py').write_text('from flask_restful import reqparse\ndef helper(reqparse):\n parser=reqparse.RequestParser()\n args=parser.parse_args()\n return db.execute(args["q"])\n')
 assert not any('default Flask request' in f for f in packet(tmp_path,5).framework_facts)

def test_custom_argument_class_has_no_default_fact(tmp_path):
 (tmp_path/'app.py').write_text('from flask_restful import reqparse\ndef helper():\n parser=reqparse.RequestParser(argument_class=Custom)\n args=parser.parse_args()\n return db.execute(args["q"])\n')
 assert not any('default Flask request' in f for f in packet(tmp_path,5).framework_facts)

def test_reqparse_replaced_method_has_no_request_fact(tmp_path):
 (tmp_path/'app.py').write_text('from flask_restful import reqparse\ndef endpoint():\n parser=reqparse.RequestParser()\n parser.parse_args=lambda: {"query":"fixed"}\n args=parser.parse_args()\n return db.execute(args["query"])\n')
 p=packet(tmp_path,7)
 assert not any('default Flask request' in f for f in p.framework_facts)

def test_assignment_index_preserves_lexical_order_and_before(tmp_path):
 import ast
 (tmp_path/'app.py').write_text('x=1\nx=2\ndef endpoint(x):\n y=3\n y=4\n return y\n')
 r=RepositoryRelationships(tmp_path);r.build()
 module=r.scopes[id(r.trees['app.py'])]
 function=next(s for s in r.definitions['endpoint'])
 assert [n.lineno for n in r.assignments(module,'x',99)]==[2,1]
 assert [n.lineno for n in r.assignments(module,'x',2)]==[1]
 assert r.assignments(module,'y',99)==[]
 assert [n.lineno for n in r.assignments(function,'y',5)]==[4]
 assert r.end(ast.Pass(lineno=1,end_lineno=None))==1

def test_shadowed_constructor_parameter_not_bound():
 temp,r,b=index({'app.py':'class Service:\n def send(self,x): return x\ndef endpoint(Service,x):\n service=Service()\n return service.send(x)\n'})
 try:
  scope,call=next((s,c) for s,c in r.calls if r.dotted(c.func)=='service.send')
  assert b.methods(call.func,scope)==[]
 finally:temp.cleanup()

def test_shadowed_imported_constructor_not_bound():
 temp,r,b=index({'service.py':'class Service:\n def send(self,x): return x\n','app.py':'from service import Service\ndef endpoint(x):\n Service=x\n service=Service()\n return service.send(x)\n'})
 try:
  scope,call=next((s,c) for s,c in r.calls if r.dotted(c.func)=='service.send')
  assert b.methods(call.func,scope)==[]
 finally:temp.cleanup()
