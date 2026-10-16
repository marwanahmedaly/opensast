"""Finite receiver bindings with exact proof ranges; no arbitrary method-name fallback."""
from __future__ import annotations
import ast
from dataclasses import dataclass
from aisast.context.framework_bindings import FastAPIBindings

@dataclass
class Receiver:
    definition: object
    instance: bool
    references: list[tuple[object, ast.AST]]
    conditional: bool = False

class ReceiverBindings:
    def __init__(self, index):
        self.index=index
        self.framework=FastAPIBindings(index)
        self.cache={}
        self.method_proofs={}
        self._flask_fields=None
        self._qualified_cache={}
        self._calls_by_scope=None
        self._ends={}

    def end(self, node):
        if id(node) not in self._ends:
            self._ends[id(node)]=self.index.end(node)
        return self._ends[id(node)]

    def qualified(self, expr, scope):
        name=self.index.dotted(expr)
        root,_,rest=name.partition('.')
        key=(id(scope.node),root)
        if key not in self._qualified_cache:
            self._qualified_cache[key]=self.framework.qualified(ast.Name(id=root),scope)
        imported=self._qualified_cache[key]
        return imported+('.'+rest if rest else '') if imported else ''

    def bindings(self, expr, scope):
        """Lexical assignments, stopping at parameters and local writes."""
        name=self.index.dotted(expr)
        if not name:return []
        current=scope
        while current:
            args=getattr(current.node,'args',None)
            if isinstance(expr,ast.Name) and args and any(a.arg==name for a in [*args.posonlyargs,*args.args,*args.kwonlyargs]):
                return []
            before=getattr(expr,'lineno',self.end(current.node)+1) if current is scope else self.end(current.node)+1
            found=self.index.assignments(current,name,before)
            if found:return [(current,n) for n in found]
            current=current.parent
        qualified=self.qualified(expr,scope)
        module,_,symbol=qualified.rpartition('.')
        files=self.index.module_files(module) if module else set()
        if len(files)==1:
            other=self.index.scopes[id(self.index.trees[next(iter(files))])]
            return [(other,n) for n in self.index.assignments(other,symbol,self.end(other.node)+1)]
        return []

    def flask_application(self, expr, scope):
        bindings=self.bindings(expr,scope)
        if len(bindings)!=1:return []
        owner,node=bindings[0]
        if isinstance(node.value,ast.Call) and self.qualified(node.value.func,owner)=='flask.Flask':
            return [(owner,node)]
        return []

    def flask_fields(self):
        if self._flask_fields is None:
            self._flask_fields={}
            for tree in self.index.trees.values():
                for node in ast.walk(tree):
                    if not isinstance(node,(ast.Assign,ast.AnnAssign)) or node.value is None:continue
                    scope=self.index.scopes[id(node)]
                    for target in node.targets if isinstance(node,ast.Assign) else [node.target]:
                        if not isinstance(target,ast.Attribute):continue
                        app=self.flask_application(target.value,scope)
                        if app:self._flask_fields.setdefault(target.attr,[]).append((scope,node,app))
        return self._flask_fields

    def registry(self, expr, scope, seen, depth):
        if not isinstance(expr,ast.Subscript):return []
        bindings=self.bindings(expr.value,scope)
        if len(bindings)!=1:return []
        owner,assignment=bindings[0]
        value=assignment.value
        if not isinstance(value,ast.Dict) or any(k is None or not isinstance(k,ast.Constant) for k in value.keys):return []
        # Mutated registries are not a closed literal map.
        for n in ast.walk(owner.node):
            node_scope=self.index.scopes.get(id(n),owner)
            target=(n.value if isinstance(n,ast.Subscript) and isinstance(n.ctx,(ast.Store,ast.Del))
                    else n.func.value if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) else None)
            if target is not None and any(o is owner and a is assignment for o,a in self.bindings(target,node_scope)):
                return []
        literal=isinstance(expr.slice,ast.Constant)
        result=[]
        for k,v in zip(value.keys,value.values):
            if literal and k.value!=expr.slice.value:continue
            for receiver in self.value(v,owner,seen,depth):
                result.append(Receiver(receiver.definition,receiver.instance,
                    [*receiver.references,(owner,assignment)],receiver.conditional or not literal))
        return result

    def value(self, expr, scope, seen=None, depth=0):
        if expr is None or depth>self.index.max_depth:return []
        seen=set() if seen is None else seen
        key=(id(expr),id(scope.node))
        if key in seen:return []
        seen=seen|{key}
        if isinstance(expr,ast.Name):
            bindings=self.bindings(expr,scope)
            if bindings:
                result=[]
                for owner,n in bindings:
                    for r in self.value(n.value,owner,seen,depth):
                        result.append(Receiver(r.definition,r.instance,[*r.references,(owner,n)],r.conditional or len(bindings)>1))
                return result
            if self.index.imports(scope).get(expr.id) and not self.qualified(expr,scope):return []
            args=getattr(scope.node,'args',None)
            if args and any(a.arg==expr.id for a in [*args.posonlyargs,*args.args,*args.kwonlyargs]):return []
            return [Receiver(d,False,[]) for d in self.index.resolve(expr,scope) if isinstance(d.node,ast.ClassDef)]
        if isinstance(expr,ast.Attribute):
            if self.qualified(expr.value,scope)=='flask.current_app':
                result=[]
                for owner,n,app in self.flask_fields().get(expr.attr,[]):
                    for r in self.value(n.value,owner,seen,depth):
                        result.append(Receiver(r.definition,r.instance,[*r.references,*app,(owner,n)],True))
                return result
            result=[]
            for owner,n in self.bindings(expr,scope):
                for r in self.value(n.value,owner,seen,depth):
                    result.append(Receiver(r.definition,r.instance,[*r.references,(owner,n)],r.conditional))
            if not result:
                result=[Receiver(d,False,[]) for d in self.index.resolve(expr,scope) if isinstance(d.node,ast.ClassDef)]
            return result
        if isinstance(expr,ast.Subscript):return self.registry(expr,scope,seen,depth)
        if isinstance(expr,ast.Call):
            if isinstance(expr.func,ast.Subscript):
                return [Receiver(r.definition,True,[*r.references,(scope,expr)],r.conditional)
                        for r in self.registry(expr.func,scope,seen,depth)]
            root=self.index.dotted(expr.func).partition('.')[0]
            if self.index.imports(scope).get(root) and not self.qualified(expr.func,scope):
                return []
            if isinstance(expr.func,ast.Name):
                if self.bindings(expr.func,scope):return []
                current=scope
                while current:
                    args=getattr(current.node,'args',None)
                    if args and any(a.arg==root for a in [*args.posonlyargs,*args.args,*args.kwonlyargs,
                                                          *([args.vararg] if args.vararg else []),
                                                          *([args.kwarg] if args.kwarg else [])]):return []
                    current=current.parent
            result=[]
            for definition in self.index.resolve(expr.func,scope):
                if isinstance(definition.node,ast.ClassDef):
                    result.append(Receiver(definition,True,[(scope,expr)]))
                else:
                    for node in ast.walk(definition.node):
                        if isinstance(node,ast.Return) and self.index.scopes.get(id(node)) is definition:
                            for r in self.value(node.value,definition,seen,depth+1):
                                result.append(Receiver(r.definition,r.instance,[*r.references,(definition,definition.node)],True))
            return result
        return []

    def methods(self, node, scope):
        if not isinstance(node,ast.Attribute) or not self.index.definitions.get(node.attr):return []
        key=(id(node),id(scope.node))
        if key in self.cache:return self.cache[key]
        methods=[];proofs=[]
        for receiver in self.value(node.value,scope):
            for definition in self.index.definitions.get(node.attr,[]):
                if definition.parent is receiver.definition:
                    if definition not in methods:methods.append(definition)
                    proofs.append((definition,receiver))
        self.cache[key]=methods;self.method_proofs[key]=proofs
        return methods

    def proofs(self, node, scope, definition):
        self.methods(node,scope)
        return [r for d,r in self.method_proofs.get((id(node),id(scope.node)),[]) if d is definition]

    def request_bindings(self, scope):
        """Known default reqparse source, with declaration and optional route proof."""
        result=[]
        if self._calls_by_scope is None:
            self._calls_by_scope={}
            for owner,call in self.index.calls:
                self._calls_by_scope.setdefault(id(owner.node),[]).append(call)
        for call in self._calls_by_scope.get(id(scope.node),[]):
            if not isinstance(call.func,ast.Attribute) or call.func.attr!='parse_args':continue
            if call.args or any(kw.arg not in {'req','strict'} or kw.arg=='req' and not
                                (isinstance(kw.value,ast.Constant) and kw.value.value is None)
                                for kw in call.keywords):continue
            if self.bindings(call.func,scope):continue  # Locally replaced parser method.
            bindings=self.bindings(call.func.value,scope)
            if len(bindings)!=1:continue
            declaration_scope,declaration=bindings[0]
            constructor=declaration.value
            if not isinstance(constructor,ast.Call) or constructor.args:continue
            if self.qualified(constructor.func,declaration_scope)!='flask_restful.reqparse.RequestParser':continue
            if any(kw.arg not in {'bundle_errors','trim'} for kw in constructor.keywords):continue
            name=self.index.dotted(call.func.value)
            refs=[(declaration_scope,declaration),(scope,call)]
            for other,node in self.index.calls:
                if other in (scope,declaration_scope) and isinstance(node.func,ast.Attribute) and node.func.attr=='add_argument' and self.index.dotted(node.func.value)==name:
                    refs.append((other,node))
            current=declaration_scope
            while current:
                refs.extend((current,n) for n in self.index._scope_imports[id(current.node)])
                current=current.parent
            parent=scope.parent
            if parent and isinstance(parent.node,ast.ClassDef) and any(self.qualified(base,parent)=='flask_restful.Resource' for base in parent.node.bases):
                refs.append((parent,ast.Pass(lineno=self.index.start(parent.node),end_lineno=max(self.index.start(parent.node),parent.node.body[0].lineno-1))))
                for registration_scope,registration in self.index.calls:
                    if not isinstance(registration.func,ast.Attribute) or registration.func.attr!='add_resource' or not registration.args:continue
                    if not any(d is parent for d in self.index.resolve(registration.args[0],registration_scope)):continue
                    api=self.bindings(registration.func.value,registration_scope)
                    if len(api)!=1:continue
                    api_scope,api_assignment=api[0]
                    if not isinstance(api_assignment.value,ast.Call) or self.qualified(api_assignment.value.func,api_scope)!='flask_restful.Api':continue
                    refs.extend([(registration_scope,registration),(api_scope,api_assignment)])
                    if api_assignment.value.args:refs.extend(self.flask_application(api_assignment.value.args[0],api_scope))
                    current=api_scope
                    while current:
                        refs.extend((current,n) for n in self.index._scope_imports[id(current.node)])
                        current=current.parent
            fact=('The supplied Flask-RESTful RequestParser.parse_args call uses the default Flask request, '
                  'not a caller-provided req object. Argument declarations describe accepted values and '
                  'locations; required=True and str conversion alone do not exclude injection syntax. '
                  'Check custom types, validators and the displayed registration/configuration.')
            result.append((name,fact,refs))
        return result
