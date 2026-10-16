/**
 * @name Dynamic Django ORM keyword expansion (CWE-89 suspect)
 * @description Track project function parameters into dynamically expanded keyword mappings passed to Django ORM filter construction for SQL review.
 * @kind path-problem
 * @problem.severity warning
 * @id aisast/plan7-cwe89-django-expanded-orm-kwargs-suspect
 * @tags security external/cwe/cwe-089
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

private predicate isImportedDjangoQ(Call call) {
  exists(Import declaration, Alias imported, ImportMember importedName, Name target |
    imported = declaration.getAName() and
    importedName = imported.getValue() and
    importedName.getImportedModuleName() in [
      "django.db.models.Q", "django.db.models.query_utils.Q"
    ] and
    target = call.getFunc() and
    target.getLocation().getFile() = importedName.getLocation().getFile() and
    (
      target.getId() = importedName.getName()
      or
      target.getId() = imported.getAsname().(Name).getId()
    )
  )
}

private predicate mappingMayContainCallerKeys(Expr values) {
  not values instanceof Dict
  or
  exists(Dict mapping, Expr key |
    mapping = values and
    key = mapping.getAKey() and
    not key instanceof StringLiteral
  )
  or
  exists(Dict mapping, DictUnpacking expanded |
    mapping = values and
    expanded = mapping.getAnItem()
  )
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof DataFlow::ExtractedParameterNode
  }

  predicate isSink(DataFlow::Node sink) {
    exists(Call call, DictUnpacking unpacking, Expr values |
      isImportedDjangoQ(call) and
      unpacking = call.getANamedArg() and
      values = unpacking.getValue() and
      mappingMayContainCallerKeys(values) and
      sink.asExpr() = values
    )
  }
}

module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "A function parameter may reach a dynamic mapping expanded into Django Q; inspect whether an untrusted mapping can set SQL connector or negation options."
