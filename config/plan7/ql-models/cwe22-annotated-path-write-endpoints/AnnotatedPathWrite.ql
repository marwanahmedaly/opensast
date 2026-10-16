/**
 * @name Write through a typed pathlib.Path receiver (CWE-22 suspect)
 * @description Select a write_text or write_bytes call on a pathlib.Path-annotated field or parameter, or a CodeQL-modeled Path receiver.
 * @kind problem
 * @problem.severity warning
 * @id aisast/plan7-cwe22-annotated-path-write-endpoint-suspect
 * @tags security external/cwe/cwe-022
 */
import python
import semmle.python.ApiGraphs

private predicate pathlibPathAnnotation(Expr annotation) {
  annotation.(Attribute).getObject().(Name).getId() = "pathlib" and
  annotation.(Attribute).getName() = "Path"
  or
  exists(Import declaration, Alias name |
    name = declaration.getAName() and
    name.getValue().(ImportMember).getImportedModuleName() = "pathlib.Path" and
    annotation.(Name).getVariable() = name.getAsname().(Name).getVariable()
  )
}

private predicate annotatedPathField(string field) {
  exists(AnnAssign declaration, Attribute target |
    target = declaration.getTarget() and
    target.getObject().(Name).getId() = "self" and
    target.getName() = field and
    pathlibPathAnnotation(declaration.getAnnotation())
  )
}

private predicate annotatedPathParameter(Name receiver) {
  exists(Parameter parameter |
    parameter.getVariable() = receiver.getVariable() and
    pathlibPathAnnotation(parameter.getAnnotation())
  )
}

// A syntactic derivation hint; assignments may be infeasible or overwritten.
// Keep this separate from a proven remote source-to-sink flow.
private predicate possiblePath(Expr expression) {
  annotatedPathParameter(expression.(Name))
  or
  expression.(Attribute).getObject().(Name).getId() = "self" and
  annotatedPathField(expression.(Attribute).getName())
  or
  exists(BinaryExpr division |
    expression = division and division.getOp() instanceof Div and
    possiblePath(division.getLeft())
  )
  or
  exists(AssignStmt assignment, Name target |
    target = assignment.getATarget() and
    target.getVariable() = expression.(Name).getVariable() and
    possiblePath(assignment.getValue())
  )
}

from Call call, Attribute method, Expr receiver
where
  call.getFunc() = method and
  method.getName() in ["write_text", "write_bytes"] and
  receiver = method.getObject() and
  (
    receiver.(Attribute).getObject().(Name).getId() = "self" and
    annotatedPathField(receiver.(Attribute).getName())
    or
    possiblePath(receiver)
    or
    call = API::moduleImport("pathlib").getMember("Path").getReturn()
      .getMember(method.getName()).getACall().asExpr()
  )
select receiver,
  "Write through a pathlib.Path receiver; inspect the path origin and containment checks."
