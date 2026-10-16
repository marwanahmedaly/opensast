/**
 * @name Dynamic file permission path (CWE-22 suspect)
 * @description Select a dynamic path whose permissions are changed by pathlib or os.chmod.
 * @kind problem
 * @problem.severity warning
 * @id aisast/plan7-cwe22-dynamic-chmod-path-suspect
 * @tags security external/cwe/cwe-022
 */
import python
import semmle.python.ApiGraphs

private predicate importedPathClass(Name name) {
  exists(Import declaration, Alias imported |
    imported = declaration.getAName() and
    imported.getValue().(ImportMember).getImportedModuleName() = "pathlib.Path" and
    name.getVariable() = imported.getAsname().(Name).getVariable()
  )
}

private predicate hasDynamicPathPart(Expr path) {
  exists(Name value |
    value = path.(Name) or value = path.getASubExpression+() and
    not importedPathClass(value)
  )
}

private predicate isPathExpression(Expr expression) {
  expression = API::moduleImport("pathlib").getMember("Path").getACall().asExpr()
  or
  exists(BinaryExpr operation |
    expression = operation and
    operation.getOp() instanceof Div and
    isPathExpression(operation.getLeft())
  )
  or
  exists(Call call, Attribute method |
    expression = call and
    method = call.getFunc() and
    method.getName() = "joinpath" and
    isPathExpression(method.getObject())
  )
  or
  exists(Name reference, Assign assignment, Name target |
    expression = reference and
    reference.getVariable() = target.getVariable() and
    target = assignment.getATarget().(Name) and
    isPathExpression(assignment.getValue())
  )
}

from Call chmod, Expr path, Attribute method
where
  (
    chmod.getFunc() = method and
    method.getName() = "chmod" and
    path = method.getObject() and
    isPathExpression(path) and
    hasDynamicPathPart(path)
  )
  or
  (
    chmod = API::moduleImport("os").getMember("chmod").getACall().asExpr() and
    path = chmod.getArg(0) and
    not path instanceof StringLiteral
  )
select path,
  "Permissions are changed on a dynamic path; inspect archive/input origin and verify it remains inside the intended directory."
