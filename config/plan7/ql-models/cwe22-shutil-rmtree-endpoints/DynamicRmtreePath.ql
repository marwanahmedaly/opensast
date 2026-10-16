/**
 * @name Dynamic recursive delete-and-recreate path (CWE-22 suspect)
 * @description Select a dynamic directory deleted with shutil.rmtree and recreated in the same function.
 * @kind problem
 * @problem.severity warning
 * @id aisast/plan7-cwe22-shutil-rmtree-path-suspect
 * @tags security external/cwe/cwe-022
 */
import python
import semmle.python.ApiGraphs

private predicate recreatedInSameScope(Name path) {
  exists(Call creation, Attribute mkdir, Name creationPath |
    creation.getScope() = path.getScope() and
    mkdir = creation.getFunc() and
    mkdir.getName() = "mkdir" and
    creationPath = mkdir.getObject() and
    creationPath.getVariable() = path.getVariable()
  )
  or
  exists(Call creation, Name creationPath |
    creation = API::moduleImport("os").getMember("makedirs").getACall().asExpr() and
    creation.getScope() = path.getScope() and
    creationPath = creation.getArg(0) and
    creationPath.getVariable() = path.getVariable()
  )
}

from API::CallNode invocation, Name path
where
  invocation = API::moduleImport("shutil").getMember("rmtree").getACall() and
  path = invocation.getArg(0).asExpr() and
  recreatedInSameScope(path)
select path,
  "Directory is deleted and recreated using a dynamic path; inspect its origin and allowed directory boundary."
