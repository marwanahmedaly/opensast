/**
 * @name Dynamic FileResponse path (CWE-22 suspect)
 * @description Select dynamic local paths served through Starlette or FastAPI FileResponse for origin and containment review.
 * @kind problem
 * @problem.severity warning
 * @id aisast/plan7-cwe22-fileresponse-path-endpoint-suspect
 * @tags security external/cwe/cwe-022
 */
import python
import semmle.python.ApiGraphs

private predicate fileResponseCall(Call call) {
  exists(API::CallNode invocation |
    (
      invocation = API::moduleImport("starlette.responses").getMember("FileResponse").getACall()
      or
      invocation = API::moduleImport("fastapi.responses").getMember("FileResponse").getACall()
    ) and
    call = invocation.asExpr()
  )
  or
  exists(Import declaration, Alias imported, Name target |
    imported = declaration.getAName() and
    imported.getValue().(ImportMember).getImportedModuleName() in
      ["starlette.responses.FileResponse", "fastapi.responses.FileResponse"] and
    target = call.getFunc() and
    target.getVariable() = imported.getAsname().(Name).getVariable()
  )
}

from Call call, Expr path
where
  fileResponseCall(call) and
  (
    path = call.getArg(0)
    or
    exists(Keyword keyword |
      keyword = call.getAKeyword() and
      keyword.getArg() = "path" and
      path = keyword.getValue()
    )
  ) and
  not path instanceof StringLiteral
select path,
  "Dynamic FileResponse path is served as a local file; inspect its origin and containment."
