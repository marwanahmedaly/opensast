/**
 * @name Dynamic HTMLResponse content (CWE-79 suspect)
 * @description Select dynamic HTML content passed to a Starlette or FastAPI HTMLResponse constructor for origin and escaping review.
 * @kind problem
 * @problem.severity warning
 * @id aisast/plan7-cwe79-htmlresponse-content-endpoint-suspect
 * @tags security external/cwe/cwe-079
 */
import python
import semmle.python.ApiGraphs

private predicate htmlResponseCall(Call call) {
  exists(API::CallNode invocation |
    (
      invocation = API::moduleImport("starlette.responses").getMember("HTMLResponse").getACall()
      or
      invocation = API::moduleImport("fastapi.responses").getMember("HTMLResponse").getACall()
    ) and
    call = invocation.asExpr()
  )
  or
  exists(Import declaration, Alias imported, Name target |
    imported = declaration.getAName() and
    imported.getValue().(ImportMember).getImportedModuleName() in
      ["starlette.responses.HTMLResponse", "fastapi.responses.HTMLResponse"] and
    target = call.getFunc() and
    target.getVariable() = imported.getAsname().(Name).getVariable()
  )
}

from Call call, Expr content
where
  htmlResponseCall(call) and
  (
    content = call.getArg(0)
    or
    exists(Keyword keyword |
      keyword = call.getAKeyword() and
      keyword.getArg() = "content" and
      content = keyword.getValue()
    )
  ) and
  not content instanceof StringLiteral
select content,
  "Dynamic HTMLResponse content reaches an HTML response; inspect its origin and escaping."
