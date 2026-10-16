/**
 * @name Dynamic HTML written to a file (CWE-79 suspect)
 * @description Select HTML-shaped dynamic text passed to a write call on a file opened for writing.
 * @kind problem
 * @problem.severity warning
 * @id aisast/plan7-cwe79-dynamic-html-file-write-endpoint-suspect
 * @tags security external/cwe/cwe-079
 */
import python
import semmle.python.ApiGraphs

private predicate writeMode(Call openCall) {
  openCall = API::builtin("open").getACall().asExpr() and
  (
    openCall.getArg(1).(StringLiteral).getText().regexpMatch("(w|a|x)[bt+]*")
    or
    exists(Keyword keyword |
      keyword = openCall.getAKeyword() and keyword.getArg() = "mode" and
      keyword.getValue().(StringLiteral).getText().regexpMatch("(w|a|x)[bt+]*")
    )
  )
}

private predicate openedFileReceiver(Expr receiver) {
  exists(AssignStmt assignment, Call openCall, Name target |
    assignment.getValue() = openCall and writeMode(openCall) and
    target = assignment.getATarget() and
    receiver.(Name).getVariable() = target.getVariable()
  )
  or
  exists(With withStmt, Call openCall, Name target |
    withStmt.getContextExpr() = openCall and writeMode(openCall) and
    target = withStmt.getOptionalVars() and
    receiver.(Name).getVariable() = target.getVariable()
  )
  or
  exists(AssignStmt assignment, Call openCall, Attribute target, Attribute field |
    assignment.getValue() = openCall and writeMode(openCall) and
    target = assignment.getATarget() and
    target.getObject().(Name).getId() = "self" and
    field = receiver and field.getObject().(Name).getId() = "self" and
    field.getName() = target.getName() and
    assignment.getScope().getEnclosingScope() = field.getScope().getEnclosingScope() and
    assignment.getScope().getEnclosingScope() instanceof Class
  )
}

from Call call, Attribute method, Expr content, StringLiteral fragment, Name dynamicPart
where
  call.getFunc() = method and method.getName() = "write" and
  openedFileReceiver(method.getObject()) and
  content = call.getArg(0) and
  not content instanceof StringLiteral and
  fragment = content.getASubExpression*() and
  fragment.getText().regexpMatch("[\\s\\S]*<[/]?[A-Za-z][^>]*>[\\s\\S]*") and
  dynamicPart = content.getASubExpression+()
select content,
  "Dynamic HTML is written to a file; inspect whether the embedded values are escaped before output."
