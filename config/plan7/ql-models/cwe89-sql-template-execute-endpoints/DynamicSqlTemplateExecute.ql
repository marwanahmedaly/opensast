/**
 * @name Dynamic SQL template passed to execute (CWE-89 suspect)
 * @description Select a SQL-shaped expression with a dynamic value at the first argument of an execute call for review.
 * @kind problem
 * @problem.severity warning
 * @id aisast/plan7-cwe89-sql-template-execute-endpoint-suspect
 * @tags security external/cwe/cwe-089
 */
import python
import semmle.python.ApiGraphs
import semmle.python.Concepts
import semmle.python.frameworks.PEP249

private predicate startsWithSqlVerb(StringLiteral fragment) {
  fragment.getText().toUpperCase().regexpMatch(
    "\\s*(SELECT|INSERT|UPDATE|DELETE|REPLACE|WITH|CREATE|ALTER|DROP|PRAGMA|DESCRIBE)\\b.*"
  )
}

private predicate storedSqliteCursorField(string field) {
  exists(AssignStmt assignment, Attribute target, Call cursorCall |
    target = assignment.getATarget() and
    target.getObject().(Name).getId() = "self" and
    target.getName() = field and
    assignment.getValue() = cursorCall and
    cursorCall = API::moduleImport("sqlite3").getMember("connect").getReturn()
      .getMember("cursor").getACall().asExpr()
  )
}

private predicate knownDatabaseExecution(Expr sql, Attribute method) {
  exists(SqlExecution execution | execution.getSql().asExpr() = sql)
  or
  exists(Attribute receiver |
    receiver = method.getObject() and
    receiver.getObject().(Name).getId() = "self" and
    storedSqliteCursorField(receiver.getName())
  )
}

from Call call, Attribute method, Expr sql, StringLiteral fragment, Name dynamicPart
where
  call.getFunc() = method and
  method.getName() in ["execute", "executemany", "executescript"] and
  sql = call.getArg(0) and
  knownDatabaseExecution(sql, method) and
  not sql instanceof StringLiteral and
  fragment = sql.getASubExpression*() and
  startsWithSqlVerb(fragment) and
  dynamicPart = sql.getASubExpression+()
select sql,
  "Dynamic SQL text is supplied to an execute-style call; inspect the receiver, value, and callers."
