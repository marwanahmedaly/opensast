/**
 * @name Dynamic SQLAlchemy text fragment (CWE-89 suspect)
 * @description Select a directly formatted expression passed to SQLAlchemy text for SQL execution review.
 * @kind problem
 * @problem.severity warning
 * @id aisast/plan7-cwe89-sqlalchemy-dynamic-text-endpoint-suspect
 * @tags security external/cwe/cwe-089
 */
import python
import semmle.python.ApiGraphs

private predicate directlyFormatted(Expr sql) {
  sql instanceof Fstring
  or
  exists(Call formatCall, Attribute formatMethod, StringLiteral template |
    sql = formatCall and
    formatCall.getFunc() = formatMethod and
    formatMethod.getName() = "format" and
    template = formatMethod.getObject() and
    exists(Expr value | value = formatCall.getAnArg() and not value instanceof StringLiteral)
  )
  or
  exists(BinaryExpr binary, StringLiteral template, Name value |
    sql = binary and
    template = binary.getASubExpression+() and
    value = binary.getASubExpression+()
  )
}

private predicate importedTextCall(Call call) {
  exists(Import declaration, Alias imported, Name target |
    imported = declaration.getAName() and
    imported.getValue().(ImportMember).getImportedModuleName() in [
      "sqlalchemy.text", "sqlalchemy.sql.text", "sqlalchemy.sql.expression.text"
    ] and
    target = call.getFunc() and
    target.getVariable() = imported.getAsname().(Name).getVariable()
  )
}

from Call textCall, Expr sql, Name dynamicPart
where
  (
    textCall = API::moduleImport("sqlalchemy").getMember("text").getACall().asExpr()
    or
    importedTextCall(textCall)
  ) and
  sql = textCall.getArg(0) and
  directlyFormatted(sql) and
  dynamicPart = sql.getASubExpression+()
select sql,
  "A dynamically formatted SQLAlchemy text fragment is constructed; inspect input origin, quoting, and bind parameters."
