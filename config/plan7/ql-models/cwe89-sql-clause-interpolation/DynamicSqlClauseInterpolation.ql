/**
 * @name Dynamic SQL text interpolation (CWE-89 suspect)
 * @description Select SQL-shaped formatted or concatenated text for execution and quoting review, including helper-bound INSERT statements.
 * @kind problem
 * @problem.severity warning
 * @id aisast/plan7-cwe89-sql-clause-interpolation-suspect
 * @tags security external/cwe/cwe-089
 */
import python

private predicate sqlLiteral(StringLiteral fragment) {
  fragment.getText().toUpperCase().regexpMatch(
    "[\\s\\S]*(ILIKE|LIKE|ANY|WHERE|ORDER BY|GROUP BY|HAVING)[\\s\\S]*"
  )
  or
  fragment.getText().toUpperCase().regexpMatch(
    "\\s*(SELECT|INSERT|UPDATE|DELETE|REPLACE|WITH|CREATE|ALTER|DROP|PRAGMA)\\b[\\s\\S]*"
  )
}

private predicate sqlBuilder(Expr expression) {
  exists(StringLiteral fragment |
    fragment = expression.getASubExpression+() and sqlLiteral(fragment)
  ) and
  (
    expression instanceof Fstring and
    exists(Name inserted | inserted = expression.getASubExpression+())
    or
    exists(Call call, Attribute method, Expr argument |
      expression = call and method = call.getFunc() and
      method.getName() = "format" and argument = call.getAnArg() and
      not argument instanceof StringLiteral
    )
    or
    exists(BinaryExpr binary, Name inserted |
      expression = binary and binary.getOp() instanceof AddOrMod and
      inserted = binary.getASubExpression+()
    )
  )
}

private class AddOrMod extends Operator {
  AddOrMod() { this instanceof Add or this instanceof Mod }
}

from Expr expression
where
  sqlBuilder(expression) and
  not exists(Expr outer |
    sqlBuilder(outer) and expression = outer.getASubExpression+()
  )
select expression,
  "Dynamic SQL-shaped text; verify whether it reaches database execution, whether inserted values are lower-trust, and whether binding/quoting prevents syntax changes. This builder alone is not SQL injection."
