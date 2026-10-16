/**
 * @name Dynamic HTML response construction (CWE-79 suspect)
 * @description Select dynamic HTML returns and native HTTP/WSGI response builders for verification, without requiring return annotations or a remote source path.
 * @kind problem
 * @problem.severity warning
 * @id aisast/plan7-cwe79-dynamic-html-return-suspect
 * @tags security external/cwe/cwe-079
 */
import python

private predicate htmlScope(Expr expression) {
  exists(StringLiteral literal |
    literal.getScope() = expression.getScope() and
    literal.getText().regexpMatch("[\\s\\S]*<[\\s\\S]*")
  )
}

private predicate responseValue(Expr expression) {
  // A CLI/custom emitter may receive HTML rather than return an HTTP response.
  // Select dynamic text carrying literal markup regardless of emitter spelling.
  // Escaped values and non-browser uses remain suspects for verification.
  exists(Call call, StringLiteral literal |
    expression = call.getAnArg() and
    not expression instanceof StringLiteral and
    literal = expression.getASubExpression*() and
    literal.getText().regexpMatch("[\\s\\S]*<[A-Za-z][\\s\\S]*>[\\s\\S]*")
  )
  or
  exists(Return statement |
    expression = statement.getValue() and
    not expression instanceof StringLiteral and
    htmlScope(expression)
  )
  or
  // Native HTTP output may be written rather than returned. The receiver
  // shape is an endpoint hint, not proof of HTTP object identity or MIME.
  exists(Call call, Attribute method, Attribute receiver |
    method = call.getFunc() and method.getName() = "write" and
    receiver = method.getObject() and receiver.getName() = "wfile" and
    expression = call.getArg(0) and
    not expression instanceof StringLiteral
  )
  or
  // WSGI commonly appends HTML fragments and returns encoded chunks.
  exists(Call call, Attribute method |
    method = call.getFunc() and method.getName() in ["append", "extend"] and
    expression = call.getArg(0) and
    not expression instanceof StringLiteral and htmlScope(expression) and
    exists(Parameter parameter |
      parameter.asName().getScope() = expression.getScope() and
      parameter.getName() = "environ"
    )
  )
}

from Expr expression
where responseValue(expression)
select expression,
  "Dynamic value at a possible HTML response operation; verify browser-facing MIME, value origins, escaping and reachability. No remote source flow is asserted."
