/**
 * @name Dynamic subprocess shell command endpoint (CWE-78 suspect)
 * @description Select a dynamic command passed to subprocess shell APIs with shell=True for later review.
 * @kind problem
 * @problem.severity warning
 * @id aisast/plan7-cwe78-subprocess-shell-endpoint-suspect
 * @tags security external/cwe/cwe-078
 */
import python
import semmle.python.ApiGraphs

from API::CallNode invocation, Expr command
where
  (
    invocation = API::moduleImport("subprocess").getMember("Popen").getACall()
    or
    invocation = API::moduleImport("subprocess").getMember(["run", "call", "check_call", "check_output"]).getACall()
  ) and
  invocation.getArgByName("shell").asExpr() instanceof True and
  command = invocation.getArg(0).asExpr() and
  not command instanceof StringLiteral
select command,
  "Dynamic command supplied to a subprocess API with shell=True; inspect its origin and guards."
