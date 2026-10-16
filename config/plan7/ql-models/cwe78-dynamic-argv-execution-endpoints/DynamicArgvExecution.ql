/**
 * @name Dynamic argv passed to a process launcher (CWE-78 suspect)
 * @description Select dynamically assembled argument vectors passed to subprocess APIs without shell=True.
 * @kind problem
 * @problem.severity warning
 * @id aisast/plan7-cwe78-dynamic-argv-execution-suspect
 * @tags security external/cwe/cwe-078
 */
import python
import semmle.python.ApiGraphs

private predicate containsDynamicArgumentPart(Expr arguments) {
  exists(Name value |
    value = arguments or value = arguments.getASubExpression+()
  )
}

private predicate usesShellTrue(Call launch) {
  exists(Keyword shell |
    shell = launch.getAKeyword() and
    shell.getArg() = "shell" and
    shell.getValue() instanceof True
  )
}

from Call launch, Expr arguments
where
  (
    launch = API::moduleImport("subprocess").getMember("Popen").getACall().asExpr() or
    launch = API::moduleImport("subprocess").getMember("run").getACall().asExpr() or
    launch = API::moduleImport("subprocess").getMember("call").getACall().asExpr() or
    launch = API::moduleImport("subprocess").getMember("check_call").getACall().asExpr() or
    launch = API::moduleImport("subprocess").getMember("check_output").getACall().asExpr()
  ) and
  arguments = launch.getArg(0) and
  not usesShellTrue(launch) and
  containsDynamicArgumentPart(arguments)
select arguments,
  "A process receives dynamically assembled argv; inspect the argument source and check whether an option or executable can change the intended command."
