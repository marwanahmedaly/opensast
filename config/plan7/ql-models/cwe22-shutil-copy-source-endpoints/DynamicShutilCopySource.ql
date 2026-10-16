/**
 * @name Dynamic shutil copyfile source path (CWE-22 suspect)
 * @description Select a dynamic source path passed to shutil.copyfile for file-origin containment review.
 * @kind problem
 * @problem.severity warning
 * @id aisast/plan7-cwe22-shutil-copyfile-source-endpoint-suspect
 * @tags security external/cwe/cwe-022
 */
import python
import semmle.python.ApiGraphs

from API::CallNode invocation, Expr source
where
  invocation = API::moduleImport("shutil").getMember("copyfile").getACall() and
  source = invocation.getArg(0).asExpr() and
  not source instanceof StringLiteral
select source,
  "Dynamic shutil.copyfile source path; inspect its origin and containment before copying."
