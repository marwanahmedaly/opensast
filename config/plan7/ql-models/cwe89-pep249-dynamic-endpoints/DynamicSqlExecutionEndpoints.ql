/**
 * @name Dynamic SQL execution endpoints (CWE-89 suspect)
 * @description Select nonliteral SQL text passed to CodeQL-modeled PEP 249 execution APIs for later review.
 * @kind problem
 * @problem.severity warning
 * @id aisast/plan7-cwe89-pep249-dynamic-endpoint-suspect
 * @tags security external/cwe/cwe-089
 */
import python
import semmle.python.Concepts
import semmle.python.frameworks.PEP249

from SqlExecution execution
where not execution.getSql().asExpr() instanceof StringLiteral
select execution.getSql(),
  "Dynamic SQL text reaches a modeled database execution API; inspect the value and its callers."
