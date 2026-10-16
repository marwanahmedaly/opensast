/**
 * @name Dynamic filesystem mutation path (CWE-22 suspect)
 * @description Select dynamic paths passed to os.remove, os.unlink, os.rename, or os.replace.
 * @kind problem
 * @problem.severity warning
 * @id aisast/plan7-cwe22-dynamic-path-mutation-suspect
 * @tags security external/cwe/cwe-022
 */
import python
import semmle.python.ApiGraphs

from Call mutation, Expr path
where
  (
    mutation = API::moduleImport("os").getMember("remove").getACall().asExpr() and
    path = mutation.getArg(0) and
    not path instanceof StringLiteral
  )
  or
  (
    mutation = API::moduleImport("os").getMember("unlink").getACall().asExpr() and
    path = mutation.getArg(0) and
    not path instanceof StringLiteral
  )
  or
  (
    mutation = API::moduleImport("os").getMember("rename").getACall().asExpr() and
    (path = mutation.getArg(0) or path = mutation.getArg(1)) and
    not path instanceof StringLiteral
  )
  or
  (
    mutation = API::moduleImport("os").getMember("replace").getACall().asExpr() and
    (path = mutation.getArg(0) or path = mutation.getArg(1)) and
    not path instanceof StringLiteral
  )
select path,
  "A dynamic path is used to delete, rename, or replace a filesystem entry; inspect its origin and directory boundary."
