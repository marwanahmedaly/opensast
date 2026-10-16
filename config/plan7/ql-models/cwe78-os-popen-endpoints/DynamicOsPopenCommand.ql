/**
 * @name Dynamic os.popen command endpoint (CWE-78 suspect)
 * @description Select dynamic commands passed to os.popen without limiting sources to command-line input.
 * @kind problem
 * @problem.severity warning
 * @id aisast/plan7-cwe78-os-popen-endpoint-suspect
 * @tags security external/cwe/cwe-078
 */
import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

private predicate importedOsPopen(Call call) {
  exists(Import declaration, Alias imported, ImportMember importedName, Name target |
    imported = declaration.getAName() and
    importedName = imported.getValue() and
    importedName.getImportedModuleName() = "os" and
    importedName.getName() = "popen" and
    target = call.getFunc() and
    target.getVariable() = imported.getAsname().(Name).getVariable()
  )
}

private predicate osPopenCall(Call call) {
  exists(API::CallNode invocation |
    invocation = API::moduleImport("os").getMember("popen").getACall() and
    call = invocation.asExpr()
  )
  or
  importedOsPopen(call)
}

from Call call, Expr command
where
  osPopenCall(call) and
  (
    command = call.getArg(0)
    or
    exists(Keyword keyword |
      keyword = call.getAKeyword() and keyword.getArg() = "cmd" and
      command = keyword.getValue()
    )
  ) and
  not command instanceof StringLiteral
select command,
  "Dynamic os.popen command; inspect web, template, command-line and other callers, quoting and reachability. No remote source flow is asserted."
