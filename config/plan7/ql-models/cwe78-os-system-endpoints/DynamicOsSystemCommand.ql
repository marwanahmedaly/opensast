/**
 * @name Input reaches os.system (CWE-78 suspect)
 * @description Track CLI values and project-defined parameters into dynamic os.system commands.
 * @kind path-problem
 * @problem.severity warning
 * @id aisast/plan7-cwe78-os-system-endpoint-suspect
 * @tags security external/cwe/cwe-078
 */
import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

private predicate importedOsSystem(Call call) {
  exists(Import declaration, Alias imported, ImportMember importedName, Name target |
    imported = declaration.getAName() and
    importedName = imported.getValue() and
    importedName.getImportedModuleName() = "os" and
    importedName.getName() = "system" and
    target = call.getFunc() and
    target.getVariable() = imported.getAsname().(Name).getVariable()
  )
}

private predicate osSystemCall(Call call) {
  exists(API::CallNode invocation |
    invocation = API::moduleImport("os").getMember("system").getACall() and
    call = invocation.asExpr()
  )
  or
  importedOsSystem(call)
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source = API::moduleImport("sys").getMember("argv").asSource()
    or
    source =
      API::moduleImport("argparse")
          .getMember("ArgumentParser")
          .getReturn()
          .getMember("parse_args")
          .getACall()
    or
    source instanceof DataFlow::ExtractedParameterNode
  }

  predicate isSink(DataFlow::Node sink) {
    exists(Call call, Expr command |
      osSystemCall(call) and
      (
        command = call.getArg(0)
        or
        exists(Keyword keyword |
          keyword = call.getAKeyword() and
          keyword.getArg() = "command" and
          command = keyword.getValue()
        )
      ) and
      not command instanceof StringLiteral and
      sink.asExpr() = command
    )
  }
}

module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "CLI input or a project-defined parameter may reach a dynamic os.system command; inspect the source, shell quoting, and guards."
