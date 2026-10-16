/**
 * @name Dynamic DuckDB SQL execution endpoint (CWE-89 suspect)
 * @description Track project function parameters into dynamically constructed SQL passed to DuckDB execution APIs for review.
 * @kind path-problem
 * @problem.severity warning
 * @id aisast/plan7-cwe89-duckdb-dynamic-execution-suspect
 * @tags security external/cwe/cwe-089
 */
import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

private API::Node duckdbConnection() {
  result = API::moduleImport("duckdb").getMember("connect").getReturn()
}

private API::CallNode duckdbExecuteCall() {
  result = duckdbConnection().getMember(["execute", "executemany"]).getACall()
  or
  result = API::moduleImport("duckdb").getMember(["execute", "executemany"]).getACall()
}

private predicate directlyDynamicSql(Expr sql) {
  sql instanceof Fstring
  or
  exists(Call formatCall, Attribute formatMethod, Expr value |
    sql = formatCall and
    formatCall.getFunc() = formatMethod and
    formatMethod.getName() = "format" and
    value = formatCall.getAnArg() and
    not value instanceof StringLiteral
  )
  or
  exists(BinaryExpr binary, StringLiteral template, Name value |
    sql = binary and
    template = binary.getASubExpression+() and
    value = binary.getASubExpression+()
  )
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof DataFlow::ExtractedParameterNode
  }

  predicate isSink(DataFlow::Node sink) {
    exists(API::CallNode execution, Expr constructedSql |
      execution = duckdbExecuteCall() and
      directlyDynamicSql(constructedSql) and
      DataFlow::localFlow(DataFlow::exprNode(constructedSql), execution.getArg(0)) and
      sink = execution.getArg(0)
    )
  }
}

module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "A function parameter may reach dynamically constructed SQL passed to DuckDB; inspect identifier quoting, parameter binding, and the value's origin."
