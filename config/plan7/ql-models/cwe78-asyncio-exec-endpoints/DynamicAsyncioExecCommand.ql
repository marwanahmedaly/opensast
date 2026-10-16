/**
 * @name Dynamic argv passed to asyncio process execution (CWE-78 suspect)
 * @description Track function parameters into argument vectors passed to asyncio.create_subprocess_exec for command review.
 * @kind path-problem
 * @problem.severity warning
 * @id aisast/plan7-cwe78-asyncio-exec-suspect
 * @tags security external/cwe/cwe-078
 */
import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof DataFlow::ExtractedParameterNode
  }

  predicate isSink(DataFlow::Node sink) {
    exists(API::CallNode launch, Call call, Expr argument |
      launch = API::moduleImport("asyncio").getMember("create_subprocess_exec").getACall() and
      call = launch.asExpr() and
      argument = call.getAnArg() and
      sink.asExpr() = argument
    )
  }
}

module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "A function parameter may reach an asyncio process argument; inspect whether it controls the executable or changes the intended command."
