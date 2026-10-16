/**
 * @name Starlette query parameters rendered in HTML through from_dict
 * @description Find possible reflected XSS paths, including object factory field reads.
 * @kind path-problem
 * @problem.severity warning
 * @id aisast/starlette-from-dict-cwe-79-suspect
 * @tags security external/cwe/cwe-079
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import StarletteRequestSources
import StarletteHtmlResponseSinks
import FromDictObjectFieldFlow

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof StarletteRequestQueryParamsSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof StarletteHTMLResponseContentSink
  }

  predicate isAdditionalFlowStep(DataFlow::Node sourceNode, DataFlow::Node sinkNode) {
    fromDictObjectFieldStep(sourceNode, sinkNode)
  }
}

module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Starlette query parameter may reach an HTML response through an object factory."
