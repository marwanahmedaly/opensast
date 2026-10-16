/**
 * @name Dynamic input rendered by markdown2 (CWE-79 suspect)
 * @description Track function parameters into markdown2's HTML conversion APIs for output-escaping review.
 * @kind path-problem
 * @problem.severity warning
 * @id aisast/plan7-cwe79-markdown2-html-suspect
 * @tags security external/cwe/cwe-079
 */
import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

private API::CallNode markdown2HtmlCall() {
  result = API::moduleImport("markdown2").getMember("markdown").getACall()
  or
  result = API::moduleImport("markdown2").getMember("Markdown").getReturn().getMember("convert").getACall()
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof DataFlow::ExtractedParameterNode
  }

  predicate isSink(DataFlow::Node sink) {
    exists(API::CallNode conversion, Expr markdownInput |
      conversion = markdown2HtmlCall() and
      markdownInput = conversion.getArg(0).asExpr() and
      not markdownInput instanceof StringLiteral and
      sink.asExpr() = markdownInput
    )
  }
}

module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "A function parameter may reach markdown2 HTML conversion; inspect raw-HTML handling and where the rendered result is used."
