/**
 * @name Dynamic input rendered by Python-Markdown (CWE-79 suspect)
 * @description Track project parameters into Python-Markdown's HTML conversion APIs for output-escaping review.
 * @kind path-problem
 * @problem.severity warning
 * @id aisast/plan7-cwe79-python-markdown-html-suspect
 * @tags security external/cwe/cwe-079
 */
import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

private API::Node pythonMarkdownInstance() {
  result = API::moduleImport("markdown").getMember("Markdown").getReturn()
}

private API::CallNode pythonMarkdownHtmlCall() {
  result = pythonMarkdownInstance().getMember("convert").getACall()
  or
  result = API::moduleImport("markdown").getMember("markdown").getACall()
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof DataFlow::ExtractedParameterNode
  }

  predicate isSink(DataFlow::Node sink) {
    exists(API::CallNode conversion, Expr markdownInput |
      conversion = pythonMarkdownHtmlCall() and
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
  "A function parameter may reach Python-Markdown HTML conversion; inspect HTML escaping and where the rendered result is used."
