/**
 * @name Dynamic HTML passed to WeasyPrint (CWE-79 suspect)
 * @description Track project inputs into nonliteral HTML supplied to WeasyPrint for HTML-injection review.
 * @kind path-problem
 * @problem.severity warning
 * @id aisast/plan7-cwe79-dynamic-weasyprint-html-string
 * @tags security external/cwe/cwe-079
 */
import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

private predicate isWeasyPrintHtmlCall(API::CallNode call) {
  call = API::moduleImport("weasyprint").getMember("HTML").getACall()
  or
  exists(Import declaration, Alias imported, Name target, Call astCall |
    imported = declaration.getAName() and
    imported.getValue().(ImportMember).getImportedModuleName() = "weasyprint.HTML" and
    astCall = call.asExpr() and
    target = astCall.getFunc() and
    target.getVariable() = imported.getAsname().(Name).getVariable()
  )
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof DataFlow::ExtractedParameterNode
  }

  predicate isSink(DataFlow::Node sink) {
    exists(API::CallNode call, Expr html |
      isWeasyPrintHtmlCall(call) and
      html = call.getArgByName("string").asExpr() and
      not html instanceof StringLiteral and
      sink.asExpr() = html
    )
  }
}

module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Project input may reach dynamic HTML passed to WeasyPrint; inspect HTML escaping and resource-fetching behavior."
