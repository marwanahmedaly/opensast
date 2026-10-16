/**
 * @name Parameter-derived SQLAlchemy Session execution (CWE-89 suspect)
 * @description Track project parameters into SQLAlchemy Session SQL statements for injection review.
 * @kind path-problem
 * @problem.severity warning
 * @id aisast/plan7-cwe89-sqlalchemy-session-execution-suspect
 * @tags security external/cwe/cwe-089
 */
import python
import semmle.python.Concepts
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.frameworks.SqlAlchemy

private predicate isSessionExecute(DataFlow::Node execution) {
  exists(DataFlow::MethodCallNode methodCall |
    execution = methodCall and
    methodCall.calls(SqlAlchemy::Session::instance(), "execute")
  )
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof DataFlow::ExtractedParameterNode
    or
    // A parameter can be a request/tool/model object rather than the SQL string
    // itself. Treat a directly read field on that parameter as a suspect source;
    // taint tracking does not implicitly flow through object dereferences.
    exists(DataFlow::AttrRead field, DataFlow::ExtractedParameterNode parameter |
      source = field and
      not parameter.getParameter().getName() = ["self", "cls"] and
      DataFlow::localFlow(parameter, field.getObject())
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(SqlExecution execution |
      isSessionExecute(execution) and
      sink = execution.getSql()
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    // SQLAlchemy's text() turns its SQL-string argument into a TextClause object;
    // preserve taint across this constructor so Session.execute(text(sql)) remains
    // visible as one source-to-execution path.
    exists(SqlAlchemy::TextClause::TextClauseConstruction text |
      nodeFrom = text.getSql() and
      nodeTo = text
    )
  }
}

module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "A function parameter may reach a SQLAlchemy Session SQL statement; inspect whether it changes SQL syntax or represents a bound value."
