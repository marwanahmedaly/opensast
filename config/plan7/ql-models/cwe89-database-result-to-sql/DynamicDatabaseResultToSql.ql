/**
 * @name Database query result reused in SQL text (CWE-89 suspect)
 * @description Track rows returned by a database read into later dynamic SQL statements for second-order SQL injection review.
 * @kind path-problem
 * @problem.severity warning
 * @id aisast/plan7-cwe89-database-result-to-sql-suspect
 * @tags security external/cwe/cwe-089
 */
import python
import semmle.python.Concepts
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.frameworks.PEP249
import semmle.python.frameworks.SqlAlchemy

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof ThreatModelSource and
    source.(ThreatModelSource).getThreatModel() = "database"
    or
    // Also cover database result APIs not represented by the PEP 249 model,
    // such as SQLAlchemy Result.fetchall(). The sink still has to be a modeled
    // SQL execution call.
    exists(DataFlow::MethodCallNode fetchCall |
      source = fetchCall and
      fetchCall.getMethodName() in ["fetchone", "fetchmany", "fetchall"]
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(SqlExecution execution |
      sink = execution.getSql() and
      not sink.asExpr() instanceof StringLiteral
    )
    or
    exists(SqlAlchemy::TextClause::TextClauseConstruction construction |
      sink = construction.getSql() and
      not sink.asExpr() instanceof StringLiteral
    )
  }
}

module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Data returned from a database read may flow into a later dynamic SQL statement; inspect where stored values came from and how the SQL is quoted."
