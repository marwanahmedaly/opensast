/** Source model for query-parameter values exposed by a Starlette Request parameter. */
import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.frameworks.Starlette

/** The query-parameter mapping read from an annotated Starlette Request parameter. */
class StarletteRequestQueryParamsSource extends RemoteFlowSource::Range {
  StarletteRequestQueryParamsSource() {
    exists(DataFlow::AttrRead queryParams, DataFlow::ParameterNode requestParameter |
      this = queryParams and
      queryParams.getAttributeName() = "query_params" and
      DataFlow::localFlow(requestParameter, queryParams.getObject()) and
      requestParameter.getParameter().getAnnotation() =
        Starlette::Request::classRef().getAValueReachableFromSource().asExpr()
    )
  }

  override string getSourceType() { result = "Starlette Request query parameters" }
}
