/** Remote input supplied as `arguments` to a v1 low-level MCP call_tool handler. */
import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.RemoteFlowSources

class McpV1CallToolArgumentsSource extends RemoteFlowSource::Range, DataFlow::ParameterNode {
  McpV1CallToolArgumentsSource() {
    exists(Function handler, DataFlow::CallCfgNode setup |
      setup = API::moduleImport("mcp").getMember("server").getMember("Server").getReturn().getMember("call_tool").getACall() and
      setup.asExpr() = handler.getADecorator() and
      this.getParameter() = handler.getArgByName("arguments")
    )
  }
  override string getSourceType() { result = "MCP v1 tool arguments" }
}
