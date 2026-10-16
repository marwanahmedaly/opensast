/**
 * @name Dynamic MCP stdio executable selection
 * @description Find nonliteral commands supplied to an MCP stdio server configuration for later review.
 * @kind problem
 * @problem.severity warning
 * @id aisast/mcp-stdio-dynamic-command-cwe-78-suspect
 * @tags security external/cwe/cwe-078
 */
import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow

from API::CallNode configuration, DataFlow::Node command
where
  (
    configuration =
      API::moduleImport("mcp").getMember("client").getMember("stdio")
        .getMember("StdioServerParameters").getACall()
    or
    configuration = API::moduleImport("mcp").getMember("StdioServerParameters").getACall()
  ) and
  command = configuration.getParameter(0, "command").asSink() and
  not command.asExpr() instanceof StringLiteral
select command, "Dynamic MCP stdio executable selection; inspect the command value and its callers."
