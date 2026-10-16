/**
 * @name MCP tool argument reaches a filesystem path operation
 * @description Find MCP v1 tool arguments that can select a filesystem path.
 * @kind path-problem
 * @problem.severity warning
 * @id aisast/mcp-v1-tool-path-suspect
 * @tags security external/cwe/cwe-022
 */
import python
import McpV1Sources
import semmle.python.security.dataflow.PathInjectionQuery
import PathInjectionFlow::PathGraph

from PathInjectionFlow::PathNode source, PathInjectionFlow::PathNode sink
where
  source.getNode() instanceof McpV1CallToolArgumentsSource and
  PathInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "An MCP tool argument may select this path; review the allowed-path checks from $@.",
  source.getNode(), "MCP tool arguments"
