/**
 * @name Dynamic asyncio shell command endpoint (CWE-78 suspect)
 * @description Select dynamic commands passed to asyncio.create_subprocess_shell for origin and quoting review.
 * @kind problem
 * @problem.severity warning
 * @id aisast/plan7-cwe78-asyncio-shell-command-endpoint-suspect
 * @tags security external/cwe/cwe-078
 */
import python
import semmle.python.ApiGraphs

private predicate importedAsyncioShell(Call call) {
  exists(Import declaration, Alias imported, Name target |
    imported = declaration.getAName() and
    imported.getValue().(ImportMember).getImportedModuleName() =
      "asyncio.create_subprocess_shell" and
    target = call.getFunc() and
    target.getVariable() = imported.getAsname().(Name).getVariable()
  )
}

from Call call, Expr command
where
  (
    call = API::moduleImport("asyncio").getMember("create_subprocess_shell").getACall().asExpr()
    or
    importedAsyncioShell(call)
  ) and
  command = call.getArg(0) and
  not command instanceof StringLiteral
select command,
  "Dynamic command is passed to asyncio.create_subprocess_shell; inspect the input origin and shell quoting."
