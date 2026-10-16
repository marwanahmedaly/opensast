/**
 * @name Dynamic MarkupSafe safe HTML construction (CWE-79 suspect)
 * @description Select dynamic content passed to MarkupSafe Markup for HTML escaping review.
 * @kind problem
 * @problem.severity warning
 * @id aisast/plan7-cwe79-markupsafe-dynamic-markup-endpoint-suspect
 * @tags security external/cwe/cwe-079
 */
import python
import semmle.python.ApiGraphs

private predicate importedMarkup(Call call) {
  exists(Import declaration, Alias imported, Name target |
    imported = declaration.getAName() and
    imported.getValue().(ImportMember).getImportedModuleName() = "markupsafe.Markup" and
    target = call.getFunc() and
    target.getVariable() = imported.getAsname().(Name).getVariable()
  )
}

from Call call, Expr content
where
  (
    call = API::moduleImport("markupsafe").getMember("Markup").getACall().asExpr()
    or
    importedMarkup(call)
  ) and
  content = call.getArg(0) and
  not content instanceof StringLiteral
select content,
  "Dynamic content is marked safe for Jinja HTML output; inspect its origin and escaping before this call."
