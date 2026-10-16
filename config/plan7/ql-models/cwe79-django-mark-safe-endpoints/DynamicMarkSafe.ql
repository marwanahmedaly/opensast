/**
 * @name Dynamic Django mark_safe output (CWE-79 suspect)
 * @description Select dynamically supplied content passed to Django mark_safe for escaping review.
 * @kind problem
 * @problem.severity warning
 * @id aisast/plan7-cwe79-django-dynamic-mark-safe-endpoint-suspect
 * @tags security external/cwe/cwe-079
 */
import python
import semmle.python.ApiGraphs

private predicate importedDjangoMarkSafe(Call call) {
  exists(Import declaration, Alias imported, Name target |
    imported = declaration.getAName() and
    imported.getValue().(ImportMember).getImportedModuleName() =
      "django.utils.safestring.mark_safe" and
    target = call.getFunc() and
    target.getVariable() = imported.getAsname().(Name).getVariable()
  )
}

from Call call, Expr content, Name dynamicPart
where
  (
    call = API::moduleImport("django.utils.safestring").getMember("mark_safe").getACall().asExpr()
    or
    importedDjangoMarkSafe(call)
  ) and
  content = call.getArg(0) and
  not content instanceof StringLiteral and
  (
    dynamicPart = content.(Name)
    or
    dynamicPart = content.getASubExpression+()
  )
select content,
  "Dynamic content is marked safe for Django HTML output; inspect its origin and all escaping paths."
