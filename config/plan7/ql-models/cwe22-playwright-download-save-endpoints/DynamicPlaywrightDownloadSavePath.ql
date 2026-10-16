/**
 * @name Playwright download save path from a suggested filename (CWE-22 suspect)
 * @description Select a dynamic Playwright download destination where the download's suggested filename is read in the same handler.
 * @kind problem
 * @problem.severity warning
 * @id aisast/plan7-cwe22-playwright-download-save-path-suspect
 * @tags security external/cwe/cwe-022
 */
import python

private predicate playwrightImported(Module fileModule) {
  exists(Import declaration, Alias imported |
    declaration.getScope() = fileModule and
    imported = declaration.getAName() and
    imported.getValue().(ImportMember).getImportedModuleName().matches("playwright.%")
  )
  or
  exists(Import declaration, Alias imported |
    declaration.getScope() = fileModule and
    imported = declaration.getAName() and
    imported.getValue().(ImportExpr).getImportedModuleName().matches("playwright%")
  )
}

from Call call, Attribute saveAs, Name receiver, Attribute suggested, Expr destination
where
  saveAs = call.getFunc() and
  saveAs.getName() = "save_as" and
  receiver = saveAs.getObject() and
  suggested.getName() = "suggested_filename" and
  suggested.getObject().(Name).getVariable() = receiver.getVariable() and
  suggested.getScope() = call.getScope() and
  playwrightImported(call.getEnclosingModule()) and
  destination = call.getArg(0) and
  not destination instanceof StringLiteral
select destination,
  "A Playwright download is saved to a dynamic path after reading its suggested filename; inspect basename and containment checks."
