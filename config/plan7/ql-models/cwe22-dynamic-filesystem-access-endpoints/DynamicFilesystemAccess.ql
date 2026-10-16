/**
 * @name Dynamic filesystem access endpoint (CWE-22 suspect)
 * @description Select modeled filesystem path arguments independently of remote source recognition; include archive, compressed-file and possible Path method readers.
 * @kind problem
 * @problem.severity warning
 * @id aisast/plan7-cwe22-dynamic-filesystem-access-suspect
 * @tags security external/cwe/cwe-022
 */
import python
import semmle.python.ApiGraphs
import semmle.python.Concepts
import semmle.python.frameworks.Stdlib

private predicate filesystemPath(Expr path) {
  // Receiver type may arrive only through a parameter annotation or a caller.
  // Method spelling is a recall-oriented hint, not proof of pathlib identity.
  exists(Call call, Attribute method |
    method = call.getFunc() and method.getName() in ["read_bytes", "read_text"] and
    path = method.getObject()
  )
  or
  exists(FileSystemAccess access | path = access.getAPathArgument().asExpr())
  or
  exists(API::CallNode call |
    (
      call = API::moduleImport("tarfile").getMember("open").getACall()
      or call = API::moduleImport("tarfile").getMember("TarFile").getACall()
      or call = API::moduleImport("tarfile").getMember("TarFile").getMember("open").getACall()
      or call = API::moduleImport("bz2").getMember(["open", "BZ2File"]).getACall()
    ) and
    (path = call.getArg(0).asExpr() or path = call.getArgByName("name").asExpr()
      or path = call.getArgByName("filename").asExpr())
  )
}

from Expr path
where filesystemPath(path) and not path instanceof StringLiteral
select path,
  "Dynamic filesystem path; verify caller trust, read/write semantics, containment, guards and reachability. This endpoint does not prove remote input or path traversal."
