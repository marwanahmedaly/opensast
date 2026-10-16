/**
 * @name Dynamic local destination for Paramiko SFTP download (CWE-22 suspect)
 * @description Select a dynamic localpath supplied to get() on an SFTP client created from Paramiko SSHClient.open_sftp().
 * @kind problem
 * @problem.severity warning
 * @id aisast/plan7-cwe22-paramiko-sftp-download-localpath-suspect
 * @tags security external/cwe/cwe-022
 */
import python
import semmle.python.ApiGraphs

private predicate paramikoSftpVariable(Name sftp) {
  exists(
    AssignStmt sftpAssignment, Name sftpTarget, Call openCall, Attribute openMethod,
    Name sshUse, AssignStmt sshAssignment, Name sshTarget, Call sshConstructor
  |
    sftpTarget = sftpAssignment.getATarget() and
    sftpTarget.getVariable() = sftp.getVariable() and
    openCall = sftpAssignment.getValue() and
    openMethod = openCall.getFunc() and
    openMethod.getName() = "open_sftp" and
    sshUse = openMethod.getObject() and
    sshTarget = sshAssignment.getATarget() and
    sshTarget.getVariable() = sshUse.getVariable() and
    sshConstructor = sshAssignment.getValue() and
    sshConstructor = API::moduleImport("paramiko").getMember("SSHClient").getACall().asExpr()
  )
}

from Call download, Attribute method, Name sftp, Expr localDestination
where
  method = download.getFunc() and
  method.getName() = "get" and
  sftp = method.getObject() and
  paramikoSftpVariable(sftp) and
  (
    localDestination = download.getArg(1)
    or
    exists(Keyword keyword |
      keyword = download.getAKeyword() and
      keyword.getArg() = "localpath" and
      localDestination = keyword.getValue()
    )
  ) and
  not localDestination instanceof StringLiteral
select localDestination,
  "Paramiko SFTP download writes to a dynamic local destination; inspect its origin and confinement."
