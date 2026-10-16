/**
 * @name Archive member names passed to ZipFile.extract (CWE-22 suspect)
 * @description Track names returned by ZipFile.namelist when they are passed to ZipFile.extract.
 * @kind path-problem
 * @problem.severity warning
 * @id aisast/plan7-cwe22-zipfile-extract-member-suspect
 * @tags security external/cwe/cwe-022
 */
import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

private module ZipFileExtractConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source =
      API::moduleImport("zipfile")
          .getMember("ZipFile")
          .getReturn()
          .getMember("namelist")
          .getACall()
  }

  predicate isSink(DataFlow::Node sink) {
    exists(API::CallNode extraction |
      extraction =
        API::moduleImport("zipfile")
            .getMember("ZipFile")
            .getReturn()
            .getMember("extract")
            .getACall() and
      sink = extraction.getArg(0)
    )
  }
}

private module ZipFileExtractFlow = TaintTracking::Global<ZipFileExtractConfig>;

import ZipFileExtractFlow::PathGraph

from ZipFileExtractFlow::PathNode source, ZipFileExtractFlow::PathNode sink
where ZipFileExtractFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Archive-controlled member name is passed to ZipFile.extract; review whether the archive and extraction root are trusted and confined."
