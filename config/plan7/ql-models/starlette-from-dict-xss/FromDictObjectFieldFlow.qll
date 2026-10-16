/**
 * Provisional, recall-oriented flow through from_dict object factories.
 *
 * This convention is a heuristic, not a Python-wide guarantee. A dictionary
 * passed to `from_dict` may influence the resulting object, and a field read
 * on that object may expose the dictionary's values. Validate candidate volume
 * and independent applicability before promoting this model.
 */
import python
import semmle.python.dataflow.new.DataFlow

predicate fromDictObjectFieldStep(DataFlow::Node sourceNode, DataFlow::Node sinkNode) {
  exists(DataFlow::MethodCallNode call |
    call.getMethodName() = "from_dict" and
    sourceNode = call.getArg(0) and
    sinkNode = call
  )
  or
  exists(DataFlow::MethodCallNode call, DataFlow::AttrRead field |
    call.getMethodName() = "from_dict" and
    DataFlow::localFlow(call, field.getObject()) and
    sourceNode = call and
    sinkNode = field
  )
}
