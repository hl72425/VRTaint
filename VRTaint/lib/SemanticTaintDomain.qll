/**
 * @name SemanticTaintDomain
 * @description Generic endpoint projection for <object,path,phase,context,source>.
 *
 * CodeQL remains the path engine.  The full tuple is joined to stable CodeQL
 * nodes at the boundary, avoiding a high-cardinality FlowState product.
 */

import csharp
import SemanticTaintFacts
import UnityStandardSourceSink

module SemanticTaintDomain {
  predicate isObservation(DataFlow::Node node) {
    UnityStandardSourceSink::isStandardSink(node)
    or
    exists(MethodCall call, int index |
      index >= 0 and index < call.getNumberOfArguments() and
      node = DataFlow::exprNode(call.getArgument(index)) and
      call.getTarget().fromSource() and
      not UnityStandardSourceSink::isStandardSink(node)
    )
    or
    exists(FieldWrite write, AssignExpr assign |
      assign.getLeftOperand() = write and
      node = DataFlow::exprNode(assign.getRightOperand())
    )
    or
    exists(ReturnStmt ret | node = DataFlow::exprNode(ret.getExpr()))
  }

  string endpointKind(DataFlow::Node node) {
    UnityStandardSourceSink::isStandardSinkKind(node, result)
    or
    exists(MethodCall call, int index |
      index >= 0 and index < call.getNumberOfArguments() and
      node = DataFlow::exprNode(call.getArgument(index)) and
      call.getTarget().fromSource() and
      not UnityStandardSourceSink::isStandardSink(node) and
      result = "call-argument"
    )
    or
    exists(FieldWrite write, AssignExpr assign |
      assign.getLeftOperand() = write and
      node = DataFlow::exprNode(assign.getRightOperand()) and result = "field-write"
    )
    or
    exists(ReturnStmt ret |
      node = DataFlow::exprNode(ret.getExpr()) and result = "return"
    )
  }

  string endpointObject(DataFlow::Node node) {
    exists(Callable c |
      c = node.getEnclosingCallable() and
      result = c.getDeclaringType().getName() + "#*"
    )
  }

  string endpointPath(DataFlow::Node node) {
    exists(FieldWrite write, AssignExpr assign |
      assign.getLeftOperand() = write and
      node = DataFlow::exprNode(assign.getRightOperand()) and
      result = "field." + write.getTarget().getName()
    )
    or
    exists(MethodCall call, int index |
      index >= 0 and index < call.getNumberOfArguments() and
      node = DataFlow::exprNode(call.getArgument(index)) and
      result = "call." + call.getTarget().getName() + ".arg[" + index.toString() + "]"
    )
    or
    exists(ReturnStmt ret |
      node = DataFlow::exprNode(ret.getExpr()) and result = "return"
    )
    or
    exists(string sinkKind |
      UnityStandardSourceSink::isStandardSinkKind(node, sinkKind) and
      result = "sink." + sinkKind
    )
  }

  string endpointPhase(DataFlow::Node node) {
    SemanticTaintFacts::executionPhase(node, result)
  }

  string endpointContext(DataFlow::Node node) {
    exists(Callable c |
      c = node.getEnclosingCallable() and
      result = "{\"schema\":\"unity-context/v1\",\"project\":\"UNKNOWN\",\"scene\":\"UNKNOWN\"," +
        "\"game_object\":\"UNKNOWN\",\"component\":\"" + c.getDeclaringType().getName() +
        "#*\",\"script\":\"" + c.getFile().getRelativePath() + "\",\"entry\":\"UNKNOWN\"," +
        "\"callable\":\"" + c.getName() + "\",\"event\":\"NONE\",\"thread\":\"MainThread\"," +
        "\"coroutine\":\"UNKNOWN\",\"async\":\"UNKNOWN\"}"
    )
  }
}
