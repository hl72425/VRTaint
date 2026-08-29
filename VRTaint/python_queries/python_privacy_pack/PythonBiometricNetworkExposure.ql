/**
 * @name Python biometric payload sent over a network
 * @kind path-problem
 * @id py/biometric-network-exposure
 * @precision high
 * @problem.severity warning
 * @security-severity 7.5
 * @tags security external/cwe/cwe-359
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

private predicate biometricContext(Call n) {
  n.getLocation().getFile().getRelativePath().toLowerCase().matches("%face%") or
  n.getLocation().getFile().getRelativePath().toLowerCase().matches("%landmark%") or
  n.getLocation().getFile().getRelativePath().toLowerCase().matches("%biometric%")
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Call call, Attribute attr |
      call.getFunc() = attr and attr.getName() = "SerializeToString" and
      biometricContext(call) and source = DataFlow::exprNode(call)
    )
  }
  predicate isSink(DataFlow::Node sink) {
    exists(Call call, Attribute attr |
      call.getFunc() = attr and attr.getName() in ["send", "sendall", "sendto"] and
      sink = DataFlow::exprNode(call.getArg(0))
    )
  }
  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Payload arguments become content of packet/message wrapper objects.
    exists(Call call, Expr arg |
      arg = call.getArg(_) and
      (
        call.getFunc().(Name).getId().matches("%Packet%") or
        call.getFunc().(Name).getId().matches("%Message%")
      ) and
      pred = DataFlow::exprNode(arg) and succ = DataFlow::exprNode(call)
    )
    or
    // Encoding/serialization of a tainted wrapper preserves its content.
    exists(Call call, Attribute attr |
      call.getFunc() = attr and
      attr.getName() in ["encode", "serialize", "SerializeToString"] and
      pred = DataFlow::exprNode(attr.getObject()) and succ = DataFlow::exprNode(call)
    )
  }
}
module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Serialized biometric/landmark payload reaches a network send operation."
