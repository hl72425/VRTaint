/**
 * @name Unity Lifecycle Flow
 * @description Utilizes modular benchmark libraries to trace data flows within XR/Unity environments. Runs with the built-in zero-fact project-model fallback and consumes generated instance facts when a Unity model pack is supplied.
 * @kind path-problem
 * @precision high
 * @id cs/vr-taint-flow-critical
 * @severity error
 * @tags security
 *
 * NOTE — project-model fallback contract:
 * This query (via lib.VRTaintFlowFramework -> UnityLifecycleBase -> UnityProjectModel)
 * depends on the extensible predicate unityLifecycleEntryModel. CodeQL rejects
 * evaluation when a reachable extensible predicate has no defining data extension
 * ("The query depends on an extensional predicate ... which has not been defined").
 * The pack therefore bundles zero-fact definitions:
 *   - qlpack.yml:                 dataExtensions: - models/*.model.yml
 *   - models/UnityProjectModelDefaults.model.yml  (sentinel rows, confidence "none")
 * ProjectModel accessors only accept "high"/"medium", so the sentinels are
 * semantically empty. Generated instance model packs add high/medium rows to the
 * same predicates without changing this query.
 */

import csharp
import lib.VRTaintFlowFramework

// ================= PROJECT-SPECIFIC CONFIGURATION =================
module UnityVRConfig implements ProjectConfigSig {

  predicate isSource(DataFlow::Node source) {
    // S1 - Unified Helper Test Sources
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName("TestSources", ["GetUIInput", "GetNetworkInput", "GetFileContent"]) and
      source = DataFlow::exprNode(mc)
    )
    or
    // S1-CMD Command Line Arguments Array Element Source
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName("TestSources", "GetCmdArgs") and
      source = DataFlow::exprNode(mc)
    )
    // S2 - Native Unity Property Sources
    or
    exists(PropertyAccess pa |
      pa.getTarget().hasFullyQualifiedName("UnityEngine.UI.InputField", "text") and
      source = DataFlow::exprNode(pa)
    )
    or
    exists(PropertyAccess pa |
      pa.getTarget().hasFullyQualifiedName("UnityEngine.Networking.DownloadHandler", "text") and
      source = DataFlow::exprNode(pa)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // K1 - Unified Helper Test Sinks
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName("TestSinks", "DangerousLoad") and
      sink = DataFlow::exprNode(mc.getArgument(0))
    )
    or
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName("TestSinks", "DangerousFileWrite") and
      sink = DataFlow::exprNode(mc.getAnArgument())
    )
    // K2 - Native Unity Property Mutation Sinks
    or
    exists(PropertyCall pc |
      pc.getTarget().hasName("set_position") and
      pc.getTarget().getDeclaringType().hasFullyQualifiedName("UnityEngine", "Transform") and
      sink = DataFlow::exprNode(pc.getArgument(0))
    )
    or
    exists(PropertyCall pc |
      pc.getTarget().hasName("set_velocity") and
      pc.getTarget().getDeclaringType().hasFullyQualifiedName("UnityEngine", "Rigidbody") and
      sink = DataFlow::exprNode(pc.getArgument(0))
    )
    // K3 - Asynchronous/Reflection API Reflection Sinks
    or
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName("UnityEngine", "MonoBehaviour", "Invoke") and
      sink = DataFlow::exprNode(mc.getArgument(0))
    )
    or
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName("UnityEngine", "MonoBehaviour", "StartCoroutine") and
      sink = DataFlow::exprNode(mc.getArgument(0))
    )
    or
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName("UnityEngine", "GameObject", "SendMessage") and
      sink = DataFlow::exprNode(mc.getArgument(0))
    )
    or
    exists(MethodCall mc |
      mc.getTarget().getName() = "Invoke" and
      mc.getTarget().getDeclaringType().hasFullyQualifiedName(
        "System.Reflection", ["MethodInfo", "MethodBase"]
      ) and
      sink = DataFlow::exprNode(mc.getAnArgument())
    )
    or
    exists(MethodCall mc, ArrayCreation arr, ArrayInitializer init, Expr element |
      mc.getTarget().getName() = "Invoke" and
      mc.getTarget().getDeclaringType().hasFullyQualifiedName(
        "System.Reflection", ["MethodInfo", "MethodBase"]
      ) and
      arr = mc.getArgument(1) and
      init = arr.getInitializer() and
      element = init.getAChildExpr() and
      sink = DataFlow::exprNode(element)
    )
    or
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName("System", "Activator", "CreateInstance") and
      sink = DataFlow::exprNode(mc.getAnArgument())
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    // B1 - String Standardization Transforms
    exists(MethodCall ma |
      ma.getTarget().getName() in ["ToUpper", "ToLower"] and
      node = DataFlow::exprNode(ma)
    )
    // B2 - Mathematical Constraints/Clamping 
    or exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName("UnityEngine", "Mathf") and
      mc.getTarget().getName() in ["Clamp", "Clamp01", "Max", "Min"] and
      node = DataFlow::exprNode(mc)
    )
    // B3 - Overlapping Coordinate Collisions
    or exists(Location loc |
      loc = node.getLocation() and
      exists(DataFlow::Node other |
        other != node and
        other.getLocation() = loc and
        (isSource(node) and isSink(other) or isSource(other) and isSink(node))
      )
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Project-specific event bindings are supplied by the generated CodeQL
    // data extension and consumed by VRTaintFlowFramework/UnitySerializedConfig.
    none()
  }
}

// ================= INSTANTIATE FRAMEWORK AND TRACKING =================
// The query remains directly runnable without --model-packs. In that mode the
// pack-level zero-fact extension definitions keep the project-model contract
// well-defined and lifecycle recognition uses resolved MonoBehaviour types.
// Supplying a generated Unity instance model pack adds precise entry/instance
// facts without changing this query or its source/sink/barrier configuration.
module Flow = VRTaintInstanceFlow<UnityVRConfig>;
module Tracking = TaintTracking::GlobalWithState<Flow>;
import Tracking::PathGraph

from
  Tracking::PathNode source,
  Tracking::PathNode sink
where
  Tracking::flowPath(source, sink)
select
  sink.getNode(), source, sink,
  " | SourceLoc: " + source.getNode().getLocation().toString() +
  " | SinkCallLoc: " + sink.getNode().getLocation().toString()
