/**
 * @name UnityBenchmarkSourceSink
 * @description Synthetic benchmark-only source, sink, and marker-barrier model.
 *              Production queries must import UnityStandardSourceSink instead.
 */

import csharp

module UnityBenchmarkSourceSink {
  predicate isSourceKind(DataFlow::Node source, string kind) {
    exists(MethodCall mc |
      mc.getTarget().getDeclaringType().hasName("TestSources") and
      mc.getTarget().getName() in ["GetUIInput", "GetNetworkInput", "GetFileContent", "GetCmdArgs"] and
      source = DataFlow::exprNode(mc) and
      (
        mc.getTarget().hasName("GetUIInput") and kind = "user-text" or
        mc.getTarget().hasName("GetNetworkInput") and kind = "network-body" or
        mc.getTarget().hasName("GetFileContent") and kind = "file-content" or
        mc.getTarget().hasName("GetCmdArgs") and kind = "cmd-arg"
      )
    )
  }

  predicate isSinkKind(DataFlow::Node sink, string kind) {
    exists(MethodCall mc |
      mc.getTarget().getDeclaringType().hasName("TestSinks") and
      mc.getTarget().hasName("DangerousLoad") and
      sink = DataFlow::exprNode(mc.getArgument(0)) and kind = "resource-path"
    )
    or
    exists(MethodCall mc |
      mc.getTarget().getDeclaringType().hasName("TestSinks") and
      mc.getTarget().hasName("DangerousFileWrite") and
      (
        sink = DataFlow::exprNode(mc.getArgument(0)) and kind = "file-path" or
        sink = DataFlow::exprNode(mc.getArgument(1)) and kind = "file-content"
      )
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    node.getLocation().getFile().getRelativePath().matches("%_TestCases/%") and
    exists(MethodCall call |
      call.getTarget().getName() in ["ToUpper", "ToLower"] and
      node = DataFlow::exprNode(call)
    )
    or
    exists(Location loc |
      loc = node.getLocation() and
      exists(DataFlow::Node other |
        other != node and other.getLocation() = loc and
        (isSource(node) and isSink(other) or isSource(other) and isSink(node))
      )
    )
    or isSource(node) and isSink(node)
  }

  predicate isSource(DataFlow::Node source) { isSourceKind(source, _) }
  predicate isSink(DataFlow::Node sink) { isSinkKind(sink, _) }
}
