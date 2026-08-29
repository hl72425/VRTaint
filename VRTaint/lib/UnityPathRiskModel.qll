/** Official tainted-path adapter with project-code filtering. */
import csharp
import semmle.code.csharp.security.dataflow.TaintedPathQuery

module UnityPathRiskModel {
  /** Project-relevant effectful official sinks. Pure Exists checks are excluded. */
  private predicate isEffectfulOfficialSink(DataFlow::Node sink) {
    sink instanceof Sink and
    not exists(MethodCall check |
      sink = DataFlow::exprNode(check.getAnArgument()) and
      check.getTarget().getName() = "Exists"
    )
  }

  /** WebClient.DownloadFile writes its second argument but is absent from older official models. */
  private predicate isWebClientDownloadPath(DataFlow::Node sink) {
    exists(MethodCall call |
      call.getTarget().getName() = "DownloadFile" and
      call.getTarget().getDeclaringType().getName() = "WebClient" and
      call.getTarget().getDeclaringType().getNamespace().getName() = "System.Net" and
      call.getNumberOfArguments() >= 2 and
      sink = DataFlow::exprNode(call.getArgument(1))
    )
  }

  predicate isSink(DataFlow::Node sink) {
    isEffectfulOfficialSink(sink) or isWebClientDownloadPath(sink)
  }
  predicate isBarrier(DataFlow::Node node) { node instanceof Sanitizer }
  predicate isProjectOwnedNode(DataFlow::Node node) {
    exists(Callable c |
      c = node.getEnclosingCallable() and c.fromSource() and
      not c.getFile().getRelativePath().matches("%/Tests/%") and
      not c.getFile().getRelativePath().matches("%/Test/%") and
      not c.getFile().getRelativePath().matches("%/Samples/%") and
      not c.getFile().getRelativePath().matches("%/Examples/%") and
      not c.getFile().getRelativePath().matches("%/AOTGenerated/%")
    )
  }
}
