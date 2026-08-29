/** Official command-injection adapter with project-code filtering. */
import csharp
import semmle.code.csharp.security.dataflow.CommandInjectionQuery

module UnityCommandRiskModel {
  predicate isSink(DataFlow::Node sink) { sink instanceof Sink }
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

