/**
 * @name External file-write path coexists with an automatic script-loading surface
 * @description An external HTTP/network input controls a file-write path and the same application
 *              recursively enumerates script files and constructs a script interpreter. This is a review
 *              candidate: root containment must be proven before treating it as script execution.
 * @kind path-problem
 * @id cs/unity-script-write-execution
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @tags security external/cwe/cwe-022 external/cwe/cwe-094
 */

import csharp
import lib.UnityExternalInput
import lib.UnityPathRiskModel

private predicate archiveEntryPathSource(DataFlow::Node source) {
  exists(PropertyAccess access |
    source = DataFlow::exprNode(access) and
    (
      access.getTarget().getName() = "FullName" and
      access.getTarget().getDeclaringType().getName() = "ZipArchiveEntry"
      or
      access.getTarget().getName() = "Name" and
      access.getTarget().getDeclaringType().getName().regexpMatch(".*ZipEntry.*") and
      access.getTarget().getDeclaringType().getNamespace().getName().regexpMatch(
        "ICSharpCode[.]SharpZipLib([.].*)?"
      )
    )
  )
}

private predicate scriptWriteSourceKind(DataFlow::Node source, string kind) {
  UnityExternalInput::sourceKind(source, kind)
  or
  archiveEntryPathSource(source) and
  kind = "ArchiveEntryPath"
}

private predicate hasAutomaticScriptLoader() {
  exists(MethodCall enumerate, Expr pattern, Expr recursive |
    enumerate.getTarget().getName() in ["GetFiles", "EnumerateFiles"] and
    pattern = enumerate.getAnArgument().getAChildExpr*() and
    pattern.toString().toLowerCase().regexpMatch(".*(lua|javascript|python).*" ) and
    recursive = enumerate.getAnArgument().getAChildExpr*() and
    recursive.toString().regexpMatch(".*AllDirectories.*")
  ) and
  exists(ObjectCreation interpreter |
    interpreter.getObjectType().getName().toLowerCase().regexpMatch(
      ".*(script|interpreter|lua|moonsharp|javascript|python).*"
    )
  )
  or
  // Direct file-to-interpreter execution, for applications that use fixed
  // script entry names (for example init.lua) instead of directory scans.
  exists(MethodCall execute, MethodCall read |
    execute.getTarget().getName().toLowerCase().regexpMatch(
      "(dostring|eval|evaluate|executestring|runscript|loadstring)"
    ) and
    read.getTarget().getName() in ["ReadAllText", "ReadToEnd"] and
    read = execute.getAnArgument().getAChildExpr*()
  )
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(string kind | scriptWriteSourceKind(source, kind)) and
    UnityExternalInput::isRuntimeNode(source)
  }
  predicate isSink(DataFlow::Node sink) {
    UnityPathRiskModel::isSink(sink) and UnityPathRiskModel::isProjectOwnedNode(sink) and
    hasAutomaticScriptLoader()
  }
  predicate isBarrier(DataFlow::Node node) { UnityPathRiskModel::isBarrier(node) }
}

module Tracking = TaintTracking::Global<Config>;
import Tracking::PathGraph

from Tracking::PathNode source, Tracking::PathNode sink, string kind,
     string objectId, string fieldPath, string phase, string context
where
  Tracking::flowPath(source, sink) and
  scriptWriteSourceKind(source.getNode(), kind) and
  UnityExternalInput::objectId(source.getNode(), objectId) and
  UnityExternalInput::fieldPath(source.getNode(), fieldPath) and
  UnityExternalInput::phase(source.getNode(), phase) and
  UnityExternalInput::context(source.getNode(), context)
select sink.getNode(), source, sink,
  "External path data reaches a file write in an application that automatically loads scripts. " +
  "Tuple=<" + objectId + ", " + fieldPath + ", " + phase + ", " + context + ", " + kind + ">."
