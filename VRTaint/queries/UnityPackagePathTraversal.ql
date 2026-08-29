/**
 * @name Unitypackage pathname traversal during editor import
 * @description A pathname read from an extracted Unity package is combined with the selected
 *              output root and used by File.Move without canonical root containment.
 * @kind problem
 * @id cs/unitypackage-path-traversal
 * @problem.severity warning
 * @security-severity 6.5
 * @precision high
 * @tags security external/cwe/cwe-022
 */

import csharp
import semmle.code.csharp.security.dataflow.TaintedPathQuery

private predicate pathnameRead(MethodCall read) {
  read.getTarget().getName() = "ReadLine" and
  exists(ObjectCreation reader, StringLiteral literal |
    reader.getObjectType().getName() = "StreamReader" and
    DataFlow::localExprFlow(reader, read.getQualifier()) and
    literal.getEnclosingCallable() = read.getEnclosingCallable() and
    literal.getValue().toLowerCase() = "pathname"
  )
}

private predicate pathCombine(MethodCall combine, MethodCall read) {
  combine.getTarget().getName() in ["Combine", "Join"] and
  combine.getTarget().getDeclaringType().getName() = "Path" and
  exists(LocalVariable contents, VariableAccess targetAccess |
    contents.getInitializer() = read and
    targetAccess = combine.getAnArgument().getAChildExpr*() and
    targetAccess.getTarget() = contents
  )
}

private predicate fileMove(MethodCall move, MethodCall combine) {
  move.getTarget().getName() = "Move" and
  move.getTarget().getDeclaringType().getName() in ["File", "Directory"] and
  DataFlow::localFlow(DataFlow::exprNode(combine), DataFlow::exprNode(move.getAnArgument()))
}

private predicate hasContainmentCheck(Method method) {
  exists(MethodCall check |
    check.getEnclosingCallable() = method and
    check.getTarget().getName() in ["GetFullPath", "StartsWith", "GetRelativePath"]
  )
}

from MethodCall read, MethodCall combine, MethodCall move
where pathnameRead(read) and pathCombine(combine, read) and fileMove(move, combine) and
  read.getEnclosingCallable() = move.getEnclosingCallable() and
  not hasContainmentCheck(read.getEnclosingCallable().(Method))
select move,
  "Unitypackage pathname reaches File.Move outside a canonical root-containment check. " +
  "Tuple=<" + read.getEnclosingCallable().getDeclaringType().getName() +
  "#*, package.pathname, " + read.getEnclosingCallable().getName() +
  ", {\"schema\":\"unity-context/v1\",\"project\":\"UNKNOWN\",\"scene\":\"EDITOR\"," +
  "\"game_object\":\"UNKNOWN\",\"component\":\"" +
  read.getEnclosingCallable().getDeclaringType().getName() + "#*\",\"script\":\"" +
  read.getFile().getRelativePath() + "\",\"entry\":\"" + read.getEnclosingCallable().getName() +
  "\",\"callable\":\"" + read.getEnclosingCallable().getName() +
  "\",\"event\":\"EditorImport\",\"thread\":\"UNKNOWN\"," +
  "\"coroutine\":\"UNKNOWN\",\"async\":\"UNKNOWN\"}, UnityPackageEntry>."
