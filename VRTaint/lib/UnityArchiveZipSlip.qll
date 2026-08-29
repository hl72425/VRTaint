/**
 * @name UnityArchiveZipSlip
 * @description High-precision archive-entry path sources for Unity SharpZipLib variants.
 *              Sinks and sanitizers are reused from CodeQL's official ZipSlipQuery library.
 */

import csharp
import semmle.code.csharp.security.dataflow.ZipSlipQuery

private predicate isSupportedSharpZipLibNamespace(string ns) {
  ns = "Unity.SharpZipLib.Zip"
  or
  ns = "ICSharpCode.SharpZipLib.Zip"
}

/** Official System.IO.Compression source, exposed here so the unified query uses VRTaint flow. */
private predicate isSystemZipArchiveEntryPath(PropertyAccess access) {
  access.getTarget().getDeclaringType().hasFullyQualifiedName(
    "System.IO.Compression", "ZipArchiveEntry"
  ) and
  access.getTarget().getName() in ["FullName", "Name"]
}

/** A resolved access to ZipEntry.Name from a supported SharpZipLib namespace. */
private predicate isResolvedSharpZipEntryName(PropertyAccess access) {
  exists(string ns |
    isSupportedSharpZipLibNamespace(ns) and
    access.getTarget().getDeclaringType().hasFullyQualifiedName(ns, "ZipEntry") and
    access.getTarget().hasName("Name")
  )
}

/**
 * A narrow structural fallback for unresolved SharpZipLib symbols.
 *
 * Precision guards:
 *  - the property target is unresolved;
 *  - the qualifier is the variable declared by a foreach loop;
 *  - element/iterable names carry archive semantics;
 *  - the archive object is invoked with the current entry inside the loop.
 *
 * The final query also requires flow into an official Zip Slip file sink.
 */
private predicate isUnresolvedSharpZipEntryPath(PropertyAccess access) {
  not exists(access.getTarget()) and
  exists(
    ForeachStmt loop, VariableAccess entryAccess, VariableAccess iterableAccess,
    MethodCall archiveEntryCall, VariableAccess archiveQualifier, VariableAccess entryArgument
  |
    access.getQualifier().stripCasts() = entryAccess and
    entryAccess.getTarget() = loop.getVariable() and
    loop.getVariable().getName().toLowerCase() in ["entry", "zipentry", "archiveentry"] and
    loop.getIterableExpr().stripCasts() = iterableAccess and
    iterableAccess.getTarget().getName().toLowerCase().regexpMatch(".*(zip|archive).*") and

    // Structural archive evidence: the iterable object is also called with the
    // current entry as an argument inside the loop (for example GetInputStream(entry)).
    archiveEntryCall.getParent+() = loop and
    archiveEntryCall.getQualifier().stripCasts() = archiveQualifier and
    archiveQualifier.getTarget() = iterableAccess.getTarget() and
    archiveEntryCall.getAnArgument().stripCasts() = entryArgument and
    entryArgument.getTarget() = loop.getVariable()
  )
}

/**
 * An attacker-controlled archive entry path supplied by Unity SharpZipLib.
 * Extending the official Source class keeps the model compatible with official sinks/sanitizers.
 */
class UnitySharpZipEntryPathSource extends Source {
  UnitySharpZipEntryPathSource() {
    exists(PropertyAccess access |
      this.asExpr() = access and
      (
        isSystemZipArchiveEntryPath(access)
        or
        isResolvedSharpZipEntryName(access)
        or
        isUnresolvedSharpZipEntryPath(access)
      )
    )
  }
}

/** The pathname file inside a Unity .unitypackage controls the final import target. */
class UnityPackagePathnameSource extends Source {
  UnityPackagePathnameSource() {
    exists(MethodCall read, Method m, Expr qualifier, LocalVariable pathnamePath |
      m = read.getTarget() and m.getName() in ["ReadLine", "ReadToEnd"] and
      qualifier = read.getQualifier() and
      exists(ObjectCreation reader, VariableAccess pathAccess |
        reader.getObjectType().getName() in ["StreamReader", "FileStream"] and
        pathAccess = reader.getAnArgument().getAChildExpr*() and
        pathAccess.getTarget() = pathnamePath and
        DataFlow::localExprFlow(reader, qualifier)
      ) and
      exists(StringLiteral pathnameLiteral |
        pathnameLiteral = pathnamePath.getInitializer().getAChildExpr*() and
        pathnameLiteral.getValue().toLowerCase() = "pathname"
      ) and
      this.asExpr() = read
    )
  }
}

/** Holds for a Unity-specific archive entry path source. */
predicate isUnityArchiveEntryPathSource(DataFlow::Node source) {
  source instanceof UnitySharpZipEntryPathSource
  or source instanceof UnityPackagePathnameSource
}


