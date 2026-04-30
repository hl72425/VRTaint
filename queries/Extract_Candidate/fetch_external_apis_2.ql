/**
 * @name Unity VR External API Extraction
 * @description Extracts external API calls from Unity VR C# projects for taint analysis.
 * @kind select
 * @tags unity, vr, taint, api
 */

import csharp
import semmle.code.csharp.dataflow.internal.DataFlowImpl

/** Determine if a method call is external (not from Unity internal namespaces). */
predicate isExternalCall(MethodAccess ma) {
  exists(Method m | ma.getTarget() = m |
    not m.getDeclaringType().getNamespace().matches("UnityEngine%") and
    not m.getDeclaringType().getNamespace().matches("UnityEditor%") and
    not m.getDeclaringType().getNamespace().matches("System%") and
    not m.getDeclaringType().getNamespace().matches("Microsoft%") and
    not m.getDeclaringType().getNamespace().matches("TMPro%") and
    not m.getDeclaringType().getNamespace().matches("NUnit%") and
    not m.getDeclaringType().getNamespace().matches("Moq%")
  )
}

/** Build a readable parameter signature string */
string paramTypes(Method m) {
  result = concat(int i |
    i in [0 .. m.getNumberOfParameters() - 1] |
    m.getParameter(i).getType().getName(), ";"
  )
}

/** Build full method signature */
string fullSignature(Method m) {
  result = m.getReturnType().getName() + " " + m.getDeclaringType().getName() + "." +
    m.getName() + "(" +
    concat(int i |
      i in [0 .. m.getNumberOfParameters() - 1] |
      m.getParameter(i).getType().getName() + " " + m.getParameter(i).getName(), ", "
    ) + ")"
}

/** Whether the method is static */
string isStaticAsString(Method m) {
  result = m.isStatic() ? "true" : "false"
}

/** Extract documentation string if available (simplified) */
string getDoc(Method m) {
  exists(string doc | m.getDocCommentText() = doc | result = doc)
  or result = ""
}

from MethodAccess call, Method callee, string fSig, string pTypes, string retType, string isStatic, string doc
where
  call.getTarget() = callee and
  isExternalCall(call) and
  not callee.getDeclaringType().getName() = "Object" and
  fSig = fullSignature(callee) and
  pTypes = paramTypes(callee) and
  retType = callee.getReturnType().getName() and
  isStatic = isStaticAsString(callee) and
  doc = getDoc(callee)
select
  call,
  callee.getDeclaringType().getNamespace() as package,
  callee.getDeclaringType() as class,
  callee.getName() as method,
  fSig as full_signature,
  pTypes as parameter_types,
  retType as return_type,
  isStatic as is_static,
  call.getFile().getRelativePath() as file,
  call.getLocation().toString() as location,
  doc as documentation
