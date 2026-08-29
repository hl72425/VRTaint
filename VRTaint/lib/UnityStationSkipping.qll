/**
 * @name UnityStationSkipping
 * @description Compatibility view of transparent lifecycle may-flow.
 */

import csharp
import UnityLifecycleBase

private predicate lifecycleStationStep(Method before, Method after) {
  exists(string beforeName, string afterName |
    isNextLifecycleStation(before, after, beforeName, afterName)
  )
}

/**
 * Holds if a field may persist from lifecycle method `m1` to `m2`.
 * Intermediate callbacks are transparent here. Definite clean kills are decided
 * only by VRTaintFlowFramework after proving clean value, strong update,
 * all-path execution, and stability.
 */
predicate isTaintBleedingThroughLifecycle(Method m1, Method m2, string n1, string n2, Field f) {
  m1.getDeclaringType() = m2.getDeclaringType() and
  isUnityLifecycleMethod(m1, n1) and
  isUnityLifecycleMethod(m2, n2) and
  (
    lifecycleStationStep+(m1, m2)
    or lifecycleMayOrder(n1, n2)
  ) and
  exists(FieldAccess access |
    access.getTarget() = f and access.getEnclosingCallable() in [m1, m2]
  )
}
