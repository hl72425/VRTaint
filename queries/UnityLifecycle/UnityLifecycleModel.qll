/**
 * UnityLifecycleModel.qll
 * Library: models Unity lifecycle callbacks for C# (Unity VR) projects.
 * Usage: import csharp; import UnityLifecycleModel; then call predicates like isLifecycleEntry(m)
 */

import csharp

module UnityLifecycleModel {

  /** MonoBehaviour subclass detection. Uses the C# library API getASuperType*() */
  class MonoBehaviourSubclass extends Class {
    MonoBehaviourSubclass() {
      exists(ValueOrRefType sup |
        sup.getName() = "MonoBehaviour" and
        this.getASuperType*() = sup
      )
    }
  }

  /** Recognize common Unity lifecycle methods on MonoBehaviour subclasses */
  predicate isUnityLifecycleMethod(Method m) {
    m.getDeclaringType() instanceof MonoBehaviourSubclass and
    (
      m.getName() = "Awake" or
      m.getName() = "OnEnable" or
      m.getName() = "Start" or
      m.getName() = "Update" or
      m.getName() = "FixedUpdate" or
      m.getName() = "LateUpdate" or
      m.getName() = "OnDisable" or
      m.getName() = "OnDestroy" or
      m.getName() = "OnApplicationPause" or
      m.getName() = "OnApplicationQuit"
    )
  }

  /** Recognize a simple XR loader lifecycle signature */
  predicate isXRLoaderLifecycle(Method m) {
    m.getDeclaringType().getName().matches("%XRLoader%") and
    (
      m.getName() = "Initialize" or
      m.getName() = "Start" or
      m.getName() = "Stop" or
      m.getName() = "Deinitialize"
    )
  }

  /** Coroutine detection: methods returning IEnumerator (Unity coroutines) */
  predicate isCoroutine(Method m) {
    exists(Type r | m.getReturnType() = r and r.getName().matches("%IEnumerator%"))
  }

  /** Detect simple SceneManager.sceneLoaded subscription calls */
  predicate subscribesSceneLoaded(Method m) {
    exists(Call c |
      c.getMethod().getDeclaringType().getName().matches("%SceneManager%") and
      c.getMethod().getName().matches("add_sceneLoaded%") and
      c.getEnclosingCallable() = m
    )
  }

  /** Unified lifecycle entry predicate */
  predicate isLifecycleEntry(Method m) {
    isUnityLifecycleMethod(m) or isXRLoaderLifecycle(m) or isCoroutine(m) or subscribesSceneLoaded(m)
  }

}