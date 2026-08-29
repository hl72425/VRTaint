/**
 * @name UnityLifecycleBase
 * @description Base library for defining Unity MonoBehaviour lifecycle methods and baseline topological sorting order.
 */
import csharp

/** A project-owned instance method on a MonoBehaviour implementation. */
private predicate isMonoBehaviourMessageCandidate(Method m) {
  m.fromSource() and
  not m.isStatic() and
  m.getDeclaringType().getABaseType*().hasFullyQualifiedName("UnityEngine", "MonoBehaviour")
}

/** Unity messages that have no parameters. */
private predicate isParameterlessUnityMessage(string name) {
  name in [
    "Reset", "Awake", "OnEnable", "Start", "FixedUpdate", "Update", "LateUpdate",
    "OnMouseDown", "OnMouseUp", "OnMouseEnter", "OnMouseOver", "OnMouseExit", "OnMouseDrag",
    "OnPreCull", "OnBecameVisible", "OnBecameInvisible", "OnWillRenderObject",
    "OnPreRender", "OnRenderObject", "OnPostRender", "OnGUI",
    "OnApplicationQuit", "OnDisable", "OnDestroy", "OnAnimatorMove"
  ]
}

/** Parameter shape of the Unity messages covered by this library. */
private predicate hasUnityMessageParameterShape(Method m, string name) {
  isParameterlessUnityMessage(name) and m.getNumberOfParameters() = 0
  or
  name in ["OnTriggerEnter", "OnTriggerExit", "OnTriggerStay"] and
  m.getNumberOfParameters() = 1 and
  m.getParameter(0).getType().hasFullyQualifiedName("UnityEngine", "Collider")
  or
  name in ["OnCollisionEnter", "OnCollisionExit", "OnCollisionStay"] and
  m.getNumberOfParameters() = 1 and
  m.getParameter(0).getType().hasFullyQualifiedName("UnityEngine", "Collision")
  or
  name = "OnApplicationPause" and m.getNumberOfParameters() = 1 and
  m.getParameter(0).getType() instanceof BoolType
  or
  name = "OnAnimatorIK" and m.getNumberOfParameters() = 1 and
  m.getParameter(0).getType() instanceof IntType
  or
  name = "OnRenderImage" and m.getNumberOfParameters() = 2 and
  m.getParameter(0).getType().hasFullyQualifiedName("UnityEngine", "RenderTexture") and
  m.getParameter(1).getType().hasFullyQualifiedName("UnityEngine", "RenderTexture")
}

/**
 * Unity message return shape. Start is the sole callback in this catalog that
 * may be a coroutine; all remaining callbacks return void.
 */
private predicate hasUnityMessageReturnShape(Method m, string name) {
  name = "Start" and
  (
    m.getReturnType() instanceof VoidType
    or m.getReturnType().hasFullyQualifiedName("System.Collections", "IEnumerator")
  )
  or
  name = m.getName() and name != "Start" and m.getReturnType() instanceof VoidType
}

predicate isUnityLifecycleMethod(Method m, string lifecycleName) {
  exists(string name |
    name = m.getName() and
    name.regexpMatch(
      "^(Reset|Awake|OnEnable|Start|" +
      "FixedUpdate|OnTriggerEnter|OnTriggerExit|OnTriggerStay|" +
      "OnCollisionEnter|OnCollisionExit|OnCollisionStay|" +
      "OnMouseDown|OnMouseUp|OnMouseEnter|OnMouseOver|OnMouseExit|OnMouseDrag|" +
      "Update|LateUpdate|" +
      "OnPreCull|OnBecameVisible|OnBecameInvisible|OnWillRenderObject|" +
      "OnPreRender|OnRenderObject|OnPostRender|OnRenderImage|" +
      "OnGUI|" +
      "OnApplicationPause|OnApplicationQuit|OnDisable|OnDestroy|" +
      "OnAnimatorIK|OnAnimatorMove)$"
    ) and
    isMonoBehaviourMessageCandidate(m) and
    hasUnityMessageParameterShape(m, name) and
    hasUnityMessageReturnShape(m, name) and
    lifecycleName = name
  )
}

/**
 * Callbacks that can be observed repeatedly while a component remains alive.
 * Any pair in this set may be separated by a frame, a physics tick, a render
 * pass, or a disable/re-enable cycle; this is a may-order, not a must-order.
 */
predicate isRecurringLifecycleName(string name) {
  name in [
    "OnEnable", "FixedUpdate",
    "OnTriggerEnter", "OnTriggerExit", "OnTriggerStay",
    "OnCollisionEnter", "OnCollisionExit", "OnCollisionStay",
    "OnMouseDown", "OnMouseUp", "OnMouseEnter", "OnMouseOver", "OnMouseExit", "OnMouseDrag",
    "Update", "LateUpdate", "OnPreCull", "OnBecameVisible", "OnBecameInvisible",
    "OnWillRenderObject", "OnPreRender", "OnRenderObject", "OnPostRender", "OnRenderImage",
    "OnGUI", "OnApplicationPause", "OnDisable", "OnAnimatorIK", "OnAnimatorMove"
  ]
}

/** Ordered engine phases and activation/deactivation callbacks. */
predicate isDeterministicLifecyclePhaseName(string name) {
  name in [
    "Awake", "OnEnable", "Start", "FixedUpdate", "Update", "LateUpdate",
    "OnDisable", "OnDestroy"
  ]
}

/** Runtime-event-dependent MonoBehaviour messages; never a MustBetween phase. */
predicate isConditionalLifecycleEventName(string name) {
  name in [
    "OnTriggerEnter", "OnTriggerExit", "OnTriggerStay",
    "OnCollisionEnter", "OnCollisionExit", "OnCollisionStay",
    "OnMouseDown", "OnMouseUp", "OnMouseEnter", "OnMouseOver", "OnMouseExit", "OnMouseDrag",
    "OnPreCull", "OnBecameVisible", "OnBecameInvisible", "OnWillRenderObject",
    "OnPreRender", "OnRenderObject", "OnPostRender", "OnRenderImage",
    "OnGUI", "OnApplicationPause", "OnAnimatorIK", "OnAnimatorMove"
  ]
}

/**
 * Bounded conditional-event may-order. Event callbacks may be followed by a
 * later engine tick, and the same callback may recur. This does not promote an
 * event callback into the deterministic MustBetween relation.
 */
predicate conditionalLifecycleEventMayFollow(string earlier, string later) {
  isConditionalLifecycleEventName(earlier) and
  later in ["FixedUpdate", "Update", "LateUpdate"]
  or
  earlier = later and isConditionalLifecycleEventName(earlier)
}

/** Finite name-level lifecycle reachability, including later frames/re-enable. */
predicate lifecycleMayFollow(string earlier, string later) {
  lifecycleOrder(earlier, later)
  or isRecurringLifecycleName(earlier) and isRecurringLifecycleName(later)
}

/**
 * Explicit may-order relation used only to add propagation edges. It must never
 * be used as evidence that an intermediate callback executes on every path.
 */
predicate lifecycleMayOrder(string earlier, string later) {
  lifecycleMayFollow(earlier, later)
}

/**
 * Small, closed must-between relation used only for definite lifecycle kills.
 * Conditional physics/UI callbacks and re-enable cycles are intentionally absent.
 */
bindingset[beforeName, middleName, afterName]
predicate lifecycleMustBetween(
  string beforeName, string middleName, string afterName
) {
  isDeterministicLifecyclePhaseName(beforeName) and
  isDeterministicLifecyclePhaseName(middleName) and
  isDeterministicLifecyclePhaseName(afterName) and
  (
    beforeName = "Awake" and middleName = "OnEnable" and
    afterName in ["Start", "Update", "LateUpdate"]
    or
    beforeName = "Awake" and middleName = "Start" and
    afterName in ["Update", "LateUpdate"]
    or
    beforeName = "Start" and middleName = "Update" and afterName = "LateUpdate"
  )
}

predicate lifecycleOrder(string earlier, string later) {
  /* ---- Initialization Phase ---- */
  earlier = "Awake" and later in [
    "OnEnable", "Start",
    "FixedUpdate", "Update", "LateUpdate",
    "OnPreCull", "OnBecameVisible", "OnBecameInvisible", "OnWillRenderObject",
    "OnPreRender", "OnRenderObject", "OnPostRender", "OnRenderImage",
    "OnGUI",
    "OnApplicationPause", "OnApplicationQuit", "OnDisable", "OnDestroy"
  ]
  or earlier = "OnEnable" and later in [
    "Start",
    "FixedUpdate", "Update", "LateUpdate",
    "OnPreCull", "OnBecameVisible", "OnBecameInvisible", "OnWillRenderObject",
    "OnPreRender", "OnRenderObject", "OnPostRender", "OnRenderImage",
    "OnGUI",
    "OnApplicationPause", "OnApplicationQuit", "OnDisable", "OnDestroy"
  ]
  or earlier = "Start" and later in [
    "FixedUpdate", "Update", "LateUpdate",
    "OnPreCull", "OnBecameVisible", "OnBecameInvisible", "OnWillRenderObject",
    "OnPreRender", "OnRenderObject", "OnPostRender", "OnRenderImage",
    "OnGUI",
    "OnApplicationPause", "OnApplicationQuit", "OnDisable", "OnDestroy"
  ]
  /* ---- Physics Phase ---- */
  or earlier = "FixedUpdate" and later in [
    "Update", "LateUpdate",
    "OnPreCull", "OnBecameVisible", "OnBecameInvisible", "OnWillRenderObject",
    "OnPreRender", "OnRenderObject", "OnPostRender", "OnRenderImage",
    "OnGUI",
    "OnApplicationPause", "OnApplicationQuit", "OnDisable", "OnDestroy"
  ]
  or earlier = "FixedUpdate" and later = "FixedUpdate"  // Self-loop
  or earlier = "FixedUpdate" and later in [
    "OnTriggerEnter", "OnTriggerExit", "OnTriggerStay",
    "OnCollisionEnter", "OnCollisionExit", "OnCollisionStay"
  ]
  or earlier = "FixedUpdate" and later in [
    "OnMouseDown", "OnMouseUp", "OnMouseEnter", "OnMouseOver", "OnMouseExit", "OnMouseDrag"
  ]
  /* ---- Game Logic Phase ---- */
  or earlier = "Update" and later in [
    "LateUpdate",
    "OnPreCull", "OnBecameVisible", "OnBecameInvisible", "OnWillRenderObject",
    "OnPreRender", "OnRenderObject", "OnPostRender", "OnRenderImage",
    "OnGUI",
    "OnApplicationPause", "OnApplicationQuit", "OnDisable", "OnDestroy"
  ]
  or earlier = "Update" and later = "Update" // Self-loop
  or earlier = "LateUpdate" and later in [
    "OnPreCull", "OnBecameVisible", "OnBecameInvisible", "OnWillRenderObject",
    "OnPreRender", "OnRenderObject", "OnPostRender", "OnRenderImage",
    "OnGUI",
    "OnApplicationPause", "OnApplicationQuit", "OnDisable", "OnDestroy"
  ]
  or earlier = "LateUpdate" and later = "LateUpdate"  // Self-loop
  /* ---- Rendering Phase ---- */
  or earlier = "OnPreCull" and later in [
    "OnBecameVisible", "OnBecameInvisible", "OnWillRenderObject",
    "OnPreRender", "OnRenderObject", "OnPostRender", "OnRenderImage"
  ]
  or earlier = "OnWillRenderObject" and later in [
    "OnPreRender", "OnRenderObject", "OnPostRender", "OnRenderImage"
  ]
  or earlier = "OnPreRender" and later in ["OnRenderObject", "OnPostRender", "OnRenderImage"]
  or earlier = "OnRenderObject" and later in ["OnPostRender", "OnRenderImage"]
  or earlier = "OnPostRender" and later = "OnRenderImage"
  /* ---- UI Phase ---- */
  or earlier = "OnGUI" and later = "OnGUI"  // Self-loop
  /* ---- Decommission / Destruction Phase ---- */
  or earlier = "OnDisable" and later = "OnDestroy"
  or earlier = "Reset" and later in ["Awake", "OnEnable", "Start"]
}

predicate isNextLifecycleStation(Method m1, Method m2, string n1, string n2) {
  m1.getDeclaringType() = m2.getDeclaringType() and
  isUnityLifecycleMethod(m1, n1) and
  isUnityLifecycleMethod(m2, n2) and
  lifecycleOrder(n1, n2) and
  
  not exists(Method mMid, string nMid |
    mMid.getDeclaringType() = m1.getDeclaringType() and
    m1.getDeclaringType().getAMember() = mMid and 
    mMid.fromSource() and
    
    // Prevents self-loop logical deadlocks (e.g., Update -> Update -> Update)
    mMid != m2 and mMid != m1 and
    
    isUnityLifecycleMethod(mMid, nMid) and
    lifecycleOrder(n1, nMid) and
    lifecycleOrder(nMid, n2)
  )
}

// Explicit transitive call chain resolution
predicate hasCalleeTransitive(Callable start, Callable target) {
    // 1-layer call: 'start' directly invokes 'target' inside its body
    exists(MethodCall mc |
        mc.getEnclosingCallable() = start and
        target = mc.getTarget()
    )
    or
    // Multi-layer call: 'start' invokes 'mid', and 'mid' transitively invokes 'target'
    exists(Callable mid |
        exists(MethodCall mc |
            mc.getEnclosingCallable() = start and
            mid = mc.getTarget()
        ) and
        hasCalleeTransitive(mid, target)
    )
}
