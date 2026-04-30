/**
 * @name Unity Lifecycle, Reflection & VR/XR Pattern Analysis
 * @description Detects Unity callback definitions, reflection/dynamic API calls, coroutine usage, and VR-specific interaction patterns.
 * @kind problem
 * @id cs/unity/execution-flow-analysis
 * @problem.severity warning
 * @precision high
 * @tags unity
 * @tags vr
 * @tags security
 */

import csharp

// ==========================================
// 1. 基础谓词：识别 MonoBehaviour 派生类
// ==========================================
predicate isMonoBehaviour(Class c) {
  // C# 使用 getABaseType() 获取父类，使用 hasFullyQualifiedName 判断完整路径
  c.getABaseType*().hasFullyQualifiedName("UnityEngine", "MonoBehaviour")
}

// ==========================================
// 2. Unity 生命周期 & 引擎回调定义
// ==========================================
class UnityCallbackMethod extends Method {
  UnityCallbackMethod() {
    isMonoBehaviour(this.getDeclaringType()) or
    (
      // 无参标准回调
      (this.getName() in [
        "Awake", "OnEnable", "Start", "FixedUpdate", "Update", "LateUpdate",
        "OnDisable", "OnDestroy", "OnGUI", "OnRenderObject",
        "OnApplicationPause", "OnApplicationQuit", "OnApplicationFocus",
        "OnValidate", "OnBecameVisible", "OnBecameInvisible",
        "OnPreCull", "OnPreRender", "OnPostRender", "OnRenderImage",
        "OnAudioFilterRead", "OnTransformParentChanged", "OnTransformChildrenChanged",
        "OnCanvasGroupChanged", "OnRectTransformDimensionsChange"
      ] and this.getNumberOfParameters() = 0)
      or
      // 碰撞/触发器回调 (1个参数)
      (this.getName() in [
        "OnTriggerEnter", "OnTriggerStay", "OnTriggerExit",
        "OnTriggerEnter2D", "OnTriggerStay2D", "OnTriggerExit2D",
        "OnCollisionEnter", "OnCollisionStay", "OnCollisionExit",
        "OnCollisionEnter2D", "OnCollisionStay2D", "OnCollisionExit2D",
        "OnParticleCollision", "OnJointBreak", "OnJointBreak2D",
        "OnAnimatorIK", "OnAnimatorMove"
      ] and this.getNumberOfParameters() = 1)
      or
      // 鼠标交互回调
      (this.getName() in [
        "OnMouseEnter", "OnMouseOver", "OnMouseExit",
        "OnMouseDown", "OnMouseUp", "OnMouseDrag", "OnMouseUpAsButton"
      ] and this.getNumberOfParameters() = 0)
    )
  }
}

// ==========================================
// 3. Unity 反射 & 动态 API 调用
// ==========================================
class UnityReflectionCall extends MethodCall { // C# 中函数调用为 MethodCall
  UnityReflectionCall() {
    this.getTarget().hasName([
      "AddComponent", "GetComponent", "GetComponents", 
      "GetComponentInChildren", "GetComponentInParent", "TryGetComponent",
      "SetActive", "Find", "FindWithTag", "FindGameObjectsWithTag",
      "Destroy", "DestroyImmediate", "Instantiate", "DontDestroyOnLoad",
      "LoadScene", "LoadSceneAsync", "SetActiveScene", "UnloadScene",
      "Invoke", "InvokeRepeating", "CancelInvoke",
      "SendMessage", "SendMessageUpwards", "BroadcastMessage",
      "Load", "LoadAsync", "LoadAsset", "LoadAssetAsync"
    ]) or
    // 使用 matches 模糊匹配 UnityEngine 及其子命名空间
    this.getTarget().getDeclaringType().getNamespace().getName().matches("UnityEngine%")
  }

  // 是否为字符串参数调用（高风险：易拼写错误、重构断裂、难以静态追踪）
  predicate isStringBased() {
    exists(Expr arg | arg = this.getArgument(0) | arg.getType() instanceof StringType)
  }

  // 泛型调用获取的目标类型
  Type getGenericTargetType() { 
    // 获取泛型参数
    result = this.getTarget().(ConstructedMethod).getATypeArgument()
  }
}

// ==========================================
// 4. 协程机制 (StartCoroutine & Yield)
// ==========================================
class UnityStartCoroutineCall extends MethodCall {
  UnityStartCoroutineCall() {
    this.getTarget().hasName("StartCoroutine") or
    isMonoBehaviour(this.getTarget().getDeclaringType())
  }
  
  string getCoroutineArgType() {
    result = this.getArgument(0).getType().getName()
  }
}

class UnityYieldStatement extends YieldReturnStmt { // C# 特有 AST 节点
  UnityYieldStatement() { 
    any() // 不需要强制约束外层方法名为 MoveNext，CodeQL 会自动处理语法树
  }
  
  string getYieldExpressionType() {
    result = this.getExpr().getType().getName()
  }
}

// VR/XR 输入系统调用 (InputSystem / XR.InputDevice)
class VRInputCall extends MethodCall {
  VRInputCall() {
    this.getTarget().hasName(["Get", "TryGet", "TryGetFeatureValue", "ReadValue", "IsPressed", "GetLocalPosition"]) or
    this.getTarget().getDeclaringType().getNamespace().getName().matches("UnityEngine%")
  }
}

// VR 物理射线投射 (手柄/头显交互核心)
class VRRaycastCall extends MethodCall {
  VRRaycastCall() {
    this.getTarget().hasName([
      "Raycast", "SphereCast", "BoxCast", "CapsuleCast",
      "RaycastAll", "SphereCastAll", "RaycastNonAlloc"
    ]) or
    this.getTarget().getDeclaringType().hasFullyQualifiedName("UnityEngine", "Physics")
  }
}

// ==========================================
// 6. 结果输出 (统一仪表盘格式)
// ==========================================
from 
  string category,
  Location loc,
  string apiName,
  string contextInfo,
  string severity
where
  (
    exists(UnityCallbackMethod cb |
      category = "Callback Definition" and
      loc = cb.getLocation() and
      apiName = cb.getName() and
      contextInfo = "Class: " + cb.getDeclaringType().getName() and
      severity = "info"
    )
    or
    exists(UnityReflectionCall rc |
      category = "Reflection/Dynamic Call" and
      loc = rc.getLocation() and
      // 避免 if-then-else 的强类型冲突，使用逻辑分发
      (
        (rc.isStringBased() and apiName = rc.getTarget().getName() + " (String-based)" and contextInfo = "Target: string" and severity = "warning")
        or
        (not rc.isStringBased() and apiName = rc.getTarget().getName() + " (Generic)" and contextInfo = "Target: Type Argument" and severity = "info")
      )
    )
    or
    exists(UnityStartCoroutineCall sc |
      category = "Coroutine Start" and
      loc = sc.getLocation() and
      apiName = "StartCoroutine" and
      contextInfo = "Arg: " + sc.getCoroutineArgType() and
      severity = "info"
    )
    or
    exists(UnityYieldStatement ys |
      category = "Yield Expression" and
      loc = ys.getLocation() and
      apiName = "yield return" and
      contextInfo = "Type: " + ys.getYieldExpressionType() and
      severity = "info"
    )
    or
    exists(VRInputCall vi |
      category = "VR Input Call" and
      loc = vi.getLocation() and
      apiName = vi.getTarget().getName() and
      contextInfo = "Type: " + vi.getTarget().getDeclaringType().getName() and
      severity = "info"
    )
    or
    exists(VRRaycastCall rc |
      category = "VR Raycast/Cast" and
      loc = rc.getLocation() and
      apiName = rc.getTarget().getName() and
      contextInfo = "Physics Query" and
      severity = "info"
    )
  )
select 
  loc, 
  category, 
  apiName, 
  contextInfo, 
  severity