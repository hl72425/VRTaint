/**
 * @name CSharp External API Candidates (Source/Sink)
 * @description Finds calls to methods defined outside the current source code (external APIs)
 * and extracts their metadata for LLM analysis.
 * @kind table
 */

import csharp
import semmle.code.csharp.dataflow.DataFlow


predicate isExternalCall(MethodCall call) {
  // 目标方法存在
  exists(Method target | target = call.getTarget()) and
  // 目标方法不在源代码中定义
  not call.getTarget().fromSource() and
  // 排除一些常见的、通常不作为污点源/汇的系统调用（可根据需要调整）
  not call.getTarget().getDeclaringType().getNamespace().getName().matches("System%")
}

// 2. 辅助函数：获取方法的完整签名
bindingset[m]
string getFullSignature(Method m) {
  result = m.getReturnType().getName() + " " + m.getName() +
           "(" + concat(int i | i = [0 .. m.getNumberOfParameters()-1] |
                                m.getParameter(i).getType().getName() + " " + m.getParameter(i).getName(), ", ") + ")"
}

// 3. 主查询：提取外部 API 的元数据
from MethodCall api
where isExternalCall(api)
select
  // 包名/命名空间
  api.getTarget().getDeclaringType().getNamespace().getName() as package_name,
  // 类名
  api.getTarget().getDeclaringType().getName() as class_name,
  // 方法名
  api.getTarget().getName() as method_name,
  // 完整签名
  getFullSignature(api.getTarget()) as full_signature,
  // 参数类型列表
  concat(Parameter p | p = api.getTarget().getParameter(_) | p.getType().getName(), ";") as param_types,
  // 摘要文档（由于外部 API 往往无文档，且原方法报错，此处不再尝试提取）
  // api.getTarget().getDoc().getSummary() as documentation,
  // 调用位置
  api.getLocation().toString() as call_location