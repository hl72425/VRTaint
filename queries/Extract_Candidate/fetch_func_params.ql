/**
 * @name CSharp Internal Public API Parameters (Source)
 * @description Finds public methods defined in the source code that are potential external
 * entry points, and extracts their parameters as source candidates.
 * @kind table
 */

import csharp
import semmle.code.csharp.dataflow.DataFlow

// 1. 辅助函数：判断是否为公共源码方法（带参数）
predicate isPublicSourceMethod(Method m) {
  m.fromSource() and
  m.isPublic() and
  m.getNumberOfParameters() > 0
}

// 2. 辅助函数（启发式）：判断是否未被内部调用
predicate isNotInvokedInternally(Method m) {
  not exists(MethodCall call |
    call.getTarget() = m and
    call.getFile().getRelativePath().matches("%.cs")
  )
}

// 3. 获取方法完整签名
bindingset[m]
string getFullSignature(Method m) {
  result =
    m.getReturnType().getName() + " " + m.getName() + "(" +
    concat(int i |
      i = [0 .. m.getNumberOfParameters() - 1] |
      m.getParameter(i).getType().getName() + " " + m.getParameter(i).getName(),
      ", "
    ) + ")"
}

// 4. 主查询
from Method m
where
  isPublicSourceMethod(m) and
  isNotInvokedInternally(m)
select
  m.getDeclaringType().getNamespace().getName() as package_name,
  m.getDeclaringType().getName() as class_name,
  m.getName() as method_name,
  getFullSignature(m) as full_signature,
  concat(Parameter p | p = m.getParameter(_) | p.getName(), ",") as parameters_as_sources,
  m.getLocation().toString() as method_location
