module GeneratedAPIs {
  import csharp

  predicate isLLMDetectedSourceMethod(Method m) {
        m.getDeclaringType().getName() = "Assembly" and m.getName() = "GetType"
    or     m.getDeclaringType().getName() = "List<<unknown type>>" and m.getName() = "Find"
    or     m.getDeclaringType().getName() = "List<AggregationManifestEntry>" and m.getName() = "Find"
    or     m.getDeclaringType().getName() = "List<BakeableMesh>" and m.getName() = "Find"
    or     m.getDeclaringType().getName() = "List<DashboardObject>" and m.getName() = "Find"
    or     m.getDeclaringType().getName() = "List<SceneSettings>" and m.getName() = "Find"
    or     m.getDeclaringType().getName() = "List<SceneVersion>" and m.getName() = "Find"
    or     m.getDeclaringType().getName() = "Queue<EditorWebRequest>" and m.getName() = "Dequeue"
    or     m.getDeclaringType().getName() = "Queue<String>" and m.getName() = "Dequeue"
  }

  predicate isLLMDetectedSinkMethod(Method m) {
        m.getDeclaringType().getName() = "BitArray" and m.getName() = "CopyTo"
    or     m.getDeclaringType().getName() = "FieldInfo" and m.getName() = "GetValue"
    or     m.getDeclaringType().getName() = "FieldInfo" and m.getName() = "SetValue"
    or     m.getDeclaringType().getName() = "List<<unknown type>>" and m.getName() = "Contains"
    or     m.getDeclaringType().getName() = "List<<unknown type>>" and m.getName() = "Remove"
    or     m.getDeclaringType().getName() = "List<<unknown type>>" and m.getName() = "RemoveAt"
    or     m.getDeclaringType().getName() = "List<DynamicObject>" and m.getName() = "Add"
    or     m.getDeclaringType().getName() = "List<Entry>" and m.getName() = "Sort"
    or     m.getDeclaringType().getName() = "Marshal" and m.getName() = "PtrToStructure"
  }

  predicate isLLMDetectedPropagator(Method m) {
        m.getDeclaringType().getName() = "Dictionary<<unknown type>,Int32>" and m.getName() = "Add"
    or     m.getDeclaringType().getName() = "List<<unknown type>>" and m.getName() = "Add"
    or     m.getDeclaringType().getName() = "List<<unknown type>>" and m.getName() = "AddRange"
    or     m.getDeclaringType().getName() = "List<<unknown type>>" and m.getName() = "IndexOf"
    or     m.getDeclaringType().getName() = "List<<unknown type>>" and m.getName() = "Insert"
    or     m.getDeclaringType().getName() = "List<<unknown type>>" and m.getName() = "ToArray"
    or     m.getDeclaringType().getName() = "List<AggregationManifestEntry>" and m.getName() = "AddRange"
    or     m.getDeclaringType().getName() = "List<BakeableMesh>" and m.getName() = "Add"
    or     m.getDeclaringType().getName() = "List<DashboardObject>" and m.getName() = "AddRange"
    or     m.getDeclaringType().getName() = "List<DynamicObject>" and m.getName() = "Add"
    or     m.getDeclaringType().getName() = "List<DynamicObjectIdPool>" and m.getName() = "Add"
    or     m.getDeclaringType().getName() = "List<EditorWebRequest>" and m.getName() = "Add"
    or     m.getDeclaringType().getName() = "List<Entry>" and m.getName() = "Add"
    or     m.getDeclaringType().getName() = "List<Entry>" and m.getName() = "Find"
    or     m.getDeclaringType().getName() = "List<SceneSettings>" and m.getName() = "Add"
    or     m.getDeclaringType().getName() = "Queue<EditorWebRequest>" and m.getName() = "Enqueue"
  }

}
