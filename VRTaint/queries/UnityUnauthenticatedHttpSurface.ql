/**
 * @name Externally bound Unity HTTP service exposes a sensitive route without visible authentication
 * @description An embedded HTTP service binds a wildcard address and registers a sensitive or
 *              state-changing route while no authentication/authorization guard is present in the server type.
 * @kind problem
 * @id cs/unity-unauthenticated-http-surface
 * @problem.severity error
 * @security-severity 8.1
 * @precision high
 * @tags security external/cwe/cwe-306
 */

import csharp

bindingset[literal]
private predicate isWildcardUrlLiteral(StringLiteral literal) {
  literal.getValue().regexpMatch(".*https?://(\\*|\\+|0[.]0[.]0[.]0).*" )
}

/**
 * A wildcard listener binding expressed either as a stored URL or through a
 * common embedded-server fluent API.  Starting from the rare wildcard literal
 * avoids materialising every assignment/descendant pair in a large database.
 */
private predicate wildcardBinding(Expr bind, Callable setup) {
  bind.getEnclosingCallable() = setup and
  setup.getDeclaringType().fromSource() and
  exists(StringLiteral literal |
    isWildcardUrlLiteral(literal) and
    (
      exists(AssignExpr assignment |
        bind = assignment and literal = assignment.getAChildExpr*()
      )
      or
      exists(MethodCall call |
        bind = call and
        call.getTarget().getName() in [
          "WithUrlPrefix", "UseUrls", "AddPrefix", "Listen", "Bind"
        ] and
        literal = call.getAnArgument().getAChildExpr*()
      )
      or
      // HttpListener.Prefixes.Add("http://*:PORT/") and equivalent wrappers.
      exists(MethodCall call |
        bind = call and call.getTarget().getName() = "Add" and
        (
          call.getQualifier().getType().getName().toLowerCase().matches("%prefix%") or
          call.getQualifier().toString().toLowerCase().matches("%prefixes%")
        ) and
        literal = call.getAnArgument().getAChildExpr*()
      )
    )
  )
}

bindingset[literal]
private predicate sensitiveLiteral(StringLiteral literal) {
  literal.getValue().toLowerCase().regexpMatch(
    ".*(upload|write|save|delete|remove|restart|reset|config|admin|exec|command|shell|script|plugin|database|logs|video).*"
  )
}

private predicate sensitiveRoute(Expr route) {
  exists(StringLiteral literal |
    (literal = route or literal = route.getAChildExpr*()) and sensitiveLiteral(literal)
  )
}

private predicate isSensitiveRouteRegistration(Expr registration, Expr route) {
  // ASP.NET/minimal-API and small wrapper APIs.
  exists(MethodCall call |
    registration = call and
  call.getTarget().getName() in [
    "MapGet", "MapPost", "MapPut", "MapDelete", "MapPatch",
    "AddRoute", "RegisterRoute"
  ] and
    route = call.getAnArgument() and
    (
      sensitiveRoute(route) or
      call.getTarget().getName() in ["MapPost", "MapPut", "MapDelete", "MapPatch"]
    )
  )
  or
  // EmbedIO-style ActionModule(route, verb, handler).  Model the module
  // constructor directly: extension calls may be materialised as constructed
  // generic methods such as WithModule<WebServer>, while the constructor
  // contract remains stable and avoids an expensive descendant join.
  exists(ObjectCreation moduleCreation |
    registration = moduleCreation and
    moduleCreation.getObjectType().getName().toLowerCase().regexpMatch(".*(action|route).*module.*") and
    route = moduleCreation.getArgument(0) and
    (
      sensitiveRoute(route)
      or
      // A catch-all API/admin module accepting a state-changing verb is a
      // sensitive surface even when individual subroutes are dispatched in
      // its handler body. This avoids expanding every handler descendant.
      exists(StringLiteral prefix |
        (prefix = route or prefix = route.getAChildExpr*()) and
        prefix.getValue().toLowerCase().regexpMatch(".*(api|admin).*" ) and
        moduleCreation.getArgument(1).toString().regexpMatch(
          ".*(Any|Post|Put|Delete|Patch).*"
        )
      )
    )
  )
}

private predicate hasAuthenticationEvidence(Class serverType) {
  exists(MethodCall call |
    call.getEnclosingCallable().getDeclaringType() = serverType and
    call.getTarget().getName().toLowerCase().regexpMatch(
      ".*(authenticate|authorize|useauthentication|useauthorization|requireauthorization|validate.*token|verify.*token).*"
    )
  )
  or
  exists(Method m, Attribute a |
    m.getDeclaringType() = serverType and a = m.getAnAttribute() and
    a.getType().getName().toLowerCase().regexpMatch(".*(authorize|authenticate).*" )
  )
}

// Keep finding computation separate from five-tuple presentation.  Calling
// UnityExternalInput::phase/context here recursively expands the lifecycle call
// graph for every candidate binding, although this rule itself is not a taint
// query.  The unified CLI enriches the emitted SARIF location afterwards.
from Callable setup, Class serverType, Expr bind
where
  wildcardBinding(bind, setup) and
  serverType = setup.getDeclaringType() and
  exists(Expr registration, Expr route |
    isSensitiveRouteRegistration(registration, route) and
    registration.getEnclosingCallable() = setup
  ) and
  not hasAuthenticationEvidence(serverType)
select bind,
  "Wildcard-bound embedded HTTP service exposes sensitive/state-changing routes without visible authentication."
