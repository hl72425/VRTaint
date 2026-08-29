/**
 * @name Unlimited gRPC receive combined with unbounded decompression
 * @description A component configures unlimited gRPC message reception and contains an unbounded
 *              decompression-to-memory operation whose output is parsed or deserialized.
 * @kind problem
 * @id cs/unity-unbounded-grpc-decompression
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @tags security external/cwe/cwe-400
 */

import csharp
import lib.UnityExternalInput

private predicate unlimitedGrpcOption(ObjectCreation option, Class owner) {
  option.getEnclosingCallable().getDeclaringType() = owner and
  exists(StringLiteral name, IntLiteral one |
    name = option.getAnArgument().getAChildExpr*() and
    name.getValue() = "grpc.max_receive_message_length" and
    one = option.getAnArgument().getAChildExpr*() and one.getIntValue() = 1 and
    one.getParent() instanceof UnaryMinusExpr
  )
}

private predicate decompressionStream(ObjectCreation creation, Class owner) {
  creation.getEnclosingCallable().getDeclaringType() = owner and
  creation.getObjectType().getName() in ["DeflateStream", "GZipStream", "BrotliStream"] and
  exists(MemberConstantAccess mode |
    mode = creation.getAnArgument().getAChildExpr*() and mode.getTarget().getName() = "Decompress"
  )
}

private predicate unboundedCopyTo(MethodCall copy, ObjectCreation creation, Class owner) {
  decompressionStream(creation, owner) and
  copy.getEnclosingCallable().getDeclaringType() = owner and
  copy.getTarget().getName() in ["CopyTo", "CopyToAsync"] and
  DataFlow::localExprFlow(creation, copy.getQualifier()) and
  not exists(MethodCall boundedRead |
    boundedRead.getEnclosingCallable() = copy.getEnclosingCallable() and
    boundedRead.getTarget().getName() in ["Read", "ReadAsync"] and
    boundedRead.getNumberOfArguments() >= 3
  )
}

private predicate downstreamParser(MethodCall copy, MethodCall parser) {
  copy.getEnclosingCallable() = parser.getEnclosingCallable() and
  parser.getTarget().getName().toLowerCase().regexpMatch(".*(deserialize|decode|parse|unmarshal).*" ) and
  copy.getLocation().getStartLine() < parser.getLocation().getStartLine()
}

from ObjectCreation option, Class owner, ObjectCreation creation, MethodCall copy, MethodCall parser,
     string objectId, string phase, string context
where
  unlimitedGrpcOption(option, owner) and
  unboundedCopyTo(copy, creation, owner) and
  downstreamParser(copy, parser) and
  UnityExternalInput::objectId(DataFlow::exprNode(copy), objectId) and
  UnityExternalInput::phase(DataFlow::exprNode(copy), phase) and
  UnityExternalInput::context(DataFlow::exprNode(copy), context)
select copy,
  "Unlimited gRPC receive size is combined with unbounded decompression into memory before parsing. " +
  "Tuple=<" + objectId + ", compressedPayload, " + phase + ", " + context + ", NetworkCallback>."
