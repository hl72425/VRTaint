/**
 * @name VRTaint official adapter exact sink preflight
 * @description Counts project-owned candidates from the exact official Sink classes before global flow evaluation.
 * @kind table
 * @id cs/vrtaint-official-adapter-sink-preflight
 */

import csharp
import semmle.code.csharp.security.dataflow.CleartextStorageQuery as CleartextStorage
import semmle.code.csharp.security.dataflow.CodeInjectionQuery as CodeInjection
import semmle.code.csharp.security.dataflow.CommandInjectionQuery as CommandInjection
import semmle.code.csharp.security.dataflow.ConditionalBypassQuery as ConditionalBypass
import semmle.code.csharp.security.dataflow.ExposureOfPrivateInformationQuery as ExposureOfPrivateInformation
import semmle.code.csharp.security.dataflow.HardcodedCredentialsQuery as HardcodedCredentials
import semmle.code.csharp.security.dataflow.LDAPInjectionQuery as LDAPInjection
import semmle.code.csharp.security.dataflow.LogForgingQuery as LogForging
import semmle.code.csharp.security.dataflow.MissingXMLValidationQuery as MissingXMLValidation
import semmle.code.csharp.security.dataflow.ReDoSQuery as ReDoS
import semmle.code.csharp.security.dataflow.RegexInjectionQuery as RegexInjection
import semmle.code.csharp.security.dataflow.ResourceInjectionQuery as ResourceInjection
import semmle.code.csharp.security.dataflow.SqlInjectionQuery as SqlInjection
import semmle.code.csharp.security.dataflow.TaintedPathQuery as TaintedPath
import semmle.code.csharp.security.dataflow.UnsafeDeserializationQuery as UnsafeDeserialization
import semmle.code.csharp.security.dataflow.UrlRedirectQuery as UrlRedirect
import semmle.code.csharp.security.dataflow.XMLEntityInjectionQuery as XMLEntityInjection
import semmle.code.csharp.security.dataflow.XPathInjectionQuery as XPathInjection
import semmle.code.csharp.security.dataflow.ZipSlipQuery as ZipSlip
import lib.UnityExternalInput

private predicate supportedFamily(string family) {
  family in [
    "CleartextStorage", "CodeInjection", "CommandInjection", "ConditionalBypass",
    "ExposureOfPrivateInformation", "HardcodedCredentials", "LDAPInjection", "LogForging",
    "MissingXMLValidation", "ReDoS", "RegexInjection", "ResourceInjection", "SqlInjection",
    "TaintedPath", "UnsafeDeserialization", "UrlRedirect", "XMLEntityInjection",
    "XPathInjection", "ZipSlip"
  ]
}

private predicate candidateSink(string family, DataFlow::Node sink) {
  family = "CleartextStorage" and sink instanceof CleartextStorage::Sink
  or family = "CodeInjection" and sink instanceof CodeInjection::Sink
  or family = "CommandInjection" and sink instanceof CommandInjection::Sink
  or family = "ConditionalBypass" and sink instanceof ConditionalBypass::Sink
  or family = "ExposureOfPrivateInformation" and sink instanceof ExposureOfPrivateInformation::Sink
  or family = "HardcodedCredentials" and sink instanceof HardcodedCredentials::Sink
  or family = "LDAPInjection" and sink instanceof LDAPInjection::Sink
  or family = "LogForging" and sink instanceof LogForging::Sink
  or family = "MissingXMLValidation" and sink instanceof MissingXMLValidation::Sink
  or family = "ReDoS" and sink instanceof ReDoS::Sink
  or family = "RegexInjection" and sink instanceof RegexInjection::Sink
  or family = "ResourceInjection" and sink instanceof ResourceInjection::Sink
  or family = "SqlInjection" and sink instanceof SqlInjection::Sink
  or family = "TaintedPath" and sink instanceof TaintedPath::Sink
  or family = "UnsafeDeserialization" and sink instanceof UnsafeDeserialization::Sink
  or family = "UrlRedirect" and sink instanceof UrlRedirect::Sink
  or family = "XMLEntityInjection" and sink instanceof XMLEntityInjection::Sink
  or family = "XPathInjection" and sink instanceof XPathInjection::Sink
  or family = "ZipSlip" and sink instanceof ZipSlip::Sink
}

private predicate officialSource(string family, DataFlow::Node source) {
  family = "CleartextStorage" and source instanceof CleartextStorage::Source
  or family = "CodeInjection" and source instanceof CodeInjection::Source
  or family = "CommandInjection" and source instanceof CommandInjection::Source
  or family = "ConditionalBypass" and source instanceof ConditionalBypass::Source
  or family = "ExposureOfPrivateInformation" and source instanceof ExposureOfPrivateInformation::Source
  or family = "HardcodedCredentials" and source instanceof HardcodedCredentials::Source
  or family = "LDAPInjection" and source instanceof LDAPInjection::Source
  or family = "LogForging" and source instanceof LogForging::Source
  or family = "MissingXMLValidation" and source instanceof MissingXMLValidation::Source
  or family = "ReDoS" and source instanceof ReDoS::Source
  or family = "RegexInjection" and source instanceof RegexInjection::Source
  or family = "ResourceInjection" and source instanceof ResourceInjection::Source
  or family = "SqlInjection" and source instanceof SqlInjection::Source
  or family = "TaintedPath" and source instanceof TaintedPath::Source
  or family = "UnsafeDeserialization" and source instanceof UnsafeDeserialization::Source
  or family = "UrlRedirect" and source instanceof UrlRedirect::Source
  or family = "XMLEntityInjection" and source instanceof XMLEntityInjection::Source
  or family = "XPathInjection" and source instanceof XPathInjection::Source
  or family = "ZipSlip" and source instanceof ZipSlip::Source
}

private predicate usesUnityExternalSource(string family) {
  supportedFamily(family) and
  not family in ["CleartextStorage", "ExposureOfPrivateInformation", "HardcodedCredentials"]
}

private predicate candidateSource(string family, DataFlow::Node source) {
  officialSource(family, source)
  or
  usesUnityExternalSource(family) and
  UnityExternalInput::isExternalSource(source) and
  UnityExternalInput::isRuntimeNode(source)
}

from string family, int sinkCount, int sourceCount
where
  supportedFamily(family) and
  sinkCount = count(DataFlow::Node sink |
    candidateSink(family, sink) and
    exists(Callable c | c = sink.getEnclosingCallable() and c.fromSource())
  ) and
  sourceCount = count(DataFlow::Node source | candidateSource(family, source)) and
  sinkCount > 0
select family, sinkCount, sourceCount
