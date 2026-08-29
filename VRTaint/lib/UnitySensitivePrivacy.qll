/**
 * @name UnitySensitivePrivacy
 * @description High-precision, project-independent Unity privacy source/sink models.
 *              The model deliberately uses API families and semantic type/name evidence;
 *              it does not contain repository, project, scene, or asset-specific names.
 */

import csharp
import UnitySensitivityCore
import UnityPrivacyLegacyFacts

module UnitySensitivePrivacy {

  bindingset[text]
  private predicate textHasPrivacyMeaning(string text) {
    text.toLowerCase().matches("%microphone%") or
    text.toLowerCase().matches("%audio%") or
    text.toLowerCase().matches("%voice%") or
    text.toLowerCase().matches("%speech%") or
    text.toLowerCase().matches("%head%") or
    text.toLowerCase().matches("%hand%") or
    text.toLowerCase().matches("%controller%") or
    text.toLowerCase().matches("%gaze%") or
    text.toLowerCase().matches("%eye%") or
    text.toLowerCase().matches("%pose%") or
    text.toLowerCase().matches("%tracked%") or
    text.toLowerCase().matches("%biometric%") or
    text.toLowerCase().matches("%location%") or
    text.toLowerCase().matches("%camera%") or
    text.toLowerCase().matches("%photo%") or
    text.toLowerCase().matches("%face%") or
    text.toLowerCase().matches("%fingerprint%") or
    text.toLowerCase().matches("%password%") or
    text.toLowerCase().matches("%passwd%") or
    text.toLowerCase().matches("%credential%") or
    text.toLowerCase().matches("%token%") or
    text.toLowerCase().matches("%secret%") or
    text.toLowerCase().matches("%email%") or
    text.toLowerCase().matches("%phone%") or
    text.toLowerCase().matches("%clipboard%") or
    text.toLowerCase().matches("%advertising%")
  }

  bindingset[text]
  private predicate textHasCredentialMeaning(string text) {
    text.toLowerCase().matches("%password%") or
    text.toLowerCase().matches("%passwd%") or
    text.toLowerCase().matches("%credential%") or
    text.toLowerCase().matches("%auth%token%") or
    text.toLowerCase().matches("%access%token%") or
    text.toLowerCase().matches("%refresh%token%") or
    text.toLowerCase().matches("%api%key%") or
    text.toLowerCase().matches("%secret%") or
    text.toLowerCase().matches("%email%") or
    text.toLowerCase().matches("%phone%")
  }

  private predicate callableHasPrivacyMeaning(Callable c) {
    textHasPrivacyMeaning(c.getName()) or
    textHasPrivacyMeaning(c.getDeclaringType().getName())
  }

  private predicate callableHasVoiceMeaning(Callable c) {
    c.getName().toLowerCase().matches("%voice%") or
    c.getName().toLowerCase().matches("%audio%") or
    c.getName().toLowerCase().matches("%speech%") or
    c.getName().toLowerCase().matches("%microphone%") or
    c.getName().toLowerCase().matches("%frame%") or
    c.getDeclaringType().getName().toLowerCase().matches("%voice%") or
    c.getDeclaringType().getName().toLowerCase().matches("%audio%") or
    c.getDeclaringType().getName().toLowerCase().matches("%microphone%")
  }

  private predicate isMicrophoneStart(MethodCall call) {
    call.getTarget().getName() = "Start" and
    call.getTarget().getDeclaringType().getName() = "Microphone"
  }

  private predicate isAudioBufferOutput(MethodCall call) {
    call.getTarget().getName() = "GetData" and
    call.getTarget().getDeclaringType().getName() = "AudioClip"
  }

  private predicate isXrFeatureRead(MethodCall call) {
    call.getTarget().getName() = "TryGetFeatureValue" and
    (
      call.getTarget().getDeclaringType().getName() = "InputDevice" or
      call.getArgument(0).toString().toLowerCase().matches("%deviceposition%") or
      call.getArgument(0).toString().toLowerCase().matches("%devicerotation%") or
      call.getArgument(0).toString().toLowerCase().matches("%eyegaze%") or
      call.getArgument(0).toString().toLowerCase().matches("%hand%")
    )
  }

  private predicate isXrInputRead(MethodCall call) {
    call.getTarget().getDeclaringType().getName() in ["OVRInput", "XRInputSubsystem"] and
    call.getTarget().getName() in
      ["Get", "GetDown", "GetUp", "TryGetInputSource", "GetLocalControllerPosition",
       "GetLocalControllerRotation", "GetLocalControllerVelocity", "GetLocalControllerAcceleration",
       "GetLocalControllerAngularVelocity", "GetLocalControllerAngularAcceleration",
       "GetControllerPosition", "GetControllerOrientation"]
  }

  private predicate isTrackedJointRead(MethodCall call) {
    call.getTarget().getName().matches("%TryGet%Pose%") and
    (
      call.getTarget().getDeclaringType().getName().matches("%HandJoint%") or
      call.getTarget().getDeclaringType().getName().matches("%Pose%") or
      call.getTarget().getDeclaringType().getNamespace().getName().toLowerCase().matches("%mixedreality%")
    )
  }

  private predicate isVoiceAccumulatorType(Type t) {
    t.getName().toLowerCase().matches("%voice%buffer%") or
    t.getName().toLowerCase().matches("%audio%buffer%") or
    t.getName().toLowerCase().matches("%sample%buffer%") or
    t.getName().toLowerCase().matches("%frame%buffer%")
  }

  /**
   * Two field accesses read the same logical accumulator slot when they target
   * the same field on receivers that can alias.  Besides identical receiver
   * expressions and `this`-compatible component receivers, accept receivers
   * that are variable/parameter reads of the same declared type: a
   * capture-state holder is typically pushed in one callback phase and
   * finalized in another through a same-typed parameter/local (often in
   * different callables), where CodeQL cannot prove object identity.  The
   * caller's accumulator-type field gate confines the bridge to audio/voice
   * buffers.
   */
  private predicate sameAccumulatorReceiver(FieldAccess a, FieldAccess b) {
    a.getQualifier() = b.getQualifier()
    or
    SensitivityCore::isReceiverCompatible(a, b)
    or
    exists(VariableAccess va, VariableAccess vb |
      va = a.getQualifier() and vb = b.getQualifier() and
      va.getTarget().getType() = vb.getTarget().getType()
    )
    or
    exists(FieldAccess qa, FieldAccess qb |
      qa = a.getQualifier() and qb = b.getQualifier() and
      sameAccumulatorReceiver(qa, qb)
    )
  }

  /**
   * Position/rotation property families on Unity transforms.  `position` and
   * `localPosition` (and `rotation`/`localRotation`) denote the same pose in
   * local vs world space, so a copy through either family keeps the pose
   * sensitive.
   */
  private predicate samePoseProperty(Member a, Member b) {
    a.getName() = b.getName() and
    a.getName() in ["position", "rotation", "localPosition", "localRotation"]
    or
    a.getName() in ["position", "localPosition"] and
    b.getName() in ["position", "localPosition"]
    or
    a.getName() in ["rotation", "localRotation"] and
    b.getName() in ["rotation", "localRotation"]
  }

  private predicate isPrivacyPayloadMember(AssignableMemberAccess member) {
    member.getTarget().getDeclaringType().getName().toLowerCase().matches("%message%") or
    member.getTarget().getDeclaringType().getName().toLowerCase().matches("%command%") or
    member.getTarget().getDeclaringType().getName().toLowerCase().matches("%request%") or
    member.getTarget().getDeclaringType().getName().toLowerCase().matches("%payload%") or
    member.getTarget().getDeclaringType().getName().toLowerCase().matches("%packet%") or
    member.getTarget().getDeclaringType().getName().toLowerCase().matches("%phrase%") or
    member.getTarget().getDeclaringType().getNamespace().getName().toLowerCase().matches("%messagetypes%") or
    member.getTarget().getDeclaringType().getNamespace().getName().toLowerCase().matches("%protobuf%")
  }

  private predicate isSensitiveTransformRead(PropertyAccess access) {
    access.getTarget().getName() in ["position", "rotation", "localPosition", "localRotation"] and
    (
      access.getTarget().getDeclaringType().getName() = "Transform" or
      access.getTarget().getDeclaringType().getName() = "<unknown type>" or
      not exists(string resolvedType |
        resolvedType = access.getTarget().getDeclaringType().getName()
      )
    ) and
    (
      textHasPrivacyMeaning(access.getQualifier().toString()) or
      callableHasPrivacyMeaning(access.getEnclosingCallable())
    )
  }

  bindingset[text]
  private predicate textHasAvatarPoseMeaning(string text) {
    text.toLowerCase().matches("%rig%") or
    text.toLowerCase().matches("%hmd%") or
    text.toLowerCase().matches("%headset%") or
    text.toLowerCase().matches("%tracker%") or
    text.toLowerCase().matches("%avatar%") or
    text.toLowerCase().matches("%wrist%") or
    text.toLowerCase().matches("%palm%") or
    text.toLowerCase().matches("%finger%") or
    text.toLowerCase().matches("%skeleton%") or
    text.toLowerCase().matches("%joint%") or
    text.toLowerCase().matches("%head%") or
    text.toLowerCase().matches("%hand%") or
    text.toLowerCase().matches("%controller%")
  }

  /**
   * A transform pose read on an XR avatar/rig part (head, hand, rig, tracker,
   * controller, ...).  These transforms are driven by device tracking and are
   * the usual pose sources before a network sync component reads them.
   */
  private predicate isAvatarPoseRead(PropertyAccess access) {
    access.getTarget().getName() in ["position", "rotation", "localPosition", "localRotation"] and
    (
      access.getTarget().getDeclaringType().getName() = "Transform" or
      access.getTarget().getDeclaringType().getName() = "<unknown type>" or
      not exists(string resolvedType |
        resolvedType = access.getTarget().getDeclaringType().getName()
      )
    ) and
    (
      textHasAvatarPoseMeaning(access.getQualifier().toString()) or
      textHasAvatarPoseMeaning(access.getEnclosingCallable().getName()) or
      textHasAvatarPoseMeaning(access.getEnclosingCallable().getDeclaringType().getName())
    )
  }

  private predicate isDeviceIdentifierRead(Expr expression) {
    exists(PropertyAccess access |
      expression = access and
      access.getTarget().getDeclaringType().getName() = "SystemInfo" and
      access.getTarget().getName() in ["deviceUniqueIdentifier", "deviceName", "deviceModel"]
    )
  }

  private predicate isLocationRead(Expr expression) {
    exists(PropertyAccess access |
      expression = access and
      access.getTarget().getDeclaringType().getName() in ["LocationService", "LocationInfo"] and
      access.getTarget().getName() in ["lastData", "latitude", "longitude", "altitude"]
    )
  }

  private predicate isCameraOrScreenRead(MethodCall call, string kind) {
    call.getTarget().getDeclaringType().getName() = "WebCamTexture" and
    call.getTarget().getName() in ["GetPixel", "GetPixels", "GetPixels32"] and
    kind = "camera-frame"
    or
    call.getTarget().getDeclaringType().getName() = "ScreenCapture" and
    call.getTarget().getName() in ["CaptureScreenshotAsTexture", "CaptureScreenshotIntoRenderTexture"] and
    kind = "screen-content"
  }

  private predicate isMotionSensorRead(PropertyAccess access, string kind) {
    access.getTarget().getDeclaringType().getName() = "Gyroscope" and
    access.getTarget().getName() in ["attitude", "rotationRate", "rotationRateUnbiased", "userAcceleration", "gravity"] and
    kind = "motion-sensor"
    or
    access.getTarget().getDeclaringType().getName() = "Compass" and
    access.getTarget().getName() in ["trueHeading", "magneticHeading", "rawVector"] and
    kind = "heading-sensor"
  }

  private predicate isPlatformIdentifierRead(PropertyAccess access, string kind) {
    access.getTarget().getDeclaringType().getName() = "Device" and
    access.getTarget().getName() in ["advertisingIdentifier", "vendorIdentifier"] and
    kind = "persistent-device-identifier"
  }

  private predicate isNetworkIdentifierRead(MethodCall call) {
    call.getTarget().getDeclaringType().getName() = "NetworkInterface" and
    call.getTarget().getName() = "GetPhysicalAddress"
  }

  private predicate isSensitivePreferenceRead(MethodCall call) {
    call.getTarget().getDeclaringType().getName() = "PlayerPrefs" and
    call.getTarget().getName() = "GetString" and
    textHasCredentialMeaning(call.getArgument(0).toString())
  }

  private predicate isSensitiveTextInputRead(PropertyAccess access) {
    access.getTarget().getDeclaringType().getName() in ["InputField", "TMP_InputField"] and
    access.getTarget().getName() = "text" and
    (
      textHasCredentialMeaning(access.getQualifier().toString()) or
      textHasCredentialMeaning(access.getEnclosingCallable().getName())
    )
  }

  private predicate isClipboardRead(PropertyAccess access) {
    access.getTarget().getDeclaringType().getName() = "GUIUtility" and
    access.getTarget().getName() = "systemCopyBuffer"
  }

  /** A sensitive Unity/VR value and its stable category. */
  predicate isSensitiveSourceKind(DataFlow::Node source, string kind) {
    exists(MethodCall call |
      isMicrophoneStart(call) and source = DataFlow::exprNode(call) and kind = "microphone-audio"
    )
    or
    exists(MethodCall call |
      isAudioBufferOutput(call) and source = DataFlow::exprNode(call.getArgument(0)) and
      kind = "microphone-audio-buffer"
    )
    or
    exists(MethodCall call |
      isXrFeatureRead(call) and source = DataFlow::exprNode(call.getArgument(1)) and
      kind = "xr-tracking"
    )
    or
    exists(MethodCall call |
      isTrackedJointRead(call) and
      call.getNumberOfArguments() > 2 and
      source = DataFlow::exprNode(call.getArgument(2)) and
      kind = "xr-hand-pose"
    )
    or
    exists(MethodCall call |
      isXrInputRead(call) and source = DataFlow::exprNode(call) and kind = "xr-controller-input"
    )
    or
    exists(PropertyAccess access |
      isSensitiveTransformRead(access) and source = DataFlow::exprNode(access) and
      kind = "xr-spatial-tracking"
    )
    or
    exists(PropertyAccess access |
      isAvatarPoseRead(access) and source = DataFlow::exprNode(access) and
      kind = "xr-avatar-pose"
    )
    or
    // Source-location facts recovered from project source text by the model
    // generator.  Build-mode-none databases do not resolve Unity/XR engine
    // APIs to named symbols (`access to property (unknown)`), so the lexical
    // scanner marks the exact source lines; CodeQL then carries the value
    // through the resolved project code to a disclosure sink.
    exists(string scriptPath, int sourceLine, string sourceKind, string evidence |
      unityPrivacySourceLocationModel(scriptPath, sourceLine, sourceKind, evidence) and
      source.asExpr().getLocation().getFile().getRelativePath() = scriptPath and
      source.asExpr().getLocation().getStartLine() = sourceLine and
      kind = sourceKind
    )
    or
    exists(Expr expression |
      isDeviceIdentifierRead(expression) and source = DataFlow::exprNode(expression) and
      kind = "device-identifier"
    )
    or
    exists(Expr expression |
      isLocationRead(expression) and source = DataFlow::exprNode(expression) and kind = "location"
    )
    or
    exists(MethodCall call |
      isCameraOrScreenRead(call, kind) and source = DataFlow::exprNode(call)
    )
    or
    exists(PropertyAccess access |
      isMotionSensorRead(access, kind) and source = DataFlow::exprNode(access)
    )
    or
    exists(PropertyAccess access |
      isPlatformIdentifierRead(access, kind) and source = DataFlow::exprNode(access)
    )
    or
    exists(MethodCall call |
      isNetworkIdentifierRead(call) and source = DataFlow::exprNode(call) and
      kind = "network-hardware-identifier"
    )
    or
    exists(MethodCall call |
      isSensitivePreferenceRead(call) and source = DataFlow::exprNode(call) and
      kind = "stored-credential-or-contact"
    )
    or
    exists(PropertyAccess access |
      isSensitiveTextInputRead(access) and source = DataFlow::exprNode(access) and
      kind = "credential-or-contact-input"
    )
    or
    exists(PropertyAccess access |
      isClipboardRead(access) and source = DataFlow::exprNode(access) and kind = "clipboard-content"
    )
    or
    // Audio files read by voice/speech processing code are sensitive even when
    // the microphone-to-file side effect is outside the C# extractor's model.
    exists(MethodCall call |
      call.getTarget().getDeclaringType().getName() = "File" and
      call.getTarget().getName() = "ReadAllBytes" and
      callableHasPrivacyMeaning(call.getEnclosingCallable()) and
      source = DataFlow::exprNode(call) and kind = "voice-audio-file"
    )
    or
    // Decoded voice callbacks and explicit audio-processing entry points.
    exists(Parameter p |
      callableHasVoiceMeaning(p.getCallable()) and
      (
        textHasPrivacyMeaning(p.getName()) or
        p.getName().toLowerCase() in ["buf", "buffer", "data", "samples", "frame", "pcm"]
      ) and
      (p.getType().toString().matches("%[]") or p.getType().getName().matches("%Frame%")) and
      source = DataFlow::parameterNode(p) and kind = "voice-audio-callback"
    )
  }

  private predicate isNetworkPayload(MethodCall call, Expr payload, string transport) {
    // NativeWebSocket / ClientWebSocket / WebSocketSharp and socket families.
    call.getTarget().getName() in ["Send", "SendAsync", "SendTo", "SendToAsync"] and
    call.getNumberOfArguments() > 0 and payload = call.getArgument(0) and
    (
      call.getTarget().getDeclaringType().getName().toLowerCase().matches("%websocket%") and transport = "websocket" or
      call.getTarget().getDeclaringType().getName() in ["Socket", "UdpClient", "TcpClient", "NetworkStream", "SslStream"] and transport = "socket"
    )
    or
    // Photon Fusion reliable data and Photon RPC payloads.
    call.getTarget().getName() = "SendReliableDataToServer" and
    call.getNumberOfArguments() > 1 and
    payload = call.getArgument(1) and transport = "photon-fusion"
    or
    call.getTarget().getName() = "SendReliableDataToPlayer" and
    call.getNumberOfArguments() > 2 and
    payload = call.getArgument(2) and transport = "photon-fusion"
    or
    call.getTarget().getName() = "RPC" and payload = call.getAnArgument() and
    payload != call.getArgument(0) and transport = "photon-rpc"
    or
    // RosSharp publishers. Requiring Publisher/Ros namespace avoids treating
    // ordinary domain methods named Publish as network transmission.
    call.getTarget().getName() = "Publish" and payload = call.getArgument(0) and
    (
      call.getTarget().getDeclaringType().getName().matches("%Publisher%") or
      call.getTarget().getDeclaringType().getNamespace().getName().toLowerCase().matches("%rossharp%")
    ) and transport = "rosbridge"
    or
    // Generated gRPC clients conventionally expose Async methods on *Client.
    call.getTarget().getName().matches("%Async") and payload = call.getArgument(0) and
    (
      call.getTarget().getDeclaringType().getName().matches("%Client") or
      call.getTarget().getDeclaringType().getNamespace().getName().toLowerCase().matches("%grpc%")
    ) and
    (
      call.getTarget().getName().matches("%Send%") or
      call.getTarget().getName().matches("%Command%") or
      call.getTarget().getName().matches("%Request%") or
      call.getTarget().getName().matches("%Update%") or
      call.getTarget().getName().matches("%Stream%")
    ) and
    transport = "grpc-client"
    or
    // System.Net.Http and WebClient upload families.
    call.getTarget().getDeclaringType().getName() = "HttpClient" and
    call.getTarget().getName() in ["PostAsync", "PutAsync", "PatchAsync"] and
    call.getNumberOfArguments() > 1 and payload = call.getArgument(1) and
    transport = "system-net-http"
    or
    call.getTarget().getDeclaringType().getName() = "WebClient" and
    call.getTarget().getName() in ["UploadData", "UploadString", "UploadValues"] and
    payload = call.getAnArgument() and payload != call.getArgument(0) and
    transport = "system-net-webclient"
    or
    // NetworkStream/SslStream writes after TcpClient/HTTP stream acquisition.
    call.getTarget().getDeclaringType().getName() in ["NetworkStream", "SslStream"] and
    call.getTarget().getName() in ["Write", "WriteAsync"] and
    payload = call.getArgument(0) and transport = "network-stream"
    or
    // Common MQTT clients. Type/namespace evidence excludes ordinary Publish methods.
    call.getTarget().getName() in ["Publish", "PublishAsync"] and
    call.getNumberOfArguments() > 0 and payload = call.getAnArgument() and
    (
      call.getTarget().getDeclaringType().getName().toLowerCase().matches("%mqtt%") or
      call.getTarget().getDeclaringType().getNamespace().getName().toLowerCase().matches("%mqtt%")
    ) and transport = "mqtt"
  }

  private predicate isTelemetryOrLogPayload(MethodCall call, Expr payload, string transport) {
    call.getTarget().getDeclaringType().getName() = "Debug" and
    call.getTarget().getName() in ["Log", "LogWarning", "LogError", "LogException", "LogFormat"] and
    payload = call.getAnArgument() and transport = "application-log"
    or
    call.getTarget().getDeclaringType().getName() = "Console" and
    call.getTarget().getName() in ["Write", "WriteLine"] and
    payload = call.getAnArgument() and transport = "console-log"
    or
    call.getTarget().getDeclaringType().getName().toLowerCase().matches("%analytics%") and
    call.getTarget().getName() in ["CustomEvent", "LogEvent", "TrackEvent", "RecordEvent"] and
    payload = call.getAnArgument() and transport = "analytics"
    or
    call.getTarget().getDeclaringType().getName().toLowerCase().matches("%crashlytics%") and
    call.getTarget().getName() in ["Log", "SetCustomKey", "RecordException"] and
    payload = call.getAnArgument() and transport = "crash-reporting"
  }

  /** An outbound disclosure point and its transport category. */
  predicate isDisclosureSinkKind(DataFlow::Node sink, string kind) {
    exists(MethodCall call, Expr payload |
      isNetworkPayload(call, payload, kind) and
      sink = DataFlow::exprNode(payload)
    )
    or
    exists(MethodCall call, Expr payload |
      isTelemetryOrLogPayload(call, payload, kind) and
      sink = DataFlow::exprNode(payload)
    )
    or
    // Multipart payload construction is itself a disclosure staging sink. A
    // finding message keeps this distinction; reachability validation checks the send.
    exists(MethodCall call |
      call.getTarget().getName() = "AddBinaryData" and
      call.getTarget().getDeclaringType().getName() = "WWWForm" and
      sink = DataFlow::exprNode(call.getArgument(1)) and kind = "http-multipart"
    )
    or
    exists(ObjectCreation creation |
      creation.getType().getName() = "UploadHandlerRaw" and
      sink = DataFlow::exprNode(creation.getArgument(0)) and kind = "http-upload"
    )
    or
    exists(MethodCall call |
      call.getTarget().getDeclaringType().getName() = "UnityWebRequest" and
      call.getTarget().getName() in ["Post", "PostWwwForm", "Put"] and
      call.getNumberOfArguments() > 1 and
      sink = DataFlow::exprNode(call.getArgument(1)) and kind = "http-request-body"
    )
    or
    exists(MethodCall call |
      call.getTarget().getDeclaringType().getName().toLowerCase().matches("%restclient%") and
      call.getTarget().getName() in ["Post", "PostAsync", "Put", "PutAsync", "Patch", "PatchAsync"] and
      call.getNumberOfArguments() > 1 and sink = DataFlow::exprNode(call.getArgument(1)) and
      kind = "rest-client"
    )
    or
    // Photon PUN synchronized values: PhotonTransformView and friends write
    // synchronized pose/data into the network stream.
    exists(MethodCall call |
      call.getTarget().getDeclaringType().getName() = "PhotonStream" and
      call.getTarget().getName() = "SendNext" and
      call.getNumberOfArguments() > 0 and
      sink = DataFlow::exprNode(call.getArgument(0)) and kind = "photon-stream"
    )
    or
    // Photon Realtime event raising (Photon Voice transports voice frames via
    // OpRaiseEvent; PUN exposes PhotonNetwork.RaiseEvent).
    exists(MethodCall call |
      call.getTarget().getName() in ["OpRaiseEvent", "RaiseEvent"] and
      call.getNumberOfArguments() > 1 and
      sink = DataFlow::exprNode(call.getArgument(1)) and kind = "photon-raise-event"
    )
  }

  predicate isSensitiveSource(DataFlow::Node source) {
    exists(string kind | isSensitiveSourceKind(source, kind))
  }

  predicate isDisclosureSink(DataFlow::Node sink) {
    exists(string kind | isDisclosureSinkKind(sink, kind))
  }

  predicate isCompatiblePrivacyFlow(DataFlow::Node source, DataFlow::Node sink,
                                    string sourceKind, string sinkKind) {
    isSensitiveSourceKind(source, sourceKind) and
    isDisclosureSinkKind(sink, sinkKind)
  }

  /** Side-effect summaries absent from common build-mode-none Unity databases. */
  predicate isPrivacyAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // `TryGet*Pose(..., out field)` writes the tracked pose into a field. Link
    // that API output to later reads of the same field; the restriction to a
    // field proven to be an out-argument of a tracking API avoids generic
    // cross-field propagation.
    exists(MethodCall call, FieldAccess output, FieldAccess read |
      isTrackedJointRead(call) and
      call.getNumberOfArguments() > 2 and
      output = call.getArgument(2) and
      read.getTarget() = output.getTarget() and
      SensitivityCore::isReceiverCompatible(output, read) and
      pred = DataFlow::exprNode(output) and
      succ = DataFlow::exprNode(read)
    )
    or
    // Component reads such as `trackedPose.Position` expose content of a pose
    // value previously populated by a tracking API.
    exists(MethodCall call, FieldAccess output, FieldAccess read, PropertyAccess component |
      isTrackedJointRead(call) and
      call.getNumberOfArguments() > 2 and
      output = call.getArgument(2) and
      read.getTarget() = output.getTarget() and
      component.getQualifier() = read and
      component.getTarget().getName() in ["Position", "Rotation", "position", "rotation"] and
      pred = DataFlow::exprNode(read) and
      succ = DataFlow::exprNode(component)
    )
    or
    // AudioClip.GetData(float[]/byte[], offset): receiver content populates arg0.
    exists(MethodCall call |
      isAudioBufferOutput(call) and
      pred = DataFlow::exprNode(call.getQualifier()) and
      succ = DataFlow::exprNode(call.getArgument(0))
    )
    or
    // Pure geometry/math helpers preserve the sensitivity of pose-derived
    // values in their result.
    exists(MethodCall call, Expr argument |
      call.getTarget().getDeclaringType().getName() in
        ["Vector2", "Vector3", "Vector4", "Quaternion", "Mathf", "Math"] and
      call.getTarget().getName() in
        ["Distance", "Angle", "Dot", "Cross", "Lerp", "LerpUnclamped", "Clamp", "Clamp01", "Abs", "Min", "Max"] and
      argument = call.getAnArgument() and
      pred = DataFlow::exprNode(argument) and
      succ = DataFlow::exprNode(call)
    )
    or
    // Buildless Unity databases can retain the invocation and its arguments
    // while leaving an SDK method unresolved (for example Vector3.Distance
    // when the Unity reference assembly was unavailable at extraction time).
    // A returned value from such an invocation may depend on any argument.
    // This is a general missing-library summary, not a project/API special case.
    exists(MethodCall call, Expr argument |
      not exists(string resolvedName | resolvedName = call.getTarget().getName()) and
      argument = call.getAChildExpr+() and
      pred = DataFlow::exprNode(argument) and
      succ = DataFlow::exprNode(call)
    )
    or
    // Parser recovery may expose an unresolved invocation as a result node
    // that the data-flow IR cannot enter. Connect a nested input directly to
    // the enclosing assignment value so normal local/field flow can resume.
    exists(AssignExpr write, MethodCall call, Expr nested |
      call = write.getRightOperand().getAChildExpr*() and
      not exists(string resolvedName | resolvedName = call.getTarget().getName()) and
      nested = call.getAChildExpr+() and
      pred = DataFlow::exprNode(nested) and
      succ = DataFlow::exprNode(write.getRightOperand())
    )
    or
    // Numeric derivations (distance normalization, coordinate conversion,
    // biometric scores, etc.) preserve sensitivity. This is intentionally
    // limited to arithmetic results; comparisons remain control predicates.
    exists(BinaryArithmeticOperation operation, Expr operand |
      operand in [operation.getLeftOperand(), operation.getRightOperand()] and
      pred = DataFlow::exprNode(operand) and
      succ = DataFlow::exprNode(operation)
    )
    or
    // Buffer.BlockCopy/Array.Copy: source array populates destination array.
    exists(MethodCall call |
      call.getTarget().getName() in ["BlockCopy", "Copy"] and
      call.getTarget().getDeclaringType().getName() in ["Buffer", "Array"] and
      pred = DataFlow::exprNode(call.getArgument(0)) and
      succ = DataFlow::exprNode(call.getArgument(2))
    )
    or
    // WWWForm mutator: binary payload becomes part of the form object.
    exists(MethodCall call |
      call.getTarget().getName() = "AddBinaryData" and
      call.getTarget().getDeclaringType().getName() = "WWWForm" and
      pred = DataFlow::exprNode(call.getArgument(1)) and
      succ = DataFlow::exprNode(call.getQualifier())
    )
    or
    // Serialization/encoding wrappers preserve privacy taint.
    exists(MethodCall call |
      call.getTarget().getName() in ["ToJson", "SerializeObject", "Serialize", "GetBytes", "ToBase64String"] and
      call.getNumberOfArguments() > 0 and
      pred = DataFlow::exprNode(call.getArgument(0)) and succ = DataFlow::exprNode(call)
    )
    or
    // Project-owned serialization/encoding helpers (Serialize*, Compress*,
    // ToBytes*, Encode* over arrays) preserve payload taint from input to the
    // returned carrier. Name-pattern evidence keeps the summary
    // project-independent without enumerating project methods.
    exists(MethodCall call |
      call.getTarget().fromSource() and
      (
        call.getTarget().getName().toLowerCase().matches("%serialize%") or
        call.getTarget().getName().toLowerCase().matches("%compress%") or
        call.getTarget().getName().toLowerCase().matches("%tobytes%") or
        call.getTarget().getName().toLowerCase().matches("%encode%") and
        call.getArgument(0).getType() instanceof ArrayType
      ) and
      call.getNumberOfArguments() > 0 and
      pred = DataFlow::exprNode(call.getArgument(0)) and succ = DataFlow::exprNode(call)
    )
    or
    // HttpContent wrappers: the input becomes the outbound content object.
    exists(ObjectCreation creation |
      creation.getType().getName() in ["StringContent", "ByteArrayContent", "FormUrlEncodedContent", "StreamContent"] and
      pred = DataFlow::exprNode(creation.getArgument(0)) and
      succ = DataFlow::exprNode(creation)
    )
    or
    // Stateful voice/audio accumulator: samples passed to a strongly named
    // buffer become part of that receiver. Type evidence keeps this summary
    // independent of project names while avoiding all-container Cartesian flow.
    exists(MethodCall call |
      isVoiceAccumulatorType(call.getQualifier().getType()) and
      call.getTarget().getName() in ["Push", "PushFrame", "Add", "AddFrame", "AddSamples", "Append", "Write"] and
      call.getNumberOfArguments() > 0 and
      pred = DataFlow::exprNode(call.getArgument(0)) and
      succ = DataFlow::exprNode(call.getQualifier())
    )
    or
    // Finalization/readback from the same strongly named accumulator preserves
    // its content in the returned phrase, frame, or array.
    exists(MethodCall call |
      isVoiceAccumulatorType(call.getQualifier().getType()) and
      call.getTarget().getName() in ["Finalize", "FinalizePhrase", "Build", "CreatePhrase", "Read", "ToArray"] and
      pred = DataFlow::exprNode(call.getQualifier()) and
      succ = DataFlow::exprNode(call)
    )
    or
    // Accesses to the same strongly typed audio accumulator field denote the
    // same persistent buffer across callbacks (push in one phase, finalize in
    // another). The field declaration and accumulator type jointly constrain
    // the bridge.
    exists(FieldAccess stored, FieldAccess loaded |
      stored.getTarget() = loaded.getTarget() and
      isVoiceAccumulatorType(stored.getType()) and
      sameAccumulatorReceiver(stored, loaded) and
      pred = DataFlow::exprNode(stored) and
      succ = DataFlow::exprNode(loaded)
    )
    or
    // Element-wise payload construction: writing a tainted value into an array
    // slot makes the whole array carrier tainted. Voice PCM, serialized
    // packets, and protobuf buffers are routinely built sample-by-sample with
    // index arithmetic, so index-sensitive element flow alone would lose the
    // privacy content before it reaches an outbound transport.
    exists(AssignExpr assignment, ElementWrite write |
      assignment.getLeftOperand() = write and
      pred = DataFlow::exprNode(assignment.getRightOperand()) and
      succ = DataFlow::exprNode(write.getQualifier())
    )
    or
    // Buildless databases may not connect an assignment's right-hand side to
    // the assignment expression node through the standard SSA path when the
    // assigned variable has an unresolved type. The value of an assignment is
    // its right-hand side, so this bridge is always sound.
    exists(AssignExpr assignment |
      pred = DataFlow::exprNode(assignment.getRightOperand()) and
      succ = DataFlow::exprNode(assignment)
    )
    or
    // Buildless fallback for unknown-typed locals: SSA may not connect a
    // tainted reassignment to later reads of the same variable. Bridge the
    // assignment value to reads of the same storage.
    exists(AssignExpr assignment, VariableRead read |
      assignment.getLeftOperand().(VariableAccess).getTarget() = read.getTarget() and
      pred = DataFlow::exprNode(assignment) and
      succ = DataFlow::exprNode(read)
    )
    or
    // Buildless property reads: a tainted receiver exposes its content through
    // a property access (getters may be unresolved for unknown-typed
    // receivers, e.g. `headQuat.w` where headQuat is UnityEngine.Quaternion).
    exists(PropertyAccess access |
      access.hasQualifier() and
      pred = DataFlow::exprNode(access.getQualifier()) and
      succ = DataFlow::exprNode(access)
    )
    or
    // A tainted value written through an object-initializer member assignment
    // taints the object being initialized. This covers DTO construction such
    // as `new XxxCommand { Q = new Quaternion { W = pose } }`, where the nested
    // writes chain value → inner object → outer command/request/payload.
    // (Object-initializer member accesses carry no qualifier, so the bridge
    // climbs from the member initializer to the enclosing object creation.)
    exists(MemberInitializer init, ObjectInitializer owner, ObjectCreation creation |
      owner = init.getParent() and
      creation = owner.getParent() and
      pred = DataFlow::exprNode(init.getRightOperand()) and
      succ = DataFlow::exprNode(creation)
    )
    or
    // Unity Transform pose copies (rig → avatar MapPosition-style sync) keep a
    // pose sensitive for network sync components that later read the pose of
    // the receiving transform.
    exists(AssignExpr assignment, AssignableMemberAccess write, PropertyAccess read |
      write = assignment.getLeftOperand() and
      samePoseProperty(write.getTarget().(Member), read.getTarget().(Member)) and
      pred = DataFlow::exprNode(assignment.getRightOperand()) and
      succ = DataFlow::exprNode(read)
    )
    or
    // A sensitive value written into a transport DTO/message taints that
    // concrete payload object. This is deliberately restricted by semantic
    // payload type/namespace evidence rather than applying to every object.
    exists(AssignExpr assignment, AssignableMemberAccess member |
      member = assignment.getLeftOperand() and
      member.hasQualifier() and
      (
        isPrivacyPayloadMember(member) or
        exists(FieldAccess writtenObject, FieldAccess outboundRead, string transport |
          writtenObject = member.getQualifier() and
          outboundRead.getTarget() = writtenObject.getTarget() and
          isDisclosureSinkKind(DataFlow::exprNode(outboundRead), transport)
        )
      ) and
      pred = DataFlow::exprNode(assignment.getRightOperand()) and
      succ = DataFlow::exprNode(member.getQualifier())
    )
    or
    // The same concrete payload field/object is later passed to an outbound
    // API. Carry object-content taint from the mutation receiver to that
    // outbound read, matching the field declaration rather than every object
    // of the DTO type.
    exists(AssignExpr assignment, AssignableMemberAccess member,
           FieldAccess writtenObject, FieldAccess outboundRead, string transport |
      member = assignment.getLeftOperand() and
      member.hasQualifier() and
      writtenObject = member.getQualifier() and
      outboundRead.getTarget() = writtenObject.getTarget() and
      SensitivityCore::isReceiverCompatible(writtenObject, outboundRead) and
      isDisclosureSinkKind(DataFlow::exprNode(outboundRead), transport) and
      pred = DataFlow::exprNode(writtenObject) and
      succ = DataFlow::exprNode(outboundRead)
    )
  }
}
