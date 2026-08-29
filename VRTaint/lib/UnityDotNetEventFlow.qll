/**
 * @name UnityDotNetEventFlow
 * @description Project-independent flow from C# event/delegate publication
 *              arguments to statically registered handler parameters.
 */

import csharp

module UnityDotNetEventFlow {
  /**
   * The publisher may reference the concrete implementation event while a
   * subscriber is typed through an interface/base contract.  Treat those as
   * one event only when the event name and declaring-type hierarchy agree.
   */
  private predicate sameEventContract(Event published, Event subscribed) {
    published = subscribed
    or
    published.getName() = subscribed.getName() and
    (
      published.getDeclaringType().getABaseType*() = subscribed.getDeclaringType()
      or subscribed.getDeclaringType().getABaseType*() = published.getDeclaringType()
    )
  }

  private predicate subscribedHandler(AddEventExpr subscription, Event event,
                                      Callable handler) {
    subscription.getLeftOperand().(EventAccess).getTarget() = event and
    (
      exists(MethodAccess ma |
        ma = subscription.getRightOperand().getAChildExpr*() and
        handler = ma.getTarget()
      )
      or
      exists(LambdaExpr lambda |
        lambda = subscription.getRightOperand().getAChildExpr*() and
        handler = lambda
      )
      or
      exists(AnonymousMethodExpr anonymous |
        anonymous = subscription.getRightOperand().getAChildExpr*() and
        handler = anonymous
      )
    )
  }

  private predicate invokedEvent(DelegateCall invocation, Event event) {
    exists(EventAccess access |
      access = invocation.getExpr().getAChildExpr*() and
      access.getTarget() = event
    )
  }

  /** Resolve an event publication argument, including null-conditional `?.Invoke`. */
  private predicate publishedArgument(Expr argument, int index, Event event) {
    exists(DelegateCall invocation |
      invokedEvent(invocation, event) and
      index >= 0 and index < invocation.getNumberOfArguments() and
      argument = invocation.getArgument(index)
    )
    or
    exists(MethodCall invocation, EventAccess access |
      invocation.getTarget().getName() = "Invoke" and
      access = invocation.getQualifier().getAChildExpr*() and
      access.getTarget() = event and
      index >= 0 and index < invocation.getNumberOfArguments() and
      argument = invocation.getArgument(index)
    )
  }

  /** Event publication argument to the corresponding registered handler parameter. */
  predicate isDotNetEventFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(Expr argument, AddEventExpr subscription,
           Event publishedEvent, Event subscribedEvent,
           Callable handler, int index |
      publishedArgument(argument, index, publishedEvent) and
      subscribedHandler(subscription, subscribedEvent, handler) and
      sameEventContract(publishedEvent, subscribedEvent) and
      index >= 0 and
      index < handler.getNumberOfParameters() and
      pred = DataFlow::exprNode(argument) and
      succ = DataFlow::parameterNode(handler.getParameter(index))
    )
  }
}
