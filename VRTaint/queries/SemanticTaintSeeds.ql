/**
 * @name Unity semantic taint seed facts
 * @description Emits every CodeQL-backed semantic seed even when no observation endpoint is reachable.
 * @kind table
 * @id cs/unity-semantic-taint-seeds
 */

import csharp
import lib.SemanticTaintFacts

from DataFlow::Node source, string factId, string objectId, string accessPath,
     string phase, string context, string sourceKind, string influenceKind, string confidence
where SemanticTaintFacts::seed(source, factId, objectId, accessPath, phase, context,
                               sourceKind, influenceKind, confidence)
select factId, objectId, accessPath, phase, context, sourceKind, influenceKind,
  confidence, source
