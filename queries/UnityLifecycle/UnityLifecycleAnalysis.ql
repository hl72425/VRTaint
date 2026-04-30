/**
 * UnityLifecycleAnalysis.ql
 * Simple validation query — list lifecycle-like methods detected by the library.
 */

import csharp
import UnityLifecycleModel

from Method m
where isLifecycleEntry(m)
select m, "Unity lifecycle or XR lifecycle callback method"
