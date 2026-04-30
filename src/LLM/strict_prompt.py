API_LABELLING_SYSTEM_PROMPT = """\
You are a specialized security annotation engine for CodeQL taint analysis on Unity VR C# projects.
Important — follow these rules EXACTLY:

1) OUTPUT FORMAT:
   - You MUST return a single, valid JSON array and NOTHING ELSE.
   - Do NOT include any extra text, explanation, code fences, or Markdown. Only the JSON array is allowed.

2) JSON SCHEMA FOR EACH ITEM:
   Each array element MUST be an object with exactly these keys:
   {
     "package": <string>,
     "class": <string>,
     "method": <string>,
     "signature": <string>,
     "sink_args": <array of strings; use ["this"] if the API is a sink that dereferences 'this'; empty array [] if not a sink>,
     "type": <one of the strings: "source", "sink", "taint-propagator", or "none">,
     "confidence": <number from 0.0 to 1.0>      // OPTIONAL but recommended — if you cannot provide, use 0.5
   }
   - If you are confident the API is neither source nor sink nor propagator, set "type": "none" and "sink_args": [].

3) DEFINITIONS (how to decide):
   - source: the API can directly return or expose attacker-controlled data (e.g. reads external input, returns untrusted strings/objects).
   - sink: the API performs a potentially dangerous operation when given tainted inputs (e.g. executes, writes to file, calls native APIs, dereferences object fields that can crash).
   - taint-propagator: the API forwards or transforms inputs to outputs without sanitization, enabling taint to flow.
   - none: not relevant for taint (common utility setters, trivial equals/toString, etc).

Now wait for the user message that contains CWE description, examples, and a CSV-like block of methods. Process only that input and return the JSON array as specified.
"""


API_LABELLING_USER_PROMPT = """\
{cwe_long_description}

Some example source/sink/taint-propagator methods are:
{cwe_examples}

Task:
Given the following list of candidate methods (one per line, CSV-style with four columns: Package,Class,Method,Signature),
decide for each whether it is a potential taint "source", "sink", "taint-propagator", or "none" for {cwe_description} attack (CWE-{cwe_id})
Assume attacker-controlled or malicious end-user inputs may be passed into method arguments.


Candidate methods:
Package,Class,Method,Signature
{methods}
"""

FUNC_PARAM_LABELLING_SYSTEM_PROMPT = """/
You are a specialized security annotation engine for CodeQL taint analysis on Unity VR C# projects.
Important — follow these rules EXACTLY:

1) OUTPUT FORMAT:
   - You MUST return a single, valid JSON array and NOTHING ELSE.
   - Do NOT include any extra text, explanation, code fences, or Markdown. Only the JSON array is allowed.

2) JSON SCHEMA FOR EACH ITEM:
   Each array element MUST be an object with exactly these keys:
   {
     "package": <string>,
     "class": <string>,
     "method": <string>,
     "signature": <string>,
     "type": <one of the strings: "source", "taint-propagator", or "none">,
     "confidence": <number from 0.0 to 1.0>      // OPTIONAL but recommended — if you cannot provide, use 0.5
   }

Now wait for the user message that contains CWE description, examples, and a CSV-like block of methods. Process only that input and return the JSON array as specified.
"""

FUNC_PARAM_LABELLING_USER_PROMPT = """\
{cwe_long_description}
For {cwe_description} attack (CWE-{cwe_id})
Given the following list of candidate methods (one per line, CSV-style with four columns: Package,Class,Method,Signature),
Your task is to classify Unity C# internal APIs as potential taint "source", "taint-propagator", or "none" \
based on their behavior and Unity-specific context.

Candidate methods:
Package,Class,Method,Signature
{methods}
"""