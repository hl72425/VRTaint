# Category2 — Object Identity and Heap

This category evaluates field, object, container-element, and receiver identity.
The serialized scenes under `Fixtures` isolate Unity component-instance identity.

| Case | Serialized binding | Storage | Expected |
|---|---|---|---|
| 2.19P | `buffer -> BufferA` | instance field | FLOW |
| 2.20N | `writer -> BufferA`, `reader -> BufferB` | instance field | NO_FLOW |
| 2.21P | `writer -> BufferA`, `reader -> BufferA` | instance field | FLOW |
| 2.22P | `writer -> BufferA`, `reader -> BufferB` | static field | FLOW |

The `.unity` files define the ground truth. Tool-specific facts are derived inputs, not labels.
