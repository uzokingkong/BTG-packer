# Bidirectional Trigger Graph VM Design

> **Status: Planned / Experimental design**
>
> This document describes a proposed execution identity for future BTG Program-VM work. It is not a claim that the current production backend already implements this complete model.

## Goal

The design goal is to make BTG recognizable as more than a conventional bytecode interpreter with opcode permutation.

The proposed identity combines four ideas:

1. bidirectional trigger-graph execution;
2. cooperative heterogeneous VM families;
3. cross-family semantic decomposition;
4. evolving route/dispatch state.

The current codebase already contains several prerequisites for this direction: a RISC semantic layer, multi-family planning, canonical cross-family state, generated route metadata, polymorphic encoding and rolling-key runtime state.

## Proposed execution model

```mermaid
flowchart TD
    A["Original x86-64 semantics"] --> B["RISC Semantic IR"]
    B --> C["Semantic Partition / Decomposition"]

    C --> S["Stack VM"]
    C --> R["Register VM"]
    C --> M["MixedRisc VM"]
    C --> F["FusedCisc VM"]

    S <--> X["Canonical VM State"]
    R <--> X
    M <--> X
    F <--> X

    X --> T["Bidirectional Trigger Graph"]
    T --> N1["Trigger Node A"]
    T --> N2["Trigger Node B"]
    T --> N3["Trigger Node C"]

    N1 --> Q["Route / Family Resolver"]
    N2 --> Q
    N3 --> Q

    Q --> S
    Q --> R
    Q --> M
    Q --> F
    Q --> V["VM ↔ Native Bridge"]
```

The key distinction from a conventional VM is that the intended long-term execution identity is not simply:

```text
VIP -> decode opcode -> handler -> next VIP
```

Instead, route selection can conceptually depend on a larger execution state:

```text
current VM state
+ predecessor/transition token
+ semantic event
+ active family
+ rolling decode state
-> trigger-node resolution
-> next route/family
```

## Bidirectional trigger graph

A conventional CFG primarily describes forward control transfer. The proposed BTG graph treats transition history as part of the execution contract as well.

```mermaid
flowchart LR
    A["Node A"] <--> B["Node B"]
    B --> C["Node C"]
    C <--> D["Node D"]
    D --> E["Node E"]
    E --> B
```

A trigger node can consume both current state and transition metadata and then emit new route state.

Conceptually a node may have inputs such as:

```text
semantic class
predecessor token
family state
packed flags
rolling state class
```

and outputs such as:

```text
next trigger token
next VM family
route destination
updated decode/transition state
```

This would make graph topology part of the VM execution model instead of being only documentation around a linear bytecode stream.

## Cooperative VM families

BTG already models multiple VM architecture families. The proposed extension pushes that concept beyond simple function assignment.

A semantic region may eventually be decomposed across families:

```mermaid
flowchart LR
    A["One source semantic region"] --> B["RISC decomposition"]
    B --> C["Register VM fragment"]
    C --> D["Canonical state exchange"]
    D --> E["Stack VM fragment"]
    E --> F["Canonical state exchange"]
    F --> G["MixedRisc VM fragment"]
    G --> H["Completed semantic result"]
```

The intended benefit is architectural diversity: analysis of one family's private representation does not fully describe the complete semantic operation.

## Evolving topology state

The current commercial runtime already uses rolling-key state to decode the encoded instruction stream. A future extension can make evolving state influence more than byte recovery.

Potential state-controlled domains include:

```text
opcode representation
operand representation
virtual-register mapping
handler/table mapping
condition encoding
trigger-edge selection
family route selection
```

```mermaid
flowchart TD
    K["Evolving VM State"] --> O["Opcode Decode"]
    K --> P["Operand Decode"]
    K --> R["Register Mapping"]
    K --> H["Handler Mapping"]
    K --> T["Trigger Edge Selection"]
    K --> F["Family Route Selection"]

    O --> U["Semantic Execution"]
    P --> U
    R --> U
    H --> U
    T --> U
    F --> U

    U --> K
```

## Relationship to the current implementation

The design should be implemented incrementally rather than replacing the existing validated backend at once.

A reasonable progression is:

```mermaid
flowchart LR
    A["Current multi-family Program-VM"] --> B["Explicit trigger-node metadata"]
    B --> C["State-aware route selection"]
    C --> D["Region-level family transitions"]
    D --> E["Cross-family semantic decomposition"]
    E --> F["Full bidirectional trigger-graph execution"]
```

Each stage should preserve the current project's fail-closed philosophy: new graph execution should not be advertised as complete until coverage, semantic equivalence and native-runtime validation can measure it explicitly.

## Documentation rule

Until a stage is implemented and validated, root README material should label it as planned or experimental. Current implemented behavior remains documented in `../program-vm.md` and `../architecture.md`.
