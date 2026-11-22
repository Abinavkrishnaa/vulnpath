# ADR-0002: Own demand-driven resolver behind a CallResolver interface

- Status: Accepted
- Date: 2026-11-22

## Context

Vulnpath needs a call graph to decide reachability. PyCG, the best-known Python call-graph tool, was archived in November 2023. Whole-program call graphs over large dependency trees are slow and mostly wasted work, because only paths into the affected package matter.

## Decision

Implement a demand-driven backward search: start from each affected symbol and expand callers file by file until an entry point is reached or the frontier is empty. Hide name resolution behind a `CallResolver` interface.

## Alternatives considered

Depend on PyCG (unmaintained); build a whole-program call graph first (slow on large trees).

## Consequences

- Scans touch only code that could matter.
- A type-aware resolver (for example ty or Pyrefly, if they expose a stable API) can replace the default one later without changing the verdict engine.
- We own correctness of name resolution, so it needs extensive golden fixtures.
