# ADR-0001: Analyzer in pure Python on the stdlib ast module

- Status: Accepted
- Date: 2026-11-22

## Context

The analyzer must install with `uvx vulnpath` or `pipx install vulnpath` on any machine, including CI runners without a compiler, and it only needs to read code, not rewrite it.

## Decision

Write the analyzer in pure Python and parse source with the standard library `ast` module. Use LibCST only if a future feature needs lossless round-tripping.

## Alternatives considered

Rust core now (fast, but needs a build toolchain and slows early iteration); LibCST everywhere (slower, and its concrete syntax tree is unnecessary for read-only analysis).

## Consequences

- No native build step; one wheel for all platforms.
- Parsing speed is adequate for the 60 s cold-scan target; revisit with profiling data.
- A Rust rewrite of the hot path stays possible behind the resolver interface (ADR-0002).
