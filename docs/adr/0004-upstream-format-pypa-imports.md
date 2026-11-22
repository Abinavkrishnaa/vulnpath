# ADR-0004: Upstream data format is PyPA ecosystem_specific.imports

- Status: Accepted
- Date: 2026-11-22

## Context

The PyPA Advisory Database already defines an optional `ecosystem_specific.imports` field (module and attribute) for affected code elements.

## Decision

Store affected symbols in a shape that maps one-to-one onto that field, with Vulnpath-only extensions (`kind`, `change`) that are dropped on export.

## Alternatives considered

Invent a new schema.

## Consequences

- Verified data can be contributed upstream without conversion loss.
- Open question for maintainers: whether method-level attributes like `Class.method` are accepted.
