# ADR-0003: Three verdicts with unknown as the safe default

- Status: Accepted
- Date: 2026-11-22

## Context

A security tool that wrongly says "not affected" is worse than no tool. Confidence scores cannot be audited by users or auditors.

## Decision

Every finding is `reachable`, `not_reachable` or `unknown`. `not_reachable` is allowed only after a complete search with no soundness blockers. Every verdict carries evidence: a call path, search statistics, or a list of blockers with file and line. The schema enforces this.

## Alternatives considered

Numeric confidence scores only.

## Consequences

- Some alerts stay `unknown`, which lowers noise reduction compared with tools that guess.
- Every `not_reachable` can be defended with evidence, including in OpenVEX statements.
