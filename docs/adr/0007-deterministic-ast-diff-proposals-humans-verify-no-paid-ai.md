# ADR-0007: Deterministic AST-diff proposals; humans verify; no paid AI

- Status: Accepted
- Date: 2026-11-22

## Context

One wrong affected-symbol record can hide a real vulnerability. Paid LLM APIs would add recurring cost.

## Decision

Candidate symbols come from a deterministic AST diff between the last affected and first fixed release. Only human-approved records can drive verdicts. An optional locally run open-weight model may rank candidates after v1, as a proposal only.

## Alternatives considered

LLM-verified records; paid LLM ranking.

## Consequences

- Proposals are reproducible and cost nothing.
- Review takes more human time per advisory.
