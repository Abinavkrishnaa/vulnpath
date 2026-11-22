# ADR-0005: Dataset distributed as signed static release files

- Status: Accepted
- Date: 2026-11-22

## Context

Scans must work offline, be reproducible, and never depend on a server being available.

## Decision

Publish the dataset as a JSON Lines file per release on GitHub Releases, signed with Sigstore keyless signing from the release workflow. The analyzer verifies the signature and the signing workflow identity before use.

## Alternatives considered

A live API queried during scans.

## Consequences

- Same inputs give the same output.
- Users can pin a dataset version.
- New data reaches users only when they update the dataset.
