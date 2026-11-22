# ADR-0006: Pipeline on GitHub Actions, data as YAML in git, review as pull requests

- Status: Accepted
- Date: 2026-11-22

## Context

The project must have zero running cost. A rented server with Django, Celery, RabbitMQ and Postgres would add monthly cost and operations work.

## Decision

Run the dataset pipeline as scheduled GitHub Actions workflows in the public `vulnpath-data` repository. Store one YAML record per advisory in git. Each new advisory arrives as a bot-opened pull request; a maintainer's approval and merge is the verification step.

## Alternatives considered

Django + Celery + RabbitMQ + Postgres on a rented server.

## Consequences

- $0 running cost: standard GitHub-hosted runners are free for public repositories.
- Nothing to operate or back up; git history is the audit log.
- Backlog processing is slower and bounded by API rate limits; workflows must be resumable.
