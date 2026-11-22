# Security policy

Vulnpath is a security tool, so a wrong `not_reachable` verdict is treated as a security bug.

## Reporting a vulnerability

Please report privately through GitHub's **"Report a vulnerability"** button on the
Security tab of this repository (GitHub private vulnerability reporting). Do not open a
public issue for security problems.

Include:

- The Vulnpath version (`vulnpath --version`) and dataset version.
- A minimal project that reproduces the problem, if possible.
- What you expected and what happened.

## What counts as a security issue

- A `not_reachable` verdict for code that can actually reach the affected symbol.
- Any way for analysed code or a downloaded package to execute during analysis.
- Any way to make the analyzer accept an unsigned or tampered dataset.
- Path traversal or resource exhaustion when extracting archives.

## Supported versions

Only the latest release receives fixes while the project is pre-1.0.
