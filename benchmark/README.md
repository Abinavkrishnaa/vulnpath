# Benchmark

The labelled benchmark arrives in milestone M1. It will hold:

- `corpus.toml`: real open-source projects pinned to exact commits.
- `labels/`: one file per (project, advisory) with the expected verdict and its evidence,
  labelled by one person and checked by a second.
- `run.py`: runs Vulnpath (and competitor adapters) and reports precision, plus every false
  `not_reachable`, which is a release blocker.
