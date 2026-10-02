# RepoCheck

[English](./README.md) / [简体中文](./README.zh-CN.md)

RepoCheck is a local-first reproducibility auditor for Python and PyTorch research repositories. We answers four concrete questions:

- Is the information required to reproduce this repository actually present?
- Do code, config, and docs agree with each other?
- Are there obvious reproducibility risks?
- What is the fastest minimal command a new user should try first?


## Why RepoCheck

Research repositories often fail reproducibility for very practical reasons:

- dependencies are not pinned
- Python or CUDA versions are undocumented
- the real entrypoint is unclear
- README commands drift away from code defaults
- dataset paths are hardcoded to a private machine
- seeds are partial or missing
- checkpoints are required but never explained

RepoCheck turns those problems into a structured audit report with evidence, severity, and a suggested minimal reproduction command.

## What It Does

- Scans a local directory, Git URL, or extracted zip
- Detects likely frameworks and config style from repository structure and Python AST
- Extracts runnable commands from README code blocks, scripts, and CI workflows
- Audits environment, entrypoints, config drift, data paths, randomness, docs, and checkpoints
- Produces terminal, JSON, and HTML reports
- Optionally runs a lightweight smoke check in an isolated virtual environment

## Quick Start

Fastest path, directly from source:

```bash
python -m repocheck check .
```

Common commands:

```bash
python -m repocheck check .
python -m repocheck check path/to/repo --report all
python -m repocheck check path/to/repo --smoke
python -m repocheck run path/to/repo --mode smoke
```

Install the CLI in editable mode:

```bash
python -m venv .venv
```

macOS / Linux:

```bash
.venv/bin/python -m pip install -e .
repocheck check .
```

Windows PowerShell:

```powershell
.venv\Scripts\python -m pip install -e .
repocheck check .
```

## Example Output

```text
Reproducibility Score: 47/100
Risk Summary: 3 high, 1 medium, 0 low

Suggested minimal command
python train.py --batch-size 64 --data-root ./data --epochs 1 --seed 42

Findings
[HIGH] ENV001: Dependency versions are not pinned
[HIGH] DATA001: Hardcoded absolute data path detected
[HIGH] SEED001: No reproducibility seed found
[MEDIUM] CFG001: README, config, and code values disagree
```

## Initial Rule Set

RepoCheck currently ships with an MVP rule set focused on the highest-value checks:

- `ENV001`: dependency versions are not pinned
- `ENV002`: Python version is not declared
- `CUDA001`: CUDA or cuDNN requirements are undocumented
- `RUN001`: runnable entrypoint is missing or broken
- `RUN002`: suggested minimal command is not actually runnable
- `DOC001`: README lacks a minimal executable example
- `DATA001`: hardcoded absolute data path detected
- `DATA002`: data preparation or download steps are missing
- `DATA003`: dataset version, integrity, or download verification details are incomplete
- `SEED001`: reproducibility seed setup not found
- `SEED002`: DataLoader or CUDA determinism setup is incomplete
- `CFG001`: README, config, and code values conflict
- `CFG002`: configuration precedence or resolved config export is incomplete
- `EVAL001`: evaluation protocol is not reproducible
- `ART001`: checkpoint source is undocumented

## Repository Layout

```text
repocheck/
 __main__.py
 cli.py
 core.py
tests/
 fixtures/
 test_cli.py
```

## Current Scope

- Python repositories first
- Best-effort support for PyTorch, argparse, Click, and Hydra-style projects
- Static analysis is the default and recommended first step
- Smoke mode is intentionally lightweight; it validates command reachability with `--help` and `--dry-run`

## Development

Run tests:

```bash
python -m unittest discover -s tests -v
```

Run the packaged CLI locally:

```bash
python -m repocheck check tests/fixtures/sample_project --report all
```

## Contributing

If there are any important judgment criteria that haven't been mentioned, PRs are welcome!


Smoke mode executes repository-provided code with your user privileges. A virtual environment isolates Python packages, not files, credentials, network, or processes. Only run smoke checks on code you trust; use a separately sandboxed container for untrusted repositories.
