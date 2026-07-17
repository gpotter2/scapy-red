# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`scapy-red` is a Python package of CLI wrappers around Scapy's networking primitives, oriented toward red-team / pentest use cases (LDAP rootDSE recon, SMB scanning, DCOM IP enumeration, SMB client, LDAPHero, LSA rights management, remote Windows registry). Requires Python 3.11+, depends on `scapy>=2.7.1rc1` and `scapy-rpc>=0.0.7`.

## Common commands

```bash
# Install for development (use `[tests]` extras to pull scapy from git)
pip install -e .[tests]

# Lint / style (matches CI)
tox -e flake8           # flake8 7.3.0, max-line-length=88, ignores E203,E731,E402,F401,F403,W504,W503
tox -e spell            # codespell with .config/codespell_ignore.txt
black .                 # CI uses psf/black@stable on the whole repo

# Build / packaging sanity check
tox -e twine

# Run the test suite (Scapy's UTscapy harness, not pytest)
python3 -m scapy.tools.UTscapy -c tests/config.utsc -f live

# Run a single .uts test file
python3 -m scapy.tools.UTscapy -t tests/winreg.uts
```

The `winreg.uts` tests connect to `127.0.0.1` over SMB and exercise the live Windows registry — they require running on Windows with admin and `WinSSP`. CI runs them on `windows-latest`.

## Architecture

### Each command is a Scapy function + one-line wrapper

Every CLI lives in its own `scapyred/<tool>.py` module and follows the same shape:

1. A top-level function (e.g. `dominfo`, `listips`, `smb_scan_winver`, `lsamgr`) whose **type annotations and docstring drive the CLI**: `scapy.utils.AutoArgparse` introspects them to build argparse.
2. A `main()` that calls `AutoArgparse(<func>)`.
3. A module-level `AUTOCOMPLETE_GEN = <func>` used by `setup.py` to generate bash completions at build time.
4. An entry in `[project.scripts]` of `pyproject.toml` exposing it as `scapy-<tool>`.

When adding a new command: write the function with full type hints + docstring, set `AUTOCOMPLETE_GEN`, register the script in `pyproject.toml` — there is no separate argparse layer to keep in sync.

### Scapy extension registration

`scapyred/__init__.py` defines `scapy_ext(pkg)`, which Scapy calls when something does `conf.exts.load("scapy-red")`. Most `main()` entry points call this themselves to register bash completions for interactive Scapy sessions. Tools that use DCE/RPC (`lsamgr.py`, `winreg.py`) additionally call `conf.exts.load("scapy-rpc")` at import time to pull in the `scapy.layers.msrpce.raw.*` modules.

### Bash completion generation

`setup.py` overrides `sdist` and `build_py` with `_build_completions()`, which:
- Reads `[project.scripts]` from `pyproject.toml`.
- Imports each entry point's `AUTOCOMPLETE_GEN` function.
- Calls `AutoArgparse(func, _parseonly=True)` to extract argument lists.
- Renders `scapyred/completions/template_complete.bash` + `template_script.bash` into per-command completion scripts under `scapyred/completions/scapy-<tool>`.

This means **completions are not committed** — they are generated on every build/sdist and shipped in the wheel. If a function has no `AUTOCOMPLETE_GEN`, completion generation silently skips it.

### winreg.py is the outlier

Unlike the other modules, `scapyred/winreg.py` is a stateful interactive CLI: `RegClient` extends `scapy.utils.CLIUtil` and registers commands via `@CLIUtil.addcommand()`, `@CLIUtil.addcomplete(...)`, `@CLIUtil.addoutput(...)`. It supports both interactive use (`cli=True`, default) and scripting (`cli=False`, used by tests). Authentication goes through `SPNEGOSSP.from_cli_arguments(...)` like `lsamgr`, plus a `use_winssp` path for implicit auth on Windows.

### Tests

Tests are **UTscapy** (`*.uts`), not pytest — sections are marked with `=`, blocks of Python execute against shared module state. `tests/config.utsc` selects `tests/*.uts` and sets `breakfailed: true, onlyfailed: true`. Don't add a pytest layer; extend the existing `.uts` files or add new ones.

## Style / CI gates

CI (`.github/workflows/unittests.yml`) enforces, in this order: `black`, `flake8`, `codespell`, `twine check --strict`, an SPDX-header check (`.github/check_spdx.sh` — every source file needs `SPDX-License-Identifier: GPL-2.0-only`), CodeQL, and the Windows UTscapy run. Match the existing header block (SPDX line, "This file is part of Scapy RED", copyright) when creating new files.
