# Contributing to credmap

credmap reads the most sensitive files on a machine and prints about them. Two
rules follow from that and everything else is negotiable: **it never writes to a
credential file**, and **it never prints a secret unless you asked for one**.
Keep both true and your change is welcome.

## Getting started

```bash
git clone https://github.com/c-wenlong/credmap.git
cd credmap
uv sync                      # the venv is not portable; re-run after a move
uv run pytest -q             # 230 tests, about 5 seconds
uv run python -m credmap     # run without installing
```

`uv.lock` is committed and CI runs `uv sync --locked`, which fails if the lock
is out of step with `pyproject.toml`, so run `uv lock` after touching
dependencies and commit the result.

Formatting and lint are a gate: `uv run ruff check .` and `uv run ruff format
--check .` both run in CI. Optionally run them on every commit with
`uvx pre-commit install`, which picks up [.pre-commit-config.yaml](.pre-commit-config.yaml)
and also keeps `uv.lock` in step for you.

Nix users can skip uv: `nix develop` opens a shell with Python, PyYAML, pytest
and uv, and `nix build` builds the package and runs the suite in the sandbox.
A flake build only sees git-tracked files, so an unstaged new module is
silently left out.

[docs/development.md](docs/development.md) has the rest: the test layout, what
each test file covers, and how the fixtures are built.

## Project layout

Twelve modules under `src/credmap/`, counting `__init__.py` and `__main__.py`.
The load-bearing seam is that **the registry is data and the parsers are
behaviour**: adding a provider should be a `Store(...)` literal and nothing
else. The ten that carry logic:

| Module | Role |
| --- | --- |
| `registry.py` | One `Store` per provider, plus the `registry.toml` overlay loader and `find()` |
| `model.py` | The two schemas: registry (`Store`, `PathSpec`, `Probe`) and result (`StoreResult`, `FoundPath`, `Profile`) |
| `resolve.py` | Env override, then XDG, then template. The only place path rules live |
| `parsers.py` | One function per format, all wrapped so they never raise on malformed input |
| `redact.py` | The single masking chokepoint, default-deny on field names |
| `scan.py` | Walks the registry, stats each path, dispatches to parsers, sizes directories |
| `liveness.py` | `--check` probes: subprocess without a shell, hard timeouts, a thread pool under a deadline |
| `doctor.py` | Anomaly checks over a completed scan |
| `render.py` | Grouped scan output, flat tables, JSON |
| `cli.py` | argparse, and the rewrite that turns a bare `credmap aws` into `where aws` |

[docs/architecture.md](docs/architecture.md) explains the data flow and why the
per-path and merged profile views must not be collapsed.

## What to contribute

- **New stores.** A provider credmap does not know about is a `Store` entry in
  `registry.py`. Set `marker=True` on the path whose existence proves the store
  is real (a directory is not proof), mark secret files `role="secrets"`, and
  list identifiers that look secret but must stay visible in `id_fields`. Users
  can prototype one without touching the package through the
  `~/.config/credmap/registry.toml` overlay, documented in
  [docs/registry-toml.md](docs/registry-toml.md).
- **New parsers.** A credential format nothing in `parsers.py` handles yet.
  Parsers return a `ParseResult`; they never raise.
- **New probes.** A `Probe` gives `--check` a way to ask a provider whether a
  credential still works. Argv only, no shell, bounded output.
- **Redaction and doctor rules**, bug fixes and docs. Always welcome.

## Guidelines

1. **credmap never writes to a credential file.** No `open()` for writing, no
   `write_text`, `unlink`, `rename`, `shutil` or `mkdir` anywhere in the
   package. Output goes through `sys.stdout.write`. SQLite is opened read-only
   by URI. This is the property the whole tool rests on, so a change that adds
   a write path will be rejected even if it works.
2. **Never commit anything that looks like a credential.** Fixtures are
   generated in `tests/conftest.py`, never stored. The fake token prefixes
   there are deliberately broken (`ghox_`, not `gho_`) so secret scanners do
   not match them. `registry.toml`, `*.pem`, `*.key` and `.env` are gitignored;
   do not work around that.
3. **Tests must not depend on your real `$HOME`.** The `fake_home` fixture
   builds a synthetic home and clears every override variable. If you check
   something by hand, do it under `HOME="$(mktemp -d)"`.
4. **Everything printed goes through `redact.scrub`.** A new renderer has to be
   added to `_all_output()` in `tests/test_redact.py`, which is the single test
   standing between a refactor and a secret in someone's terminal transcript.
5. **Add tests** for a new parser, store, probe or redaction rule. Malformed
   input is part of the contract, so test it.
6. **One concern per PR.** A real bug you find outside the scope of your change
   gets its own PR.

## Pull request process

1. Fork, branch from `main`.
2. Make the change, add tests, run `uv run pytest -q`.
3. Update the docs under `docs/` and the `--help` text if user-facing behaviour
   changed, and add a `CHANGELOG.md` entry.
4. Open a PR and fill in the template. The checklist there is the short form of
   the guidelines above.

CI runs the suite on Linux and macOS with Python 3.11 and 3.13, runs ruff and
zizmor, measures coverage, smoke-tests the built wheel against a temporary
`$HOME`, and builds the flake.

## Reporting bugs

Use the [bug report form](https://github.com/c-wenlong/credmap/issues/new?template=bug_report.yml).
Redact before you paste: `--reveal` output is never safe to share, and paths and
profile names can identify you even when the secrets are masked.

Security problems do not go in a public issue. See [SECURITY.md](SECURITY.md).
