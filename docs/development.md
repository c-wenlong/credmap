# Development

| Item | Value |
|---|---|
| Python | 3.11 or newer (`tomllib` is stdlib from 3.11) |
| Runtime dependency | PyYAML 6+ |
| Build backend | hatchling, wheel from `src/credmap` |
| Package manager | uv |
| Tests | pytest, 230 tests, about 5 s (the liveness tests run stub CLIs with real timeouts) |
| Lint | ruff, `check` and `format`, line length 88, target py311 |

```bash
uv sync                      # after a fresh clone or a move; the venv is not portable
uv run pytest -q             # run the suite
uv run ruff check .          # lint, same gate as CI
uv run ruff format .         # format, CI checks this with --check
uv run python -m credmap     # run without installing
uv tool install . --force    # put credmap on PATH from this checkout
uv build                     # sdist and wheel into dist/

nix build                    # the same package nix-darwin consumers get; runs the tests
nix develop                  # shell with python, pyyaml, pytest and uv
```

A flake build only sees git-tracked files. A new module that is not staged
is silently left out of the build.

## Tests

Fixtures are generated in `tests/conftest.py`, not committed. Nothing in the
repo should look like a credential file to a human or a secret scanner.

The `fake_home` fixture builds a synthetic home covering every format, points
`HOME` at it, and clears every override variable so a developer's real
environment cannot leak into a test. The list comes from `override_vars()` in
`tests/conftest.py`, which walks `registry.BUILTIN` for every `env` and
`root_env` and adds the two XDG roots, so it cannot fall behind a new store.
There are 12 today.

| File | Covers |
|---|---|
| `test_cli.py` | Default verb, exit codes, JSON validity |
| `test_parsers.py` | One test per format, plus robustness against malformed input |
| `test_redact.py` | The whole-program leak test, parametrised over every sentinel secret |
| `test_registry.py` | Marker semantics, env overrides, lookup, the TOML overlay |
| `test_resolve.py` | Path resolution precedence and `display` |
| `test_doctor.py` | What counts as one problem and what its fix line says |
| `test_liveness.py` | Probe subprocess handling, name matching, status fan-out, all against stub CLIs on `PATH` |

`tests/test_redact.py` is the file to be most careful with. It is the only
thing standing between a refactor and a secret in someone's terminal
transcript. Any new renderer must be added to its `_all_output()` list.

## Releasing

See [releasing.md](releasing.md).

## Continuous integration

`.github/workflows/ci.yml` runs on every push to `main` and every pull
request. Five jobs:

| Job | What it does |
|---|---|
| Tests | The suite and `uv build --no-sources` on Linux and macOS, Python 3.11 and 3.13 |
| Lint | `ruff check`, `ruff format --check`, and `zizmor` over the workflow files |
| Coverage | The suite under `pytest --cov`, uploaded to Codecov; a failed upload does not fail the job |
| Built wheel smoke test | Installs the wheel into a fresh venv and runs the entry point against a temporary `$HOME`, so a module missing from the wheel is caught |
| Nix flake build and check | `nix build` (which runs the suite in the sandbox), the built binary, and `nix flake check` |

Every job syncs with `uv sync --locked`, which refuses to run if `uv.lock` is
out of step with `pyproject.toml`. Run `uv lock` after touching dependencies
and commit the result. (`--frozen` would skip that comparison; `--locked`
makes the drift a CI failure.)
