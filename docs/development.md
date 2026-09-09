# Development

| Item | Value |
|---|---|
| Python | 3.11 or newer (`tomllib` is stdlib from 3.11) |
| Runtime dependency | PyYAML 6+ |
| Build backend | hatchling, wheel from `src/credmap` |
| Package manager | uv |
| Tests | pytest, 87 tests, about 0.4 s |

```bash
uv sync                      # after a fresh clone or a move; the venv is not portable
uv run pytest -q             # run the suite
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
`HOME` at it, and clears the override variables (`XDG_CONFIG_HOME`,
`XDG_CACHE_HOME`, `AWS_SHARED_CREDENTIALS_FILE`, `AWS_CONFIG_FILE`,
`CLOUDSDK_CONFIG`, `KUBECONFIG`, `DOCKER_CONFIG`,
`GOOGLE_APPLICATION_CREDENTIALS`, `GH_CONFIG_DIR`, `NETRC`) so a developer's
real environment cannot leak into a test. `AZURE_CONFIG_DIR` and `GNUPGHOME`
are honoured by the registry but not cleared by the fixture yet.

| File | Covers |
|---|---|
| `test_cli.py` | Default verb, exit codes, JSON validity |
| `test_parsers.py` | One test per format, plus robustness against malformed input |
| `test_redact.py` | The whole-program leak test, parametrised over every sentinel secret |
| `test_registry.py` | Marker semantics, path resolution, lookup, TOML overlay, doctor |

`tests/test_redact.py` is the file to be most careful with. It is the only
thing standing between a refactor and a secret in someone's terminal
transcript. Any new renderer must be added to its `_all_output()` list.

## Releasing

See [releasing.md](releasing.md).
