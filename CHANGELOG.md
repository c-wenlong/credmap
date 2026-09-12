# Changelog

Versions follow [semantic versioning](https://semver.org). Findings referenced
by number are the review ledger in [docs/known-issues.md](docs/known-issues.md).

## Unreleased

Repository, documentation and CI work. No behaviour change: the only edits
under `src/` are ruff's formatting, three `try`/`except`/`pass` blocks
rewritten as `contextlib.suppress`, and long string literals split.

### Documentation

- README gains a header card: banner, badges, and a nav row to the docs.
- Doc audit against the code. The corrections:
  - The test count was stale at 65 and is 230.
  - The formats were counted as six and there are ten, under four base directories rather than three.
  - `--found` belongs to `paths` and drops absent paths from the table and from `--json` alike; `--all` belongs to `scan`.
  - `docs/security.md` said no module imports `urllib`, when `parsers.py` imports `urllib.parse` to percent-quote the SQLite URI, and described output as going through `print` when it goes through `sys.stdout.write`.
  - PyPI is described as reserved and switched off rather than published, and the Homebrew tap as a decision against rather than an option.
  - Module count, `model.py`'s dataclass list, the test-file table, the `jsondir` naming rule, `paths[].size` for a directory, and the overlay permission warning all now match the code.

### Repository hygiene

- `CONTRIBUTING.md`, `SECURITY.md`, issue forms for bugs and features, a pull request template, and `.github/dependabot.yml` for the `uv` and `github-actions` ecosystems.
- `.github/release.yml` groups generated release notes into Security, Fixes and Other, and drops Dependabot's own pull requests.
- `.pre-commit-config.yaml` with ruff, `uv lock` and the standard whitespace and YAML hooks. Optional: `uvx pre-commit install`.

### CI

- New jobs in `ci.yml`: coverage with a Codecov upload that cannot fail the build, a smoke test that installs the built wheel into a fresh venv and runs its entry point against a temporary `$HOME`, a `nix build` plus `nix flake check`, and a lint job.
- The lint job runs `ruff check`, `ruff format --check` and `zizmor` over the workflow files. Both tools come from the locked dev group, so a new release cannot turn a green commit red without a lockfile change. Ruff is configured in `pyproject.toml`: line length 88, target py311, rules `E F I UP B SIM RUF`.
- pytest now runs with `filterwarnings = ["error"]`, `--strict-markers`, `--strict-config` and `xfail_strict`, so a warning is a failure.
- Both workflows sync with `uv sync --locked` instead of `--frozen`, which turns a `uv.lock` that has drifted from `pyproject.toml` into a CI failure rather than a silent skip.
- `actions/checkout` to v7, `astral-sh/setup-uv` to v10.1.0, and the nix job to `DeterminateSystems/determinate-nix-action@v3`.
- The liveness tests resolve the fallback `PATH` for their stub CLIs instead of hardcoding `/usr/bin:/bin`, which does not exist inside a nix build sandbox on Linux.

## 0.1.4

Tests and the release workflow; the package itself is unchanged from 0.1.3.

- `write_overlay` in the CLI tests set the overlay file's mode but left its directory to the umask. On a machine with umask 002 that directory came out group-writable, the loader correctly refused the overlay, and the test failed. The suite now passes under umask 002, 022 and 077. Worth a release because the sdist ships `tests/`, so the defect was in the published artifact.
- The PyPI publish job in `release.yml` is skipped unless the repository variable `PUBLISH_TO_PYPI` is `true`, so a release is not red for a step nobody has configured yet.

## 0.1.3

The rest of the 2026-09-09 review, plus the packaging to ship it.

### Redaction

- A strong hint in a field name now beats the `_id` / `_url` / `_uri` exemption, so `session_id`, `secret_url` and `password_uri` are masked while `key_id`, `client_id` and `callback_url` stay visible (5).
- Field names are judged on the leaf first, with camelCase split, and only fall back to the parent path. `Credentials.AccessKeyId` and `Credentials.Expiration` show; `credentials.session_id` does not (5e).
- The fingerprint tail appears only from 16 characters up, rather than 9, so a human-chosen password no longer leaks a third of itself (5d).
- AWS `credential_process`, `web_identity_token_file` and `role_session_name` are identifiers, not secrets (24).

### Correctness

- An unreadable INI file reports an error instead of looking empty (6). The same treatment now covers a directory of INI files (30).
- The SQLite read-only URI percent-quotes its path. A `?` in a relocated `CLOUDSDK_CONFIG` used to strand `mode=ro` in the URI fragment, fall back to read-write-create, and leave a stray database behind, which was a write from a tool that promises never to write (7, 25).
- `display()` no longer turns `/Users/kaichen/x` into `~chen/x` for a user named `kai` (8).
- `KUBECONFIG` entries get `$VAR` expansion, not only `~` (11).
- A profile holding one secret in two fields no longer reports itself as shared with itself (9).

### Liveness (`--check`)

- Store-level probes match identities parsed out of JSON, or whole words, instead of bare substrings. A context named `dev` is no longer marked live by the word `devops` (12).
- One identity appearing in two files is probed once and the verdict is applied to every copy (13).
- `check()` reads every result under an overall deadline; a straggler or an exception becomes `unknown` with a reason instead of vanishing (20).
- Output is capped at 64 KiB and the process group is killed on timeout (26).
- `extract` works for store-level probes, which makes Azure's configuration live (22).
- A profile name starting with `-` is skipped rather than passed to a CLI as an option (27).

### Interface

- `credmap aws` routes to `where` instead of failing with an argparse error (21).
- `paths --found --json` honours `--found` (16).
- An empty query matches nothing instead of everything (19).
- `doctor` shows bloat in MB below a gigabyte and shell-quotes the paths in its `rm -rf` and `chmod` suggestions (17, 28).
- A store whose file failed to parse no longer also reports "no profiles were parsed" (18).

### Registry overlay

- A non-UTF-8 `registry.toml` is ignored rather than crashing every command (14).
- `paths = []` removes a store; presence of the key decides, not truthiness. A bare string where an array is expected wraps into one element instead of one alias per character (15).
- A `registry.toml`, or its parent directory, writable by group or others is refused with a warning on stderr (23, 31).

### Packaging

- MIT `LICENSE`.
- `flake.nix` and `flake.lock`: `nix build` produces the package and runs the suite; `nix run github:c-wenlong/credmap` works.
- The PyPI distribution is `credmap-cli`; the import package and command remain `credmap`. `credmap` on PyPI is an unrelated 2022 upload.
- `ci.yml` runs the suite on Linux and macOS against Python 3.11 and 3.13. `release.yml` builds on a tag, publishes a GitHub release with the artifacts, and uploads to PyPI through Trusted Publishing.

### Design honesty

- `doctor` no longer decides a note's severity by searching it for a phrase. The parser sets `note_level`, and a test runs three wordings of one note through `doctor` demanding the same result. This was the last place where the code contradicted a stated invariant (32).
- A directory of profile files reports what it could not open, as an error when nothing parsed and a warning when only some did (30).
- The overlay permission check covers the parent directory as well as the file, because write permission on a directory is permission to replace what is in it (31).

### Tests

74 to 230. New files for liveness, resolve and doctor, which had none. Fixture
sentinels no longer match real secret-scanner patterns (29), and the list of
environment overrides cleared by `fake_home` is derived from the registry so it
cannot drift again.

## 0.1.2

Superseded by 0.1.3 within the hour: its release workflow referenced a version
of `astral-sh/setup-uv` that does not exist, so nothing was published.

## 0.1.1

The secret-leak channels found by the review, all of which reached default
output with no flag:

- Parser errors quoted the file they choked on. `configparser` embeds the offending line, PyYAML marks carry a source snippet, and `netrc` reprs the token it could not place, which is the password when the file breaks one line above it. Errors now report format, line number and exception class only (3).
- An indented continuation line in an INI file folded the secret into the previous, visible field. Any value containing a newline is now masked regardless of its field name (1).
- A credential file holding one bare string (Pulumi, Fly) printed in full (4, 5a).
- Provider CLI output was copied verbatim into profile details (5b).
- `passphrase`, `jwt`, `cookie`, `dsn`, `mnemonic`, `seed` and `sas` were not in the hint list (5c).
- Both `doctor` renderers were missing from the whole-program leak test, which is why a green suite hid all of the above (2).

## 0.1.0

Initial version: 26 built-in stores, ten formats, redaction, `doctor`,
`--check`, and the `registry.toml` overlay.
