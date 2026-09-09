# Architecture

credmap is about 2,300 lines of Python in eleven modules with one runtime
dependency, PyYAML. The design has one load-bearing seam: **the registry is
data, the parsers are behaviour.** Adding a provider is a `Store(...)` literal
and nothing else. If provider-specific code appears in `scan.py` or
`render.py`, the missing piece is a field on `PathSpec`, not a special case.

## Modules

| Module | Responsibility |
|---|---|
| `registry.py` | The data: one `Store` per provider, plus the `registry.toml` overlay loader and `find()` |
| `model.py` | Dataclasses for the registry schema (`Store`, `PathSpec`, `Probe`, `Bloat`) and the result schema (`StoreResult`, `FoundPath`, `Profile`, `ParseResult`) |
| `resolve.py` | Env override, then XDG, then template. The only place path rules live |
| `parsers.py` | One function per format, all wrapped so they never raise |
| `redact.py` | The masking chokepoint |
| `scan.py` | Walks the registry, stats each path, dispatches to parsers, computes directory sizes |
| `liveness.py` | `--check` probes: subprocess without a shell, hard timeouts, a thread pool |
| `doctor.py` | Anomaly checks over a completed scan |
| `render.py` | Grouped scan output, tables, JSON |
| `cli.py` | argparse; rewrites a missing verb to `scan` |

## Data flow

1. `registry.load()` returns the built-in stores merged with the user overlay.
2. For each store, `scan` resolves every `PathSpec` to one or more concrete paths, stats them, and calls `parsers.parse` on those that exist. The result is a `StoreResult` holding a `FoundPath` per path, each with its own list of `Profile`s.
3. With `--check`, `liveness.check` mutates profile statuses in place on the per-path profiles.
4. Renderers read `StoreResult.profiles`, which merges profiles by name across paths and returns copies. The per-path lists are the originals and are what liveness writes to; the two views must not be collapsed.
5. Every field value a renderer prints goes through `redact.scrub` first.
6. `doctor.diagnose` runs its checks over the scan results and returns findings; the CLI maps an `error`-level finding to exit code 1.

## Invariants

These are the properties a plausible-looking change will silently break.

- **Never write to a credential file.** The tool stats, reads and parses. It has no write path and should not grow one. `doctor` prints the provider command that fixes a problem and stops there.
- **All secret output goes through `redact.scrub`.** The leak test in `tests/test_redact.py` runs every renderer over a fixture home and asserts that no sentinel value appears. A new render path that formats fields itself will pass its own unit tests and fail that one. Add the path to `_all_output()` when you add a renderer.
- **Redaction is default-deny.** A field whose name looks secret is masked whether or not the registry declared it. When a field is wrongly masked, add it to `id_fields`; never loosen the hint list.
- **Identifiers stay visible.** Access key IDs, client IDs, account numbers and projects are how you find a credential upstream.
- **Parsers never raise.** Failure becomes `ParseResult(error=...)`. A broken file is exactly when you most need the tool to work.
- **`note` and `error` are separate channels.** Severity is decided by which field is set. Return `_ok(...)` or `_fail(...)`, not a hand-built tuple.
- **`scan` is offline and instant.** Anything that shells out belongs in `liveness.py` behind `--check`.

## Traps

- A store's knowledge of one identity can span files: gcloud names an account in `credentials.db` and records its expiry in `access_tokens.db`. The merge happens in `StoreResult.profiles`.
- Paths move. `AWS_SHARED_CREDENTIALS_FILE`, `CLOUDSDK_CONFIG`, `KUBECONFIG` (a list), `DOCKER_CONFIG`, `GOOGLE_APPLICATION_CREDENTIALS`, `XDG_CONFIG_HOME` all relocate a store. Resolution belongs in `resolve.py`.
- Empty is not absent. `~/.docker/config.json` with `credsStore: desktop` has no `auths` because the secrets are in the OS keychain.
- Format is not implied by extension. gcloud's credentials are SQLite; the JSON file beside them is ADC, a different credential with a different lifecycle. SQLite is opened read-only via URI so a scan can never lock the database out from under a running gcloud.
- Absence of mention is not proof of death. Store-level probes mark matched profiles live and leave the rest alone.

## Adding a provider

Add a `Store` to `registry.py` and a test asserting its profiles parse. Four
fields carry the non-obvious semantics: `marker`, `role`, `identities` and
`select`. All four are explained in [stores.md](stores.md) and
[registry-toml.md](registry-toml.md). When you add a field to `Store`, add it
to `_store_from_toml` too; a field the overlay cannot express is a field users
cannot fix for themselves.
