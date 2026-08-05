# credmap — agent notes

Read-only CLI that indexes credential stores scattered across a machine.
Python 3.11+, one runtime dependency (PyYAML), managed with `uv`.

```bash
uv sync                      # after a fresh clone or a move (the venv is not portable)
uv run pytest -q             # 65 tests, ~0.3s
uv run python -m credmap     # run without installing
uv tool install . --force    # put `credmap` on PATH
```

## Invariants

These are the things that will be silently broken by a plausible-looking change.
Everything else is negotiable.

**Never write to a credential file.** The tool stats, reads and parses. It has no
write path and should not grow one — `doctor` prints the provider command that
fixes a problem and stops there. Adding mutation means re-reasoning about backups,
locking against a running CLI, and blast radius, none of which exist today.

**All secret output goes through `redact.scrub`.** Not "most". The leak test in
`tests/test_redact.py` asserts the whole-program property by running every
renderer over a fixture home and checking that no sentinel value appears. A new
render path that formats fields itself will pass its own unit tests and fail
that one. Add the path to `_all_output()` when you add a renderer.

**Redaction is default-deny.** `redact.is_secret` masks anything whose *name*
looks secret, whether or not a registry entry declared it, so a store a user adds
in their own `registry.toml` is safe before anyone curates its field list. When a
field is wrongly masked the fix is to add it to that store's `id_fields` — never
to loosen `_HINTS`.

**Identifiers stay visible.** An AWS access key ID, a client ID, an account
number and a project are how you find a credential upstream; masking them makes
the output useless without making anything safer. That's what `id_fields` is for.

**Parsers never raise.** `parsers.parse` wraps every parser in a catch-all and
turns failure into `(., note)`. A malformed credential file must appear in the
scan with an explanation, not abort the run — a broken file is exactly when you
most need the tool to work.

**`scan` is offline and instant.** No network calls, ever, without `--check`.
Roughly 0.1s of user time today. Anything that shells out belongs in
`liveness.py` behind that flag.

## Where things go

```
src/credmap/
  registry.py   THE DATA — one Store per provider. Edit this to add a provider.
  model.py      dataclasses for the registry schema and the result schema
  resolve.py    env override -> XDG -> template. The only place path rules live.
  parsers.py    ini | inidir | json | yaml | sqlite-gcloud | netrc | jsondir | keydir | raw | opaque
  redact.py     the masking chokepoint
  scan.py       walks the registry, stats, dispatches to parsers
  liveness.py   --check probes: subprocess, hard timeouts, thread pool
  doctor.py     anomaly checks over a completed scan
  render.py     grouped scan output, tables, JSON
  cli.py        argparse; `scan` is the default verb
```

The load-bearing seam is **registry as data, parsers as behaviour**. Adding a
provider should be a `Store(...)` literal and nothing else. If you find yourself
writing provider-specific code in `scan.py` or `render.py`, the missing piece is
a field on `PathSpec`, not a special case.

## Adding a provider

Add a `Store` to `registry.py` and a test asserting its profiles parse. Four
fields carry the non-obvious semantics:

- `marker=True` — the path whose existence *proves* the store is real. Directory
  presence is not proof: `~/.azure` gets created by VS Code extensions that never
  write a credential, and `~/.supabase` holds only telemetry. Without a marker
  every such directory becomes a false positive.
- `role` — `secrets` | `config` | `token-cache` | `keys`. Drives the permission
  audit and duplicate detection (token caches legitimately repeat the client
  secret that minted them, so they're excluded from the duplicate check).
- `identities` — are the profiles here credential identities worth probing, or
  just named config blocks? Defaults to true for `secrets`. AWS `config` opts in
  because SSO profiles live there; gcloud's `configurations/` stays out because
  those are config names, not accounts. Get this wrong and `--check` runs
  `aws sts get-caller-identity --profile <sso-cache-hash>`.
- `select` — where profile names live in a parsed document. `None` = whole file
  is one profile; `"."` = root mapping's keys (gh `hosts.yml`); `"a.b"` = descend,
  then keys, or each item's `name` if it's a list (kube `contexts`).

## Traps

- **A store's knowledge of one identity can span files.** gcloud names an account
  in `credentials.db` and records its expiry in `access_tokens.db`.
  `StoreResult.profiles` merges by name and returns copies; the per-path
  `FoundPath.profiles` are the originals and are what `liveness` mutates. Don't
  collapse the two.
- **Paths move.** `AWS_SHARED_CREDENTIALS_FILE`, `CLOUDSDK_CONFIG`, `KUBECONFIG`
  (an `os.pathsep` *list*), `DOCKER_CONFIG`, `GOOGLE_APPLICATION_CREDENTIALS`,
  `XDG_CONFIG_HOME` all relocate a store. Resolution belongs in `resolve.py`,
  never inlined.
- **Empty is not absent.** `~/.docker/config.json` with `credsStore: desktop` has
  no `auths` because the secrets are in the OS keychain. Report the indirection.
- **Format is not implied by extension.** gcloud's credentials are SQLite; the
  JSON file beside them is ADC, a different credential with a different lifecycle.
  Open SQLite read-only via URI (`file:...?mode=ro`) so a scan can never lock the
  database out from under a running gcloud.
- **Absence of mention is not proof of death.** Store-level probes mark matched
  profiles live and leave the rest alone. A valid kube context simply isn't the
  current one.

## Tests

Fixtures are generated in `tests/conftest.py`, not committed — nothing in this
repo should look like a credential file to a human or a secret scanner. The
`fake_home` fixture builds a synthetic home covering every format, points `HOME`
at it, and clears every override env var so a developer's real environment can't
leak into a test.

`tests/test_redact.py` is the file to be most careful with. It is the only thing
standing between a refactor and a secret in someone's terminal transcript.
