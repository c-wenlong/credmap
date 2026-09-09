# credmap — agent notes

Read-only CLI that indexes credential stores scattered across a machine.
Python 3.11+, one runtime dependency (PyYAML), managed with `uv`.

```bash
uv sync                      # after a fresh clone or a move (the venv is not portable)
uv run pytest -q             # 230 tests, ~5s (the liveness stubs use real timeouts)
uv run python -m credmap     # run without installing
uv tool install . --force    # put `credmap` on PATH
nix build                    # the package nix consumers get; runs the suite in the sandbox
```

The PyPI distribution is `credmap-cli`; the import package and the command
are both `credmap`. Full reference lives in [docs/](docs/README.md), and
[docs/known-issues.md](docs/known-issues.md) is the ledger of what the
2026-09-09 review found and which release closed it.

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

The rule reads the *leaf* of a dotted name first, with camelCase split so
`Credentials.AccessKeyId` is judged as `access_key_id`. A strong hint (secret,
token, pass, private, session, bearer, jwt, cookie, mnemonic, seed) beats the
`_id` / `_url` / `_uri` exemption, so `session_id` and `secret_url` mask while
`key_id` and `callback_url` show. Only when the leaf decides nothing does the
parent path get consulted. Changing the order of those checks is how a
credential becomes visible, so re-read `is_secret`'s docstring before touching it.

**Anything printed that has no field name is masked by shape.** `scrub` judges a
value by the name of the field holding it, which covers profile fields and
nothing else. Probe output has no such name, so `redact.scrub_text` fingerprints
every run of 20+ token-alphabet characters and caps the line. Parser errors solve
the same problem by construction: they never quote the file. A new channel that
carries external text to the user needs one of those two treatments.

**A multi-line value is masked whatever it is called**, `id_fields` included.
`configparser` folds an indented line into the previous key's value, so a leading
space in front of `aws_secret_access_key` would otherwise park the secret inside
the visible `aws_access_key_id`. Nothing legitimate in these formats spans lines.

**Identifiers stay visible.** An AWS access key ID, a client ID, an account
number and a project are how you find a credential upstream; masking them makes
the output useless without making anything safer. That's what `id_fields` is for.

**Parsers never raise.** `parsers.parse` wraps every parser in a catch-all and
turns failure into `ParseResult(error=...)`. A malformed credential file must
appear in the scan with an explanation, not abort the run — a broken file is
exactly when you most need the tool to work.

**A parser error never quotes the file.** Build it with `_safe_error`, which
reports the format, the line numbers the exception carries *structurally*, and
the exception class. Never interpolate `str(exc)`: `configparser` embeds the
offending line, PyYAML marks carry a source snippet and a caret, and
`netrc.NetrcParseError` reprs the token it could not place, which is the password
when the file is broken one line above it. That leak shipped once.

**Silence is not an answer.** `ConfigParser.read()` swallows `OSError`, so an
unreadable credentials file used to render exactly like an empty one. Open the
file yourself and hand the handle to `read_file`. Any parser that can fail to
*read* must say so; "no profiles" is a claim about the contents, not about
whether you got to see them.

**`note` and `error` are separate channels.** A note is context about a store
that is fine ("secrets are in the Keychain", "current context: alpha"); an error
means the file could not be read or understood. Severity is decided by which
field is set, never by pattern-matching the prose. `doctor` used to grep notes
for substrings like `"unparsable"`, so any parser that reworded its message
silently downgraded a broken file to informational. Return `_ok(...)` or
`_fail(...)`, not a hand-built tuple.

A note that the reader should act on rather than merely know about says so with
`_ok(..., note_level="warn")`. That covers a half-finished SSO login and a
config directory where some profiles would not open: the file was understood, so
it is not an error, but it is not trivia either. The level is a field for the
same reason the split exists at all, and `test_doctor.py` pins it by running
three different wordings of one note through `doctor` and demanding the same
severity from each.

**`scan` is offline and instant.** No network calls, ever, without `--check`.
Roughly 0.1s of user time today. Anything that shells out belongs in
`liveness.py` behind that flag.

**A probe is hostile input.** It is someone else's binary, found on `$PATH`,
printing whatever it likes. So: no shell, one argv element per profile name, a
name starting with `-` is skipped rather than handed over as an option, only the
first 64 KiB of output is kept, the process *group* is killed on timeout so a
grandchild holding the pipe cannot hang the scan, and `check()` has an overall
deadline on top of each probe's own. Every one of those exists because removing
it breaks something specific.

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

The user overlay in `registry.toml` can express all of the above, plus `probe`
and `bloat`. An entry whose id matches a built-in **inherits every field it does
not mention**, so `[aws] name = "Work AWS"` keeps the probe and the curated field
lists. Setting a key to an empty value is how you remove an inherited one
(`probe = {}`); `paths = []` drops the store from the registry entirely, which is
how a user hides a built-in. Presence of the key decides, not its truthiness, so
keep using `key in raw` rather than testing the parsed value. Keep
`_store_from_toml` in step when you add a field to `Store` — a field the overlay
cannot express is a field users cannot fix for themselves.

The overlay is also a privilege boundary: it can point credmap at any readable
file and can name any command for `--check`. A `registry.toml` (or its parent
directory) writable by group or others is refused, with `OVERLAY_WARNING` printed
once to stderr.

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
  database out from under a running gcloud. **Percent-quote the path** when you
  build that URI: an f-string put a `?` in a relocated `CLOUDSDK_CONFIG` straight
  into the query string, which stranded `mode=ro`, fell back to
  read-write-create, and left a stray database behind. A write, from the tool
  whose first invariant is that it never writes.
- **Absence of mention is not proof of death.** Store-level probes mark matched
  profiles live and leave the rest alone. A valid kube context simply isn't the
  current one. Match on a whole word or, better, on identities parsed out of the
  probe's JSON; a bare substring test marks a context named `dev` live from the
  word `devops`.
- **One identity can appear in two files.** AWS `default` lives in both
  `credentials` and `config`. Probe it once and apply the verdict to every
  `Profile` object with that name, or one row shows a live mark and its twin
  does not.

## Tests

Fixtures are generated in `tests/conftest.py`, not committed — nothing in this
repo should look like a credential file to a human or a secret scanner. The
`fake_home` fixture builds a synthetic home covering every format, points `HOME`
at it, and clears every override env var so a developer's real environment can't
leak into a test.

`tests/test_redact.py` is the file to be most careful with. It is the only thing
standing between a refactor and a secret in someone's terminal transcript. Its
`_all_output()` list must name every renderer, `doctor`'s included, and the
fixture home deliberately contains malformed, unreadable, bare-scalar and
indented-continuation files so that the leak test exercises the error channel and
not just the happy path. Every sentinel it knows about lives in `ALL_SECRETS`.

Sentinels must not look like real credentials to a *scanner*, either: the
Hugging Face and GitHub fixtures use `hfx_` and `ghox_` prefixes because the
real ones fullmatch gitleaks patterns that have no checksum step.
