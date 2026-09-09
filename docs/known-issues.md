# Known issues

Findings from the code review on 2026-09-09, against commit `11c16e0`. All
were verified by reading the code, and rows marked "reproduced" were
exercised against a synthetic home. Rows marked **fixed** were closed in
v0.1.1 the same day, each with a fixture in `tests/conftest.py`; the rest are
open.

## Secret leaks

These contradicted the invariant that all secret output goes through
`redact.scrub`. Issues 1 to 4 and 5a to 5c were fixed in v0.1.1; 5, 5d and 5e
remain open.

| # | Where | Problem | Status |
|---|---|---|---|
| 1 | `parsers.py` `parse_ini`, `redact.py` `_scrub_value` | `configparser` folds an indented line into the previous key's value. A credentials file with a leading space on the secret line makes `aws_access_key_id` hold `AKIA...\naws_secret_access_key = <secret>`. That key is in `id_fields`, so the whole multi-line value prints verbatim in `show` and `--json`, without `--reveal`. | **fixed** in v0.1.1 |
| 2 | `render.py` `render_findings`, `findings_to_dict` | The two `doctor` render paths never call `scrub` and are missing from `_all_output()` in `tests/test_redact.py`, so the leak test cannot catch anything they print. | **fixed** in v0.1.1 |
| 3 | `parsers.py` INI, YAML and netrc error paths | Parse-error strings embed raw file content: the offending INI line, the YAML source line with a caret, or the netrc token, which can be the password. `doctor` and `show` print them unmasked. | **fixed** in v0.1.1 |
| 4 | `parsers.py` `_flatten` | A JSON file whose top level is a bare string becomes a `value` field, which no hint matches, so it prints unmasked. No shipped store hits this today. | **fixed** in v0.1.1 |
| 5 | `redact.py` `_NEVER_SUFFIXES` | The suffix allow-list beats an explicit hint match, so `secret_url`, `password_uri`, `token_url` and `session_id` all print in clear. A session ID is a bearer credential, and callback or SAS URLs carry tokens in the query string. | reproduced |
| 5a | `parsers.py` `_flatten` | Same root as issue 4, but live on shipped stores: `~/.pulumi/credentials.json` holding a bare `"pul-..."` string and `~/.fly/config.yml` holding a bare token both print in full in the table and in `--json`. | **fixed** in v0.1.1 |
| 5b | `liveness.py`, `doctor.py`, `render.py` | Probe stdout and stderr are copied verbatim into `Profile.detail` and never scrubbed. A provider CLI that echoes the token in its failure text puts it into `doctor --check` and every `--json` payload. The overlay's `extract` key pulls an arbitrary stdout value into the same field. | **fixed** in v0.1.1 |
| 5c | `redact.py` `_HINTS` | Common secret names are not in the hint list: `passphrase`, `passcode`, `pwd`, `pw`, `pat`, `jwt`, `cookie`, `dsn`, `connection_string`, `mnemonic`, `seed`, `sas`, `recovery_code`, `code_verifier`. `passphrase` is the sharp one because `password` and `passwd` are both present. | **fixed** in v0.1.1 |
| 5d | `redact.py` `mask` | The four-character tail shows from 9 characters up, so a 9-character human password reveals 44 percent of itself. The floor is calibrated for machine tokens. | verified |
| 5e | `redact.py` `is_secret` | Hints match the full dotted path but the allow-list matches only the leaf. Under a parent named `credentials`, children named `account`, `user`, `session_id` or `callback_url` print in clear; under `Credentials` in the AWS CLI cache, `AccessKeyId` and `Expiration` are over-masked. | reproduced |

Suggested fixes for what remains: apply the suffix allow-list only when no
hint matched; raise the tail floor to 16 characters; judge hints and
allow-list on the same scope.

What v0.1.1 did: strip file content from parser error messages and
report only format, line number and exception type; mask any string
containing a newline regardless of key; treat a whole-file scalar as secret by
construction; scrub and cap `Profile.detail`; apply the suffix allow-list only
when no hint matched; add `pass`, `phrase`, `jwt`, `cookie`, `dsn`,
`mnemonic`, `seed`, `sas` to the hints; add both `doctor` renderers to
`_all_output()`; add one malformed file per format to `fake_home` with a
sentinel secret on the broken line so the existing leak test covers all of it.

One negative result, so nobody re-tests it: `json.JSONDecodeError` messages
are position-only. `netrc.NetrcParseError` turned out to repr the token it
could not place, which can be the password, so netrc was fixed too.

## Wrong answers

| # | Where | Problem | Status |
|---|---|---|---|
| 6 | `parsers.py` `parse_ini` | `ConfigParser.read()` swallows `OSError`, so a permission-denied `~/.aws/credentials` reports zero profiles and no error. Indistinguishable from an empty file. | reproduced |
| 7 | `parsers.py` `parse_sqlite_gcloud` | The read-only URI is built by f-string. A `CLOUDSDK_CONFIG` path containing `?` or `#` is parsed as query or fragment and silently yields no accounts. | reproduced |
| 8 | `resolve.py` `display` | Home-prefix collapse uses a bare `startswith`. With `HOME=/Users/kai`, `/Users/kaichen/.aws/credentials` renders as `~chen/.aws/credentials`, including in doctor's `chmod` fix line. | reproduced |
| 9 | `doctor.py` `_duplicates` | One profile holding the same string in two secret fields reports itself as "shared by 2 profiles (x:only, x:only)". | reproduced |
| 10 | `doctor.py`, `cli.py` | A parse failure is `warn`, and only `error` exits 1, so an unreadable credentials file exits 0. | reproduced |
| 11 | `resolve.py` `multi` branch | `KUBECONFIG` elements get `~` expanded but not `$VAR`, so `$HOME/b.yml` stays literal and is not found. | reproduced |
| 12 | `liveness.py` `_probe_store` | Store-level liveness is a substring test of the profile name against stdout. A context named `dev` matches almost any output. | verified |
| 13 | `liveness.py` `probeable` | Profiles are deduplicated by name, so an AWS `default` in both `credentials` and `config` is probed once and only one row gets the live mark. | verified |

## Robustness and usability

| # | Where | Problem | Status |
|---|---|---|---|
| 14 | `registry.py` overlay loader | A non-UTF-8 `registry.toml` raises `UnicodeDecodeError`, which is not caught, and every command crashes. | verified |
| 15 | `registry.py` `_store_from_toml` | `paths = []` in an overlay re-inherits the built-in paths instead of dropping them. | verified |
| 16 | `cli.py` `cmd_paths` | `paths --found --json` ignores `--found`. | reproduced |
| 17 | `doctor.py` `_bloat` | Size is always shown in GB, so a 60 MB directory reads `0.1 GB`. | verified |
| 18 | `doctor.py` `_empty` | A store whose file failed to parse gets both the parse error and "no profiles were parsed". | reproduced |
| 19 | `registry.py` `find` | An empty query matches every store. | reproduced |
| 20 | `liveness.py` `check` | No overall deadline across probes, and exceptions inside a probe are never read from the future, so they vanish. | verified |
| 21 | `cli.py` default verb | `credmap aws` becomes `scan aws` and dies with an argparse error rather than falling through to `where`. | reproduced |
| 22 | `liveness.py` `_probe_store` | Azure's `extract = "id"` is dead configuration: `extract` only applies to per-profile probes. | verified |
| 23 | `registry.py` overlay loader | The overlay is read with no ownership or permission check. A group-writable `~/.config/credmap` hands another local user arbitrary file read into stdout and, under `--check`, argv execution as the owner. | reproduced |
| 24 | `registry.py` AWS store | `credential_process`, `web_identity_token_file` and `role_session_name` are masked. A session name and a file path are identifiers. | verified |
| 25 | `parsers.py` `parse_sqlite_gcloud` | SQLite percent-decodes the URI path, so a segment containing `%` opens a different file. `mode=ro` itself holds; a `?` fails closed. | reproduced |
| 26 | `liveness.py` `_run` | Probe output capture is unbounded. A chatty CLI drove memory to 800 MB inside the timeout. The timeout itself held even with a grandchild holding the pipe. | reproduced |
| 27 | `liveness.py` `_probe_profile` | A profile name starting with `-` reaches the provider CLI as an option-shaped token. No shell injection: semicolons, backticks and `$()` are inert, verified against a stub CLI. | verified |
| 28 | `doctor.py` `_bloat` | The printed `rm -rf <path>/*` remedy is unquoted. A bloat path with a space, which an overlay can hold, turns a paste into deleting the wrong directory. | verified |
| 29 | `tests/conftest.py` | Two sentinels fullmatch real scanner patterns: `hf_` plus 34 alphanumerics and `gho_` plus 36. gitleaks and trufflehog will flag the file. | verified |

## Documentation drift

Fixed in this docs folder; the README and AGENTS.md still say otherwise.

- Both say 65 tests; the suite has 74.
- The README lists `--all`, `--check` and `--reveal` as if global. Only `--json` is on every verb.
- `paths --found` is undocumented.
- "Assign an empty value to drop an inherited one" does not hold for `paths`.
- AGENTS.md says doctor never pattern-matches note prose, but `_WARN_NOTE_MARKERS = ("never completed",)` still does.
- AGENTS.md says `fake_home` clears every override variable; it omits `AZURE_CONFIG_DIR` and `GNUPGHOME`.
- The `←$VAR` annotation appears on `paths` and `where` too, not only `scan`.

## Test coverage gaps

| Module | Line coverage |
|---|---|
| `model.py`, `redact.py` | 100% |
| `resolve.py` | 97% |
| `render.py` | 95% |
| `registry.py` | 93% |
| `doctor.py` | 91% |
| `cli.py` | 87% |
| `parsers.py` | 83% |
| `scan.py` | 64% |
| `liveness.py` | 13% |

Coverage figures are from before v0.1.1. `liveness.py` still has no direct
tests, and no test reads a file it cannot open, which is why issue 6 is
still open. The malformed-file and indented-continuation fixtures now exist.
