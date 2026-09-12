# Known issues

Findings from the code review on 2026-09-09, against commit `11c16e0`. All
were verified by reading the code, and rows marked "reproduced" were
exercised against a synthetic home. Rows marked **fixed** were closed the
same day in v0.1.1 or v0.1.3, each with a test that fails if the fix is
reverted. Findings 30 to 32 were found while fixing the others.

Everything is closed except one row, which is a decision rather than an
omission.

## Open by decision, and the findings found late

| # | Where | Problem | Decision |
|---|---|---|---|
| 10 | `doctor.py`, `cli.py` | A parse failure is `warn`, and only `error` exits 1, so an unreadable credentials file exits 0. | Kept. `doctor` exits non-zero only on something provable, and an unparsable file is a warning to investigate, not proof the credential is dead. Documented in [doctor.md](doctor.md). |
| 30 | `parsers.py` `parse_inidir` | An unreadable file inside a config directory was skipped silently. | **fixed** in v0.1.3: an error when nothing parsed, a `warn` note counting the failures when some did |
| 31 | `registry.py` overlay loader | The permission check covered `registry.toml` but not its parent directory, and write permission on a directory is permission to replace what is in it. | **fixed** in v0.1.3: both are checked, and the warning says which one is at fault |
| 32 | `doctor.py` note severity | `doctor` decided a note's severity by searching it for `"never completed"`, contradicting the invariant that severity is structural. | **fixed** in v0.1.3: `note_level` is set by the parser, with a test over three phrasings of one note |

## Secret leaks

These contradicted the invariant that all secret output goes through
`redact.scrub`.

| # | Where | Problem | Status |
|---|---|---|---|
| 1 | `parsers.py` `parse_ini`, `redact.py` `_scrub_value` | `configparser` folds an indented line into the previous key's value. A credentials file with a leading space on the secret line makes `aws_access_key_id` hold `AKIA...\naws_secret_access_key = <secret>`. That key is in `id_fields`, so the whole multi-line value prints verbatim in `show` and `--json`, without `--reveal`. | **fixed** in v0.1.1 |
| 2 | `render.py` `render_findings`, `findings_to_dict` | The two `doctor` render paths never call `scrub` and are missing from `_all_output()` in `tests/test_redact.py`, so the leak test cannot catch anything they print. | **fixed** in v0.1.1 |
| 3 | `parsers.py` INI, YAML and netrc error paths | Parse-error strings embed raw file content: the offending INI line, the YAML source line with a caret, or the netrc token, which can be the password. `doctor` and `show` print them unmasked. | **fixed** in v0.1.1 |
| 4 | `parsers.py` `_flatten` | A JSON file whose top level is a bare string becomes a `value` field, which no hint matches, so it prints unmasked. | **fixed** in v0.1.1 |
| 5 | `redact.py` `_NEVER_SUFFIXES` | The suffix allow-list beats an explicit hint match, so `secret_url`, `password_uri`, `token_url` and `session_id` all print in clear. | **fixed** in v0.1.2: strong hints beat the suffix rule |
| 5a | `parsers.py` `_flatten` | Same root as issue 4, but live on shipped stores: `~/.pulumi/credentials.json` holding a bare `"pul-..."` string and `~/.fly/config.yml` holding a bare token both print in full. | **fixed** in v0.1.1 |
| 5b | `liveness.py`, `doctor.py`, `render.py` | Probe stdout and stderr are copied verbatim into `Profile.detail` and never scrubbed. A provider CLI that echoes the token in its failure text puts it into `doctor --check` and every `--json` payload. | **fixed** in v0.1.1 |
| 5c | `redact.py` `_HINTS` | Common secret names are not in the hint list: `passphrase`, `passcode`, `jwt`, `cookie`, `dsn`, `mnemonic`, `seed`, `sas`. | **fixed** in v0.1.1 |
| 5d | `redact.py` `mask` | The four-character tail shows from 9 characters up, so a 9-character human password reveals 44 percent of itself. | **fixed** in v0.1.2: tail from 16 characters |
| 5e | `redact.py` `is_secret` | Hints match the full dotted path but the allow-list matches only the leaf. Under a parent named `credentials`, `session_id` prints; under `Credentials` in the AWS CLI cache, `AccessKeyId` and `Expiration` are over-masked. | **fixed** in v0.1.2: leaf decides first, camelCase split, parent only as fallback |

One negative result, so nobody re-tests it: `json.JSONDecodeError` messages
are position-only. `netrc.NetrcParseError` turned out to repr the token it
could not place, which can be the password, so netrc was fixed too.

## Wrong answers

| # | Where | Problem | Status |
|---|---|---|---|
| 6 | `parsers.py` `parse_ini` | `ConfigParser.read()` swallows `OSError`, so a permission-denied `~/.aws/credentials` reports zero profiles and no error. | **fixed** in v0.1.2: `unreadable INI (PermissionError)` |
| 7 | `parsers.py` `parse_sqlite_gcloud` | The read-only URI is built by f-string. A `CLOUDSDK_CONFIG` path containing `?` or `#` is parsed as query or fragment. | **fixed** in v0.1.2: path is percent-quoted |
| 8 | `resolve.py` `display` | Home-prefix collapse uses a bare `startswith`. With `HOME=/Users/kai`, `/Users/kaichen/.aws/credentials` renders as `~chen/.aws/credentials`. | **fixed** in v0.1.2 |
| 9 | `doctor.py` `_duplicates` | One profile holding the same string in two secret fields reports itself as "shared by 2 profiles (x:only, x:only)". | **fixed** in v0.1.2 |
| 11 | `resolve.py` `multi` branch | `KUBECONFIG` elements get `~` expanded but not `$VAR`. | **fixed** in v0.1.2 |
| 12 | `liveness.py` `_probe_store` | Store-level liveness is a substring test of the profile name against stdout. A context named `dev` matches almost any output. | **fixed** in v0.1.2: JSON identity match, else whole-word match |
| 13 | `liveness.py` `probeable` | Profiles are deduplicated by name, so an AWS `default` in both `credentials` and `config` is probed once and only one row gets the live mark. | **fixed** in v0.1.2: verdict applied to every copy |

## Robustness and usability

| # | Where | Problem | Status |
|---|---|---|---|
| 14 | `registry.py` overlay loader | A non-UTF-8 `registry.toml` raises `UnicodeDecodeError`, which is not caught, and every command crashes. | **fixed** in v0.1.2 |
| 15 | `registry.py` `_store_from_toml` | `paths = []` in an overlay re-inherits the built-in paths instead of dropping them; a bare-string `aliases` becomes one alias per character. | **fixed** in v0.1.2: an empty `paths` removes the store; bare strings wrap |
| 16 | `cli.py` `cmd_paths` | `paths --found --json` ignores `--found`. | **fixed** in v0.1.2 |
| 17 | `doctor.py` `_bloat` | Size is always shown in GB, so a 60 MB directory reads `0.1 GB`. | **fixed** in v0.1.2 |
| 18 | `doctor.py` `_empty` | A store whose file failed to parse gets both the parse error and "no profiles were parsed". | **fixed** in v0.1.2 |
| 19 | `registry.py` `find` | An empty query matches every store. | **fixed** in v0.1.2 |
| 20 | `liveness.py` `check` | No overall deadline across probes, and exceptions inside a probe are never read from the future, so they vanish. | **fixed** in v0.1.2: deadline of longest timeout plus 5 s; exceptions become `unknown` |
| 21 | `cli.py` default verb | `credmap aws` becomes `scan aws` and dies with an argparse error. | **fixed** in v0.1.2: a bare store name becomes `where` |
| 22 | `liveness.py` `_probe_store` | Azure's `extract = "id"` is dead configuration: `extract` only applies to per-profile probes. | **fixed** in v0.1.2 |
| 23 | `registry.py` overlay loader | The overlay is read with no permission check. A group- or world-writable `registry.toml` hands another local user arbitrary file read and, under `--check`, argv execution. | **fixed** in v0.1.2: such a file is ignored with a warning on stderr. Directory check is issue 31 |
| 24 | `registry.py` AWS store | `credential_process`, `web_identity_token_file` and `role_session_name` are masked. | **fixed** in v0.1.2: added to `id_fields` |
| 25 | `parsers.py` `parse_sqlite_gcloud` | SQLite percent-decodes the URI path, so a `%41` segment opens `A` instead. Worse than first recorded: a `?` in the path stranded `mode=ro` in the fragment, fell back to read-write-create, and created a stray database. That was a write from a tool with no write path. | **fixed** in v0.1.2, with a test asserting no file appears |
| 26 | `liveness.py` `_run` | Probe output capture is unbounded. A chatty CLI drove memory to 800 MB inside the timeout. | **fixed** in v0.1.2: first 64 KiB kept, rest drained |
| 27 | `liveness.py` `_probe_profile` | A profile name starting with `-` reaches the provider CLI as an option-shaped token. | **fixed** in v0.1.2: skipped as `unknown` |
| 28 | `doctor.py` `_bloat` | The printed `rm -rf <path>/*` remedy is unquoted. | **fixed** in v0.1.2: `shlex.quote`, tilde kept outside the quotes |
| 29 | `tests/conftest.py` | Two sentinels fullmatch real scanner patterns: `hf_` plus 34 alphanumerics and `gho_` plus 36. | **fixed** in v0.1.2: prefixes are `hfx_` and `ghox_`. The `AKIAFAKEFAKEFAKEFAKE` sentinel still matches the gitleaks AWS regex, which has no checksum; trufflehog verifies against STS and drops it |

## Documentation drift

All closed. The README, AGENTS.md and this folder now agree with the code.

- The test count was stated as 65 in two places; the suite has 230.
- AGENTS.md claimed severity is never decided by pattern-matching note prose, while `doctor` searched notes for `"never completed"`. Notes now carry a `note_level` set by the parser, the substring list is deleted, and a test asserts that three different phrasings of the same note keep the same severity.
- AGENTS.md claimed `fake_home` clears every override variable; it omitted `AZURE_CONFIG_DIR` and `GNUPGHOME`. The list is now derived from the registry, so it covers all 12 and cannot fall behind a new store.
- "Assign an empty value to drop an inherited one" now holds for every field, `paths` included, where it removes the store.
- The README described `--all`, `--check` and `--reveal` as though they were global, and did not mention `paths --found`.

## Test coverage

Before the fixes `liveness.py` had 13 percent line coverage and no direct
tests, and no test read a file it could not open. `tests/test_liveness.py`,
`tests/test_resolve.py` and `tests/test_doctor.py` now exist, and the
malformed-file, indented-continuation, bare-scalar and permission-denied
fixtures are in place.
