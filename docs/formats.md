# File formats

Every path in the registry declares a `fmt`. The parser for that format turns
the file into a list of profiles, each with a name, a flat `fields` mapping,
and optionally an expiry. Parsers live in `src/credmap/parsers.py`.

Two rules hold for every parser:

- **Parsers never raise.** `parse()` wraps each parser in a catch-all and turns any exception into `ParseResult(error=...)`. A malformed credential file shows up in the scan with an explanation rather than aborting the run.
- **Error messages never quote the file.** A parse failure reports the format, the line number the library reported structurally, and the exception class. Library exception text is never interpolated, because configparser, PyYAML and netrc all embed the offending source in theirs.
- **`note` and `error` are separate channels.** A note is context about a healthy store ("secrets are in the Keychain"). An error means the file could not be read or understood. `doctor` decides severity by which field is set, never by reading the prose. A note can additionally be levelled `warn` by the parser when it describes something worth acting on, such as a half-finished SSO login.

| fmt | Expects | How profiles are derived | Notes and errors it can emit |
|---|---|---|---|
| `ini` | An INI file (AWS, pypirc) | One profile per section. `[profile X]` becomes `X`; `[sso-session X]` and `[services X]` become `X` with `detail` set so `--check` skips them. | error `unparsable INI, line N (ExceptionName)` |
| `inidir` | A directory of INI files, one per profile (gcloud `configurations/`) | One profile per file, with a leading `config_` stripped from the name. Fields are keyed `section.key`. | error when the directory cannot be listed, or when no file in it could be read; a `warn`-level note counting the failures when some parsed and others did not |
| `json` | A JSON document, read as UTF-8 with an optional BOM | Via `select`, see below. | note `secrets held in macOS Keychain, not in this file` when `credsStore` is `desktop`, or `secrets held in helper '<x>'` for another helper; error `unparsable JSON: ...` |
| `yaml` | A YAML document via `safe_load`; an empty file is `{}` | Via `select`. | note `current context: <name>` when `current-context` is set; error `unparsable YAML, line N (ExceptionName)` |
| `sqlite-gcloud` | gcloud's `credentials.db` and `access_tokens.db`, opened read-only via `file:<path>?mode=ro` | Rows of `credentials.account_id` become profiles. Rows of `access_tokens` merge in by account and set `expires_at` and `status`. Accounts without an `@` are opaque hashes and are counted, not listed. | note `N cached token(s) keyed by opaque id (M expired) — stale cache, not accounts`; error `unreadable SQLite: ...` or `query failed: ...` |
| `netrc` | A netrc file via the stdlib module | One profile per `machine`, fields `login`, `account`, `password`. | error `unparsable netrc, line N (ExceptionName)` |
| `jsondir` | A directory of `*.json` (AWS SSO and CLI caches) | One profile per readable object. `detail` is `access token` when `accessToken` or `Credentials` is present, else `client registration`. Named by `startUrl` or the first 8 characters of the file name. Expiry from `expiresAt` or `registrationExpiresAt`. | note `client registrations only, no access token — SSO login never completed` |
| `keydir` | A directory containing `*.pub` (`~/.ssh`) | One profile per public key, named after the private half, with `type`, `comment` and `private_key_present`. Private keys are never opened. | error when the directory cannot be listed |
| `raw` | A file whose whole content is one token | One profile named after the file, with a single `token` field. | error `file is empty` |
| `opaque` | A known store that is deliberately not opened (npmrc, cargo, stripe, wrangler, gnupg) | None. Presence is reported, contents are not read. | note `present (contents not parsed)` |

## `select`: where profile names live

A path spec's `select` tells the `json` and `yaml` parsers how to find
profiles inside a parsed document.

| `select` | Meaning | Example |
|---|---|---|
| unset | The whole file is one profile. Its name is the first of `account`, `client_email`, `user`, `type` found in the document, else the file name. | gcloud ADC, pulumi |
| `"."` | Each key of the root mapping is a profile. | `gh/hosts.yml`, one profile per host |
| `"a.b"` | Descend key by key. If the node is a list, each item is a profile named by its `name` or `id`. If it is a mapping, its keys are profiles. | kube `contexts`, docker `auths`, azure `subscriptions` |

Fields are flattened one level, so a nested mapping becomes `parent.child`
keys. A document that is a single scalar rather than a mapping becomes one
`token` field, so a file that is nothing but a credential is masked by
construction.

## Expiry

`expires_at` is parsed from ISO 8601 (a trailing `Z` is accepted) and from
`YYYY-MM-DD HH:MM:SS[.ffffff]`. Naive timestamps are assumed UTC. A profile
with a parseable expiry gets `status` `expired` or `valid` offline, without
any network call.
