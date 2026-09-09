# Security posture

credmap reads the most sensitive files on a machine and prints about them.
This page states what it does and does not do, so you can decide whether to
run it, and what to do before you paste its output anywhere.

## What holds

These properties were checked by reading the code and by exercising it
against synthetic homes in the 2026-09-09 review.

- **No write path.** The package contains no bare `open()`, no `write_text`, no `unlink`, `rename`, `shutil` or `mkdir`. Output goes through `sys.stdout.write` and nothing else. The single SQLite connection is opened read-only via URI; an insert through it fails with "attempt to write a readonly database", and opening it creates no journal or WAL sidecar, so a scan cannot lock gcloud's database.
- **Offline by default.** `subprocess` is imported only in `liveness.py`. No module imports `socket`, `urllib` or an HTTP client. Nothing runs unless `--check` is given.
- **Subprocess handling is correct.** Probes run without a shell. A profile name is one argv element, so `;`, backticks and `$()` in a name are inert. The hard timeout fires even when the child leaves a grandchild holding the output pipe open.
- **One redaction chokepoint.** Both the table renderer and the JSON serialiser call the same `scrub`, which recurses into nested mappings and lists. Every leak found in review comes from a channel that bypasses `fields`, not from a hole in `scrub`.
- **Default-deny masking works for every shipped store.** All 26 built-ins were walked with their real field names. Every genuine secret is masked today, including ones no `secret_fields` entry declares: the Azure MSAL cache, the Claude Code OAuth blob, Pulumi's access-token map, gh's nested `oauth_token`.
- **The riskiest plaintext files are never parsed.** `~/.git-credentials`, `~/.npmrc`, `~/.cargo/credentials.toml` and Stripe's config are `opaque`: presence is reported, contents are not read.
- **`--reveal` is contained.** It exists only on `show` and no other flag implies it.
- **The repository is clean.** Fixtures are generated at test time. `registry.toml`, `*.pem`, `*.key` and `.env` are gitignored.

## Fixed on 2026-09-09

The review found channels that reached output without passing through
`scrub`. These were closed the same day, each with a fixture that makes the
whole-program leak test fail if the fix is reverted:

1. Parser error messages no longer quote the file. They report format, line number and exception class only.
2. A value containing a newline is masked whatever its field is called, which closes the indented-INI-continuation leak.
3. A credential file that is one bare string (Pulumi, Fly) is masked by construction.
4. Provider CLI output under `--check` is masked by shape and capped before it reaches `doctor` or `--json`.
5. `passphrase`, `jwt`, `cookie`, `dsn`, `mnemonic`, `seed`, `sas` and anything containing `pass` are now caught by default-deny.
6. Both `doctor` renderers are in the leak test.

v0.1.2 closed the rest of the redaction findings: strong hints such as
`session`, `secret` and `token` now beat the `_id`/`_url` suffix exemption,
the fingerprint tail shows only from 16 characters up, and the leaf of a
dotted name is judged before its parent so `Credentials.AccessKeyId` shows
while `credentials.session_id` does not. It also bounded probe output,
added an overall probe deadline, refused a group- or world-writable overlay,
and percent-quoted the SQLite URI. The last of those had been a genuine
write path: a `?` in `CLOUDSDK_CONFIG` stranded `mode=ro` in the fragment
and SQLite created a stray database. A test now asserts no file appears.

## Still open

One, by decision: an unparsable credentials file is a `doctor` warning rather
than an exit-1 error, because `doctor` fails only on something provable. See
[known-issues.md](known-issues.md).

## Things to know

- **Symlinks are followed.** A `~/.aws/credentials` symlinked elsewhere is read, and the permission audit reports the target's real mode. This is by design; it is your home.
- **The overlay has your full authority.** `~/.config/credmap/registry.toml` can point credmap at any readable file and can declare any command for `--check`. A group- or world-writable overlay file is ignored with a warning; the directory is not checked, so keep it writable only by you.
- **The fingerprint reveals the last four characters** of any secret of 16 characters or more, plus its length. Shorter values show only their length.
- **Provider CLI output is masked by shape.** Under `--check`, any run of 20 or more token-alphabet characters in a CLI's stdout or stderr is fingerprinted before it is shown, and only the first 64 KiB is read.
- **Terminal transcripts persist.** Default output is designed to be safe to paste. `--reveal` output is not, and is never implied.

## Reporting

This is a personal project. Open an issue on the repository. Do not include real credentials in a
report; the fixtures in `tests/conftest.py` show how to build a synthetic one.
