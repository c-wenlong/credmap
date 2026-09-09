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

## Still open

Listed with detail in [known-issues.md](known-issues.md): the `_url`/`_uri`
suffix exemption overrides an explicit hint match, so `secret_url` and
`session_id` print; the fingerprint tail reveals four characters from nine
characters up, which is a lot of a human-chosen password; and hints are
judged on the full dotted path while the allow-list is judged on the leaf.

## Things to know

- **Symlinks are followed.** A `~/.aws/credentials` symlinked elsewhere is read, and the permission audit reports the target's real mode. This is by design; it is your home.
- **The overlay has your full authority.** `~/.config/credmap/registry.toml` can point credmap at any readable file and can declare any command for `--check`. It is read without an ownership or permission check, so keep that directory writable only by you.
- **The fingerprint reveals the last four characters** of any secret longer than eight characters, plus its length. That is calibrated for machine tokens. For a human-chosen password it reveals a meaningful fraction.
- **Terminal transcripts persist.** Default output is designed to be safe to paste. `--reveal` output is not, and is never implied.

## Reporting

This is a personal project. Open an issue on the repository, or if the repo
is private, contact the author directly. Do not include real credentials in a
report; the fixtures in `tests/conftest.py` show how to build a synthetic one.
