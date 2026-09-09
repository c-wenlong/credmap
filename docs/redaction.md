# Redaction

Nothing secret is printed by default. Every field value that any renderer
prints passes through one function, `redact.scrub`, and the leak test in
`tests/test_redact.py` runs every renderer over a synthetic home to assert
that no sentinel secret ever appears in output.

## What a masked value looks like

| Secret length | Rendered as |
|---|---|
| 8 characters or fewer | `<redacted, N chars>` |
| More than 8 | `<redacted, N chars, ends ...XXXX>` |

The four-character tail is enough to match a key against a provider console
without putting the key in a terminal transcript. Short secrets show no tail.

Only non-empty strings are masked. Booleans, integers, `null` and empty
strings pass through, because they carry no secret and hiding them makes the
output harder to read.

Any string containing a newline is masked whatever its field is called, even
an `id_fields` entry. Nothing legitimate in these formats spans lines, and
configparser folds an indented line into the previous value, so a leading
space before `aws_secret_access_key` would otherwise park the secret inside
the visible `aws_access_key_id`.

## Deciding what is secret

`is_secret(field, store)` runs these checks in order and stops at the first
that decides:

1. The name is in the store's `id_fields`: **visible**. This is checked first, so a curated identifier beats every other rule.
2. The name is in the store's `secret_fields`: **masked**.
3. The last segment of a dotted name is in the never-secret set, or ends with `_id`, `_ids`, `_present`, `_expiry`, `_domain`, `_url` or `_uri`: **visible**. The never-secret set is `type`, `name`, `account`, `login`, `user`, `username`, `email`, `keyring`, `key_type`, `public_key`, `git_protocol`, `private_key_present`, `project`, `region`, `universe_domain`.
4. The full name contains any of `secret`, `token`, `password`, `passwd`, `pass`, `phrase`, `private`, `credential`, `auth`, `key`, `cert`, `session`, `bearer`, `signature`, `jwt`, `cookie`, `dsn`, `mnemonic`, `seed`, `sas`: **masked**.
5. Otherwise **visible**.

Step 4 makes redaction default-deny. A store you add in your own
`registry.toml` is safe before anyone curates its field list, because any
field whose name looks secret is masked whether or not the registry declared
it. Nested values are judged by their full dotted path, so everything under an
`auth` key is masked.

When a field is wrongly masked, the fix is to add it to that store's
`id_fields`. The hint list is never loosened to make one store look nicer.

## Identifiers stay visible

An AWS access key ID, a client ID, an account number and a project are how you
find a credential upstream. Masking them makes the output useless without
making anything safer. That is what `id_fields` is for, and the curated lists
in [stores.md](stores.md#curated-field-lists) exist for exactly this reason.

## `--reveal`

`show --reveal` returns fields untouched. It is the only way to see full
values, it exists on no other verb, and no other flag implies it. `scan`,
`where`, `paths` and `doctor` always mask.

## Text without a field name

Probe output under `--check` has no field name to judge it by, so it is
masked by shape instead: any run of 20 or more characters from the token
alphabet (letters, digits, `_-+/=.`) is replaced with a fingerprint, and the
line is capped at 160 characters. A long filesystem path in a CLI's error
gets masked as collateral. Parser error messages are built without quoting
the file at all; see [formats.md](formats.md).

What remains open is listed in [known-issues.md](known-issues.md): the
`_url`/`_uri` suffix exemption beating a hint match, the four-character tail
on short human passwords, and the leaf-versus-path scope mismatch.
