# doctor

`credmap doctor` runs a set of checks over a completed scan and prints only
problems. It is offline unless `--check` is given. Each finding has a level,
a store, a message, and where possible the provider command that fixes it.
credmap never runs that command itself.

## Checks

| Check | Level | Condition | Fix printed |
|---|---|---|---|
| Dead credential | error | A profile probed with `--check` was rejected by its provider | the store's login command |
| Expired token | warn | A cached expiry in the past, read offline from the file | the store's login command |
| CLI missing | info | Credentials exist but the provider CLI is not installed (only with `--check`) | |
| Shared secret | warn | The same secret string appears in two or more profiles across `secrets`-role paths | `these are the same credential — revoking it breaks all of them` |
| SSO never completed | warn | An AWS SSO cache holds client registrations but no access token | the store's login command |
| Unreadable profiles | warn | Some files in a config directory could not be opened, though others parsed | the store's login command |
| Unparsable file | warn | A path exists but its parser reported an error | the store's login command |
| Other notes | info | Keychain indirection, current kube context, stale gcloud token cache, opaque stores | |
| Loose permissions | warn | A `secrets`, `keys` or `token-cache` path is readable by group or others | `chmod 600 <path>`, or `chmod 700` for a directory, with the path shell-quoted |
| Bloat | info | A declared bloat directory exceeds its threshold (gcloud logs over 500 MB); size shown in MB below 1 GB | `rm -rf <path>/*`, with the path shell-quoted and a leading `~/` left for the shell to expand |
| Empty store | info | The store's marker exists but no profiles were parsed and no note explains why | |

A note's severity comes from a field the parser sets, not from its wording, so
rephrasing a message can never change how it is reported.

Token caches are excluded from the shared-secret check because they
legitimately repeat the client secret that minted them.

Duplicate findings with the same level, store and message are collapsed.

## Exit code

`doctor` exits 1 only when an `error`-level finding exists, and the only
`error` today is a profile that `--check` proved dead. Warnings and info exit
0, so `credmap doctor` works as a pre-flight check that fails only on
something provable.

That also means an offline `doctor` can never exit non-zero. An unreadable
credentials file is a warning.

## Examples

```
$ credmap doctor
  warn  aws    ~/.aws/credentials is mode 0644 — readable by group or others
               fix: chmod 600 ~/.aws/credentials
  warn  aws    one secret is shared by 2 profiles (aws:default, aws:staging)
               fix: these are the same credential — revoking it breaks all of them
  info  docker secrets held in macOS Keychain, not in this file

$ credmap doctor --json
[
  {
    "level": "warn",
    "store": "aws",
    "message": "~/.aws/credentials is mode 0644 — readable by group or others",
    "fix": "chmod 600 ~/.aws/credentials"
  }
]
```
