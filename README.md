# credmap

Read-only discovery for credential stores scattered across your machine.

Credentials end up in a dozen places, in six formats, under three different base
directories. `credmap` builds an index so you can stop guessing.

```
$ credmap where gcp
  STORE       PATH                                                   FORMAT         ROLE                 PRESENT
  gcloud      ~/.config/gcloud/credentials.db                        sqlite-gcloud  secrets      marker  yes
  gcloud      ~/.config/gcloud/access_tokens.db                      sqlite-gcloud  token-cache          yes
  gcloud      ~/.config/gcloud/configurations                        inidir         config               yes
  gcloud-adc  ~/.config/gcloud/application_default_credentials.json  json           secrets      marker  yes
```

It **never writes to a credential file**. Discovery and diagnosis only;
mutation stays with each provider's own CLI.

## Install

```bash
git clone https://github.com/c-wenlong/credmap
uv tool install ./credmap
```

That puts `credmap` on your PATH at `~/.local/bin/credmap`. The install is a
copy, not a link — re-run it with `--force` after changing the source. For a
live-editing install, use `uv tool install -e .` from this directory instead.

## Commands

| Command | What it does |
|---|---|
| `credmap` | What credential stores exist here (alias for `scan`) |
| `credmap where <query>` | Locate a provider — `gcp`, `k8s`, `aws`, `github`… |
| `credmap show <store>` | Every profile and field, secrets masked |
| `credmap paths` | The full registry of known paths, present or not |
| `credmap doctor` | Problems only |

Flags: `--json` on everything, `--all` to include absent stores, `--check` to
verify credentials against each provider, `--reveal` to unmask.

`scan` is offline and takes about a tenth of a second. Only `--check` touches
the network, and every probe has a hard timeout.

## Secrets

Nothing secret is printed by default. Values render as a fingerprint:

```
aws_secret_access_key = <redacted, 40 chars, ends ...Y4EZ>
```

Enough to match a key against a provider console without putting it in a
terminal transcript. `--reveal` is the only way to see full values and is never
implied by another flag.

Masking is default-deny: a field is masked if its *name* looks secret, whether
or not the registry declared it, so a store you add yourself is safe before
anyone curates its field list. Identifiers that merely look secret — an AWS
access key ID, a client ID, a project — stay visible, because they're what you
need to find the credential upstream.

## Why it isn't just `ls`

Four rules a path list gets wrong, each drawn from a real machine:

- **Directory presence isn't proof.** `~/.azure` gets created by VS Code
  extensions that never write a credential, and `~/.supabase` can hold nothing
  but telemetry. Each store declares a *marker* file instead.
- **Secrets may not be in the file.** `~/.docker/config.json` with
  `credsStore: desktop` has an empty `auths` — the real secrets are in the OS
  keychain. "Empty" would otherwise read as "logged out".
- **Formats lie about themselves.** gcloud's OAuth credentials are in SQLite;
  the JSON file beside them is Application Default Credentials, a different
  credential with a different lifecycle.
- **Paths move.** `AWS_SHARED_CREDENTIALS_FILE`, `CLOUDSDK_CONFIG`,
  `KUBECONFIG`, `DOCKER_CONFIG`, `GOOGLE_APPLICATION_CREDENTIALS` and
  `XDG_CONFIG_HOME` all relocate a store. Resolution checks env first, and
  `scan` marks which paths were redirected with `←$VAR`.

## `doctor`

Checks that need more than a file listing:

- One secret reused across several profiles — they're one credential, not many
- Dead credentials (`--check`) and expired tokens (offline, from cached expiry)
- SSO logins that registered a client but never obtained a token
- Credential files and token caches readable by group or others
- Keychain indirection, reported as information rather than a problem
- Store bloat, e.g. gcloud logs that dwarf the credentials beside them

Exits non-zero only when something is provably dead, so it works as a pre-flight
check. Warnings and info alone exit 0.

## Extending

Add providers without editing the package, in
`~/.config/credmap/registry.toml`:

```toml
[acme]
name = "ACME internal"
kind = "cloud"
aliases = ["acme-corp"]
secret_fields = ["api_token"]
fix = "acme auth login"

  [[acme.paths]]
  path = "~/.acme/creds.json"
  fmt = "json"
  role = "secrets"
  marker = true
```

An entry can also declare a liveness probe for `--check`, and directories worth
flagging when they outgrow the credentials beside them:

```toml
[acme.probe]
argv = ["acme", "whoami", "--profile", "{profile}"]
extract = "Account"   # JSON key to pull out of stdout
timeout = 5

[[acme.bloat]]
path = "~/.acme/logs"
threshold_mb = 500
```

Entries merge over the built-ins by id, so you can also override a shipped one.
An override **inherits every field it doesn't mention** — `[aws] name = "Work
AWS"` renames the store and keeps its probe, paths and curated field lists.
Assign an empty value to drop an inherited one (`probe = {}`).

A malformed overlay is ignored rather than fatal. Formats available: `ini`,
`inidir`, `json`, `yaml`, `sqlite-gcloud`, `netrc`, `jsondir`, `keydir`, `raw`,
`opaque`.

## Development

```bash
uv sync            # the venv is not portable; re-run after moving the project
uv run pytest -q   # 65 tests, ~0.3s
```

Tests generate a synthetic home directory rather than committing fixture files —
nothing here should look like a credential to a human or a secret scanner.

See [docs/](docs/README.md) for the full reference: every command and flag,
the built-in stores, the JSON schema, installing through Nix, and the open
review findings. [AGENTS.md](AGENTS.md) is the short version for coding agents.
