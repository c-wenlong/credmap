<p align="center">
  <img src="assets/banner.png" alt="credmap mascot: a pixel-art detective puppy with a magnifying glass beside a wooden signpost, under AWS, Google Cloud and Azure logos drawn as clouds" width="800">
</p>

<h1 align="center">
credmap
</h1>

<p align="center">
  <strong>Read-only discovery for credential stores scattered across your machine.</strong>
</p>

<p align="center">
  <a href="https://github.com/c-wenlong/credmap/actions/workflows/ci.yml"><img src="https://github.com/c-wenlong/credmap/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://app.codecov.io/gh/c-wenlong/credmap"><img src="https://codecov.io/gh/c-wenlong/credmap/graph/badge.svg?branch=main" alt="Coverage"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11%2B-blue.svg" alt="Python 3.11+"></a>
  <img src="https://img.shields.io/badge/deps-PyYAML%20only-brightgreen.svg" alt="deps: PyYAML only">
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#commands">Commands</a> ·
  <a href="#secrets">Secrets</a> ·
  <a href="#doctor">doctor</a> ·
  <a href="#extending">Extending</a> ·
  <a href="#documentation">Docs</a> ·
  <a href="#contributing">Contributing</a>
</p>

---

Credentials end up in a dozen places, in ten formats, under four different base
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

## Why it isn't just `ls`

Four rules a path list gets wrong, each drawn from a real machine:

- **Directory presence isn't proof.** `~/.azure` gets created by VS Code
  extensions that never write a credential, and `~/.supabase` can hold nothing
  but telemetry. Each store declares a *marker* file instead.
- **Secrets may not be in the file.** `~/.docker/config.json` with
  `credsStore: desktop` has an empty `auths`, and the real secrets sit in the OS
  keychain. "Empty" would otherwise read as "logged out".
- **Formats lie about themselves.** gcloud's OAuth credentials are in SQLite;
  the JSON file beside them is Application Default Credentials, a different
  credential with a different lifecycle.
- **Paths move.** `AWS_SHARED_CREDENTIALS_FILE`, `CLOUDSDK_CONFIG`,
  `KUBECONFIG`, `DOCKER_CONFIG`, `GOOGLE_APPLICATION_CREDENTIALS` and
  `XDG_CONFIG_HOME` all relocate a store. Resolution checks env first, and
  `scan` marks which paths were redirected with `←$VAR`.

## Install

With Nix, pin a release tag as a flake input and add the package to your
list; `nix run github:c-wenlong/credmap` works for a one-off:

```nix
inputs.credmap = {
  url = "github:c-wenlong/credmap/v0.1.4";
  inputs.nixpkgs.follows = "nixpkgs";
};
# then, in home.packages or environment.systemPackages:
inputs.credmap.packages.${pkgs.stdenv.hostPlatform.system}.default
```

From a checkout:

```bash
git clone https://github.com/c-wenlong/credmap
uv tool install ./credmap
```

That puts `credmap` on your PATH at `~/.local/bin/credmap`. The install is a
copy, not a link, so re-run it with `--force` after changing the source. For a
live-editing install, use `uv tool install -e .` from this directory instead.

Nothing is published to PyPI yet. The distribution name is reserved as
`credmap-cli`, because `credmap` there is held by an unrelated 2022 upload;
the command stays `credmap` either way. When the publish job is switched on,
`uv tool install credmap-cli` is the route.

Requirements: Python 3.11 or newer, macOS or Linux, and one runtime
dependency, PyYAML.

See [docs/install.md](docs/install.md) for upgrading, nix-darwin wiring, and
why there is no Homebrew tap.

## Commands

| Command | What it does |
|---|---|
| `credmap` | What credential stores exist here (alias for `scan`) |
| `credmap where <query>` | Locate a provider: `gcp`, `k8s`, `aws`, `github`… |
| `credmap show <store>` | Every profile and field, secrets masked |
| `credmap paths` | The full registry of known paths, present or not |
| `credmap doctor` | Problems only |

A first word that names a store is a `where` on its own, so `credmap aws` is
`credmap where aws`. Anything else falls through to `scan`.

Flags are per-verb, not global. `--json` is on all five. `--all` (include
absent stores) is `scan` only, `--found` (drop absent paths) is `paths` only,
`--reveal` is `show` only, and `--check` (verify each credential against its
provider) is on `scan`, `show` and `doctor`.

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
anyone curates its field list. Identifiers that merely look secret (an AWS
access key ID, a client ID, a project) stay visible, because they're what you
need to find the credential upstream.

## `doctor`

Checks that need more than a file listing:

- One secret reused across several profiles: they're one credential, not many
- Dead credentials (`--check`) and expired tokens (offline, from cached expiry)
- SSO logins that registered a client but never obtained a token
- Credential files and token caches readable by group or others
- Keychain indirection, reported as information rather than a problem
- Store bloat, e.g. gcloud logs that dwarf the credentials beside them

Exits non-zero only when something is provably dead, so it works as a pre-flight
check. Warnings and info alone exit 0.

## Extending

credmap ships 26 providers. Add your own without editing the package, in
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
An override **inherits every field it doesn't mention**. `[aws] name = "Work
AWS"` renames the store and keeps its probe, paths and curated field lists.
Assign an empty value to drop an inherited one (`probe = {}`).

A malformed overlay is ignored rather than fatal, and one that is writable by
group or others is refused with a reason on stderr. Formats available: `ini`,
`inidir`, `json`, `yaml`, `sqlite-gcloud`, `netrc`, `jsondir`, `keydir`, `raw`,
`opaque`.

## Documentation

[docs/](docs/README.md) is the full reference: every command, flag and exit
code, the 26 built-in stores, the `--json` schema, the redaction rules,
installing through Nix, the security model, and the open review findings.
[AGENTS.md](AGENTS.md) is the short version for coding agents.

## Development

```bash
uv sync            # the venv is not portable; re-run after moving the project
uv run pytest -q   # 230 tests
```

Tests generate a synthetic home directory rather than committing fixture files.
Nothing here should look like a credential to a human or a secret scanner.
[docs/development.md](docs/development.md) has the rest: the nix build, what
each test file covers, and which fixture guards the no-leak invariant.

## Contributing

Issues and pull requests are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) covers
the setup, the invariants a change must not break, and what CI runs. Please
don't open a public issue for a security problem: [SECURITY.md](SECURITY.md)
has the reporting route, and [docs/security.md](docs/security.md) describes
what credmap does and does not guarantee.

## License

MIT, see [LICENSE](LICENSE).
