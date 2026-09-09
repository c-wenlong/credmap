# Extending the registry

Providers can be added, or built-ins adjusted, without editing the package.
credmap reads `~/.config/credmap/registry.toml` on every run. `XDG_CONFIG_HOME`
relocates it along with everything else.

The file is merged over the built-ins by store id. A malformed file is ignored
as a whole, silently, and the built-ins are used unchanged.

## A new store

```toml
[acme]
name = "ACME internal"
kind = "cloud"
aliases = ["acme-corp"]
secret_fields = ["api_token"]
id_fields = ["account_id"]
docs = "https://acme.example/docs/cli"
note = "tokens are minted by the acme CLI, not by hand"
fix = "acme auth login"

  [[acme.paths]]
  path = "~/.acme/creds.json"
  fmt = "json"
  role = "secrets"
  marker = true

  [[acme.paths]]
  path = "{config}/acme/config.toml"
  fmt = "opaque"
  role = "config"
```

A new store with no `paths` is skipped. The table name becomes the store id
and cannot be set any other way.

### Store keys

| Key | Type | Default |
|---|---|---|
| `name` | string | the table name |
| `kind` | string | `misc` |
| `aliases` | array of strings | none |
| `secret_fields` | array of strings | none. Forces masking; see [redaction.md](redaction.md) |
| `id_fields` | array of strings | none. Forces visibility, wins over `secret_fields` |
| `docs`, `note`, `fix` | string | empty |
| `paths` | array of tables | required for a new store |
| `probe` | table | none |
| `bloat` | array of tables | none |

Arrays must be arrays. `aliases = "acme"` is accepted and becomes the four
aliases `a`, `c`, `m`, `e`.

### `[[paths]]` keys

| Key | Type | Default | Meaning |
|---|---|---|---|
| `path` | string | required | Template. `{config}`, `{cache}`, `$VAR` and `~` are expanded |
| `fmt` | string | `opaque` | One of the formats in [formats.md](formats.md) |
| `role` | string | `config` | `secrets`, `config`, `token-cache` or `keys` |
| `marker` | bool | false | This path's existence proves the store exists |
| `env` | string | | Variable that replaces this path outright |
| `root_env` | string | | Variable that replaces the directory; used with `rel` |
| `rel` | string | | Path relative to `$root_env` |
| `multi` | bool | false | `env` holds a path list separated by the OS path separator |
| `select` | string | | Where profile names live; see [formats.md](formats.md#select-where-profile-names-live) |
| `identities` | bool | derived | Whether profiles here are credential identities worth probing. Defaults to true for `secrets` |

### `[probe]` keys

```toml
[acme.probe]
argv = ["acme", "whoami", "--profile", "{profile}"]
extract = "Account"   # JSON key to pull out of stdout, per-profile probes only
timeout = 5
```

`argv` must be a non-empty array or the probe is dropped. Include `{profile}`
in an element to run once per profile; leave it out to run once per store.
See [check.md](check.md).

### `[[bloat]]` keys

```toml
[[acme.bloat]]
path = "~/.acme/logs"
threshold_mb = 500
```

`doctor` reports the directory when it outgrows the threshold. Malformed
entries are skipped individually.

## Overriding a built-in

An entry whose id matches a built-in inherits every field it does not mention.

```toml
[aws]
name = "Work AWS"
```

keeps the AWS probe, paths and curated field lists and only changes the
display name.

To drop an inherited field, assign it an empty value:

```toml
[aws]
probe = {}          # no --check for AWS
bloat = []
aliases = []
docs = ""
```

`paths = []` does not drop the inherited paths; an empty list falls back to
the built-in's list. To change a built-in's paths, list the full set you want.

## Safety

Redaction is default-deny, so a store added here is safe before its field list
is curated: any field whose name looks secret is masked. Add identifiers you
need to see to `id_fields` rather than relying on the heuristic.

The overlay can point credmap at any readable file and can declare any probe
command. It is your own file with your own permissions, so this is the same
trust as your shell profile.
