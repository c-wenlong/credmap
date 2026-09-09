# credmap documentation

Read-only discovery for credential stores scattered across your machine.
credmap finds them, parses them, masks the secrets, and tells you what is
wrong. It never writes to a credential file.

## Using it

| Page | What it covers |
|---|---|
| [install.md](install.md) | Installing and upgrading, including through Homebrew and nix-darwin |
| [cli.md](cli.md) | Every verb, flag and exit code |
| [stores.md](stores.md) | The 26 built-in providers, their paths, aliases and probes, and how paths are resolved |
| [doctor.md](doctor.md) | What `doctor` checks and when it fails a pre-flight |
| [check.md](check.md) | What `--check` runs and what the statuses mean |
| [json.md](json.md) | The `--json` schema for every verb |
| [redaction.md](redaction.md) | How masking decides what to hide, and `--reveal` |
| [registry-toml.md](registry-toml.md) | Adding providers or overriding built-ins without editing the package |
| [security.md](security.md) | What credmap does and does not guarantee |

## Working on it

| Page | What it covers |
|---|---|
| [architecture.md](architecture.md) | Modules, data flow, invariants and traps |
| [formats.md](formats.md) | Every parser and the `select` rule |
| [development.md](development.md) | Setup, tests, fixtures |
| [releasing.md](releasing.md) | Cutting a release and what fires |
| [known-issues.md](known-issues.md) | The 2026-09-09 review ledger: every finding and which release closed it |
| [../CHANGELOG.md](../CHANGELOG.md) | What changed in each version |

The [AGENTS.md](../AGENTS.md) at the repo root is the short version of
architecture.md for coding agents and stays the authority on invariants.
