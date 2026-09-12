# Command reference

`credmap` has five verbs. `scan` is the default: running `credmap` with no verb,
or with only flags, runs `scan`.

| Verb | Arguments | Flags | What it does |
|---|---|---|---|
| `scan` | none | `--json`, `--all`, `--check` | Walk every registry store, stat and parse each path, print grouped output. Absent stores are hidden unless `--all`. |
| `where` | `<query>` | `--json` | Look a provider up by id, alias, name, or kind, then print its paths (present or not). |
| `show` | `<store>` | `--json`, `--check`, `--reveal` | Every profile and field for one store, secrets masked. |
| `paths` | none | `--json`, `--found` | Flat table of every registered path. `--found` drops absent paths from the table and from `--json` alike. |
| `doctor` | none | `--json`, `--check` | Anomalies only. Exits 1 when a credential is provably dead. |

Global flags: `-h`/`--help` and `--version`. `--json` is per-verb, so it goes
after the verb (`credmap paths --json`). `credmap --json` still works because
the missing verb is rewritten to `scan`.

Flags are not global. `--all` is `scan` only, `--reveal` is `show` only, and
`--check` is on `scan`, `show` and `doctor` but not `where` or `paths`.

## Lookup

`where` and `show` resolve the query case-insensitively. Exact matches on the
store id or an alias rank first, then partial matches on id, display name,
kind, or alias substring. `show` uses the first match; `where` prints all of
them. See [stores.md](stores.md) for the id and alias of every built-in.

```
credmap where gcp        # gcloud, gcloud-adc
credmap where k8s        # kube
credmap show aws
credmap show aws --check
credmap show aws --reveal
```

## Exit codes

| Code | When |
|---|---|
| 0 | Success. `doctor` returns 0 when nothing is at `error` level, so warnings and info alone do not fail a pre-flight check. |
| 1 | `doctor` found an `error`-level finding. Today that means a profile probed with `--check` was rejected by its provider. |
| 2 | `where` or `show` matched nothing, or argparse rejected a flag. A first token that names a store (`credmap aws`) is rewritten to `where aws`; any other unknown first token becomes `scan <token>`, which argparse rejects with the same code. |
| 130 | Interrupted with Ctrl-C. |

A closed stdout pipe (`credmap | head`) is swallowed and exits 0.

## Offline by default

Every verb is offline unless `--check` is given. A full `scan` is roughly a
tenth of a second. `--check` runs each provider's own CLI with a hard timeout;
see [check.md](check.md).

## Secrets

Nothing secret is printed by default. `--reveal` is the only flag that unmasks
values, it exists only on `show`, and no other flag implies it. See
[redaction.md](redaction.md).
