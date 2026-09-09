# --check: liveness probes

`--check` is the only thing in credmap that touches the network or runs
another program. It is available on `scan`, `show` and `doctor`. Without it,
every command is offline and finishes in about a tenth of a second.

## What runs

A store is probed when it declares a `probe`, its marker exists, and it has at
least one probeable profile. Five built-ins declare probes:

| store | command | mode |
|---|---|---|
| `aws` | `aws sts get-caller-identity --profile {profile} --output json` | per profile |
| `gcloud` | `gcloud auth list --format=json` | per store, 10 s timeout |
| `azure` | `az account show --output json` | per store |
| `kube` | `kubectl config current-context` | per store |
| `gh` | `gh auth status` | per store |

The default timeout is 5 seconds per invocation. Probes run in a thread pool
of 8 under an overall deadline of the longest timeout plus 5 seconds. A probe
still running at the deadline leaves its profiles `unknown` with detail
`timed out`; a probe that raises leaves them `unknown` with the exception
class named.

Commands are run without a shell. A profile name is substituted as a single
argv element, so spaces or shell characters in a name cannot change what
runs. A name beginning with `-` is skipped rather than handed to the CLI as
an option. Only the first 64 KiB of stdout and stderr are kept; the rest is
drained and discarded so a chatty CLI cannot exhaust memory. On timeout the
whole process group is killed, so a grandchild holding the pipe cannot hang
the scan.

## Per-profile versus per-store

If any argv element contains `{profile}`, the probe runs once per profile
name. The same identity can appear in two files (AWS `default` in both
`credentials` and `config`); it is probed once and the verdict is applied to
every copy. Success marks the profile `live`; when the probe declares an
`extract` key and stdout is a JSON object, the extracted value is shown as
detail (for AWS, the account number).

Otherwise the probe runs once for the store. If stdout parses as JSON, the
values of `account`, `name`, `id`, `user`, `username` and `context` keys are
collected and profiles are matched exactly against them. If it does not,
each profile name is searched for as a whole word, where `_`, `.`, `@` and
`-` count as part of the word, so a context named `dev` is not matched by
`devops`. Matched profiles are marked `live`, and `extract` applies to them
as in per-profile mode. Profiles not mentioned are left alone: a valid kube
context simply is not the current one. Absence of mention is never treated
as death.

Everything a CLI prints is masked by shape before it becomes a profile's
detail; see [redaction.md](redaction.md#text-without-a-field-name).

## Which profiles are probeable

Profiles from paths that exist and whose role is `secrets`, or whose spec sets
`identities = true`. AWS `config` opts in because SSO profiles live there.
gcloud's `configurations/` stays out because those are configuration names,
not accounts. AWS `[sso-session]` and `[services]` sections are skipped.

## Outcomes

| status | Meaning |
|---|---|
| `live` | The provider accepted the credential |
| `dead` | The provider rejected it, or the probe's own timeout fired. The detail carries the last line of stderr, masked and capped |
| `no-cli` | The provider CLI is not installed |
| `expired` / `valid` | Set offline from a cached expiry, not by a probe |
| `unknown` | Nothing known either way, including a probe that hit the overall deadline, raised, or was skipped for a `-` prefixed name |

Only `dead` produces an `error`-level finding in `doctor`, and so only `dead`
makes `doctor` exit non-zero.
