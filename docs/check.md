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
of 8 and the command finishes when every probe has returned or timed out.

Commands are run without a shell. A profile name is substituted as a single
argv element, so spaces or shell characters in a name cannot change what runs.

## Per-profile versus per-store

If any argv element contains `{profile}`, the probe runs once per profile.
Success marks that profile `live`; when the probe declares an `extract` key
and stdout is a JSON object, the extracted value is shown as detail (for AWS,
the account number).

Otherwise the probe runs once for the store. Its stdout is lowercased and
every profile whose name appears in it is marked `live`. Profiles not
mentioned are left alone: a valid kube context simply is not the current one.
Absence of mention is never treated as death. `extract` is ignored in this
mode.

## Which profiles are probeable

Profiles from paths that exist and whose role is `secrets`, or whose spec sets
`identities = true`. AWS `config` opts in because SSO profiles live there.
gcloud's `configurations/` stays out because those are configuration names,
not accounts. AWS `[sso-session]` and `[services]` sections are skipped.

## Outcomes

| status | Meaning |
|---|---|
| `live` | The provider accepted the credential |
| `dead` | The provider rejected it, or the probe timed out. The detail carries the last line of stderr |
| `no-cli` | The provider CLI is not installed |
| `expired` / `valid` | Set offline from a cached expiry, not by a probe |
| `unknown` | Nothing known either way |

Only `dead` produces an `error`-level finding in `doctor`, and so only `dead`
makes `doctor` exit non-zero.
