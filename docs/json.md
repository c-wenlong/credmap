# JSON output

Every verb accepts `--json`. Output is UTF-8 JSON with two-space indentation.
Secrets are masked exactly as in the table output; `show --json --reveal` is
the only combination that emits full values.

| Command | Top-level shape |
|---|---|
| `scan --json` | Array of store objects, only `found` stores unless `--all` |
| `paths --json` | Array of store objects for every store. `--found` drops absent path entries and then any store left with no paths |
| `where --json` | Array of store objects, one per match |
| `show --json` | One store object, not an array |
| `doctor --json` | Array of finding objects |

## Store object

```json
{
  "id": "aws",
  "name": "AWS CLI",
  "kind": "cloud",
  "found": true,
  "note": "",
  "docs": "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html",
  "paths": [
    {
      "path": "/Users/you/.aws/credentials",
      "exists": true,
      "format": "ini",
      "role": "secrets",
      "marker": true,
      "mode": "0644",
      "size": 116,
      "env_override": null,
      "note": "",
      "error": null,
      "profiles": [
        {
          "name": "default",
          "status": "unknown",
          "detail": "",
          "expires_at": null,
          "fields": {
            "aws_access_key_id": "AKIAEXAMPLEEXAMPLE12",
            "aws_secret_access_key": "<redacted, 40 chars, ends ...GGGH>"
          }
        }
      ]
    }
  ]
}
```

| Field | Type | Notes |
|---|---|---|
| `found` | bool | A marker path exists |
| `paths[].path` | string | Absolute, never `~` |
| `paths[].exists` | bool | |
| `paths[].mode` | string or null | Zero-padded octal such as `"0644"`; null when absent |
| `paths[].size` | int | Bytes as `stat` reports them. For a directory that is the directory entry itself, not its contents |
| `paths[].env_override` | string or null | Name of the variable that relocated this path |
| `paths[].note` | string | Empty when unset |
| `paths[].error` | string or null | Parser failure, if any |
| `profiles[].status` | string | `live`, `dead`, `expired`, `valid`, `unknown`, `no-cli` |
| `profiles[].expires_at` | string or null | |
| `profiles[].fields` | object | Whatever the parser produced: strings, bools, nested objects, arrays, all passed through redaction |

Profiles are listed per path. A gcloud account that appears in both
`credentials.db` and `access_tokens.db` shows up under each path; the merged
view used by the table renderer is not exposed in JSON.

## Finding object

```json
{
  "level": "warn",
  "store": "aws",
  "message": "~/.aws/credentials is mode 0644 — readable by group or others",
  "fix": "chmod 600 ~/.aws/credentials"
}
```

`level` is `error`, `warn` or `info`. `fix` is an empty string when there is
nothing to run. Paths inside messages use `~`, unlike the store object.
