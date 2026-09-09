# Built-in stores

The registry ships 26 stores. Each is a `Store` literal in
`src/credmap/registry.py`, and each is data, not code: adding a provider means
adding a literal, not a parser or a special case.

Conventions used below:

- `{config}` is `$XDG_CONFIG_HOME` or `~/.config`; `{cache}` is `$XDG_CACHE_HOME` or `~/.cache`.
- **marker** marks the path whose existence proves the store is real. A store is `found` when any marker path exists. Directory presence alone is not proof: `~/.azure` is created by editor extensions that never write a credential.
- **role** is one of `secrets`, `config`, `token-cache`, `keys`. It drives the permission audit and the duplicate-secret check (token caches legitimately repeat the secret that minted them, so they are excluded).
- **env** relocates one path; **root_env** relocates the whole directory the path lives under. See [Path resolution](#path-resolution).
- Probe timeout is 5 seconds unless stated.

## cloud

| id | name | aliases | paths | probe (`--check`) | fix |
|---|---|---|---|---|---|
| `aws` | AWS CLI | amazon, iam, s3 | `~/.aws/credentials` ini, secrets, marker, `$AWS_SHARED_CREDENTIALS_FILE` · `~/.aws/config` ini, config, marker, `$AWS_CONFIG_FILE`, profiles count as identities · `~/.aws/sso/cache` jsondir, token-cache · `~/.aws/cli/cache` jsondir, token-cache | `aws sts get-caller-identity --profile {profile} --output json`, extracts `Account` | `aws configure` / `aws configure sso` |
| `gcloud` | Google Cloud SDK | gcp, google | `{config}/gcloud/credentials.db` sqlite-gcloud, secrets, marker · `{config}/gcloud/access_tokens.db` sqlite-gcloud, token-cache · `{config}/gcloud/configurations` inidir, config. All relocated by `$CLOUDSDK_CONFIG` | `gcloud auth list --format=json`, 10 s | `gcloud auth login` |
| `gcloud-adc` | Google Application Default Credentials | adc, gcp-adc, google-adc | `{config}/gcloud/application_default_credentials.json` json, secrets, marker, `$GOOGLE_APPLICATION_CREDENTIALS`, root `$CLOUDSDK_CONFIG` | none | `gcloud auth application-default login` |
| `azure` | Azure CLI | az, microsoft | `~/.azure/azureProfile.json` json, config, marker, profiles from `subscriptions` · `~/.azure/msal_token_cache.json` json, token-cache. Both under `$AZURE_CONFIG_DIR` | `az account show --output json` | `az login` |
| `doctl` | DigitalOcean | digitalocean, do | `{config}/doctl/config.yaml` yaml, secrets, marker | none | `doctl auth init` |

## infra

| id | name | aliases | paths | probe | fix |
|---|---|---|---|---|---|
| `kube` | Kubernetes | k8s, kubectl, kubeconfig | `~/.kube/config` yaml, secrets, marker, `$KUBECONFIG` (a path list), profiles from `contexts` | `kubectl config current-context` | `kubectl config use-context <name>` |
| `docker` | Docker | registry, dockerhub | `~/.docker/config.json` json, secrets, marker, root `$DOCKER_CONFIG`, profiles from `auths` | none | `docker login` |
| `terraform` | Terraform | tf, hashicorp | `~/.terraform.d/credentials.tfrc.json` json, secrets, marker, profiles from `credentials` · `~/.terraformrc` opaque, config | none | `terraform login` |
| `pulumi` | Pulumi | | `~/.pulumi/credentials.json` json, secrets, marker | none | `pulumi login` |
| `vault` | HashiCorp Vault | | `~/.vault-token` raw, secrets, marker | none | `vault login` |

## vcs

| id | name | aliases | paths | probe | fix |
|---|---|---|---|---|---|
| `ssh` | SSH keys | | `~/.ssh` keydir, keys, marker | none | `ssh-keygen -t ed25519 -C <comment>` |
| `gnupg` | GnuPG | gpg | `~/.gnupg` opaque, keys, marker, root `$GNUPGHOME` | none | `gpg --list-secret-keys` |
| `gh` | GitHub CLI | github | `{config}/gh/hosts.yml` yaml, secrets, marker, root `$GH_CONFIG_DIR`, one profile per host | `gh auth status` | `gh auth login` |
| `git-credentials` | Git credential store | | `~/.git-credentials` opaque, secrets, marker | none | `git config --global credential.helper osxkeychain` |
| `netrc` | netrc | heroku, wandb, machine | `~/.netrc` netrc, secrets, marker, `$NETRC` · `~/.authinfo` netrc, secrets | none | |

## pkg

| id | name | aliases | paths | fix |
|---|---|---|---|---|
| `npm` | npm | | `~/.npmrc` opaque, secrets, marker | `npm login` |
| `pypi` | PyPI | twine, pypirc | `~/.pypirc` ini, secrets, marker | |
| `cargo` | Cargo / crates.io | rust, crates | `~/.cargo/credentials.toml` opaque, secrets, marker | `cargo login` |

## paas

| id | name | aliases | paths | fix |
|---|---|---|---|---|
| `firebase` | Firebase CLI | | `{config}/configstore/firebase-tools.json` json, secrets, marker | `firebase login` |
| `supabase` | Supabase CLI | | `~/.supabase/access-token` raw, secrets, marker · `~/.supabase` opaque, config | `supabase login` |
| `vercel` | Vercel | | `~/Library/Application Support/com.vercel.cli/auth.json` json, secrets, marker · `{config}/vercel/auth.json` json, secrets, marker | `vercel login` |
| `fly` | Fly.io | flyctl | `~/.fly/config.yml` yaml, secrets, marker | `fly auth login` |
| `stripe` | Stripe CLI | | `{config}/stripe/config.toml` opaque, secrets, marker | `stripe login` |
| `wrangler` | Cloudflare Wrangler | cloudflare, cf | `{config}/.wrangler/config/default.toml` opaque, secrets, marker · `~/.wrangler/config/default.toml` opaque, secrets, marker | `wrangler login` |

## ai

| id | name | aliases | paths | fix |
|---|---|---|---|---|
| `huggingface` | Hugging Face | hf | `{cache}/huggingface/token` raw, secrets, marker · `{config}/huggingface/token` raw, secrets, marker | `huggingface-cli login` |
| `claude` | Claude Code | anthropic | `~/.claude/.credentials.json` json, secrets, marker | `claude login` |

## Curated field lists

`secret_fields` forces masking and `id_fields` forces visibility for a store,
overriding the name heuristic in [redaction.md](redaction.md). `id_fields`
wins a conflict.

| store | secret_fields | id_fields |
|---|---|---|
| `aws` | aws_secret_access_key, aws_session_token, aws_security_token | aws_access_key_id, sso_account_id, role_arn, sso_session, sso_role_name, sso_start_url, sso_region, sso_registration_scopes, credential_process, web_identity_token_file, role_session_name |
| `gcloud-adc` | client_secret, refresh_token, private_key | client_id, client_email, project_id, quota_project_id |
| `doctl` | access-token | |
| `kube` | token, password, client-key-data, client-certificate-data | |
| `docker` | auth, password, identitytoken | |
| `terraform` | token | |
| `pulumi` | accessToken, accessTokens | |
| `vault` | token | |
| `gh` | oauth_token | user, git_protocol |
| `netrc` | password, account | login |
| `pypi` | password | username, repository |
| `firebase` | refresh_token, access_token, tokens | user, email |
| `vercel` | token | |
| `fly` | access_token | |
| `huggingface` | token | |
| `claude` | accessToken, refreshToken | |

Only `gcloud` declares a bloat directory: `{config}/gcloud/logs` at a 500 MB
threshold. See [doctor.md](doctor.md).

## Path resolution

All path rules live in `src/credmap/resolve.py`. For each path spec, in order:

1. If the spec names an `env` variable and it is set to a non-empty value, that value is the path. `KUBECONFIG` is a list split on the OS path separator, and every element becomes its own path entry.
2. Otherwise, if the spec names a `root_env` and it is set, the path is `$ROOT/<rel>`.
3. Otherwise the template is expanded: `{config}` and `{cache}` are replaced, then environment variables, then `~`.

`XDG_CONFIG_HOME` and `XDG_CACHE_HOME` are read at call time, so they also
relocate the overlay file described in [registry-toml.md](registry-toml.md).

When an env override is in effect, `scan`, `paths` and `where` annotate the
path with `←$VAR`, and JSON output carries it in `env_override`. The annotation
appears even when the redirected path does not exist, which is itself a useful
signal.

Paths under the home directory are displayed with `~`. JSON output always uses
absolute paths.
