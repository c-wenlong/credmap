"""The registry: where credentials live, per provider.

This module is data, not behaviour. Adding a provider should mean adding a
``Store`` here — never touching the scanner. Users extend it without editing
the package via ``~/.config/credmap/registry.toml`` (see :func:`load`).

Conventions worth knowing before adding an entry:

* ``marker=True`` marks the path whose existence *proves* the store is real.
  Directory presence is not proof: ``~/.azure`` is created by VS Code
  extensions that never write a credential.
* ``role="secrets"`` means the file holds key material; ``config`` means it
  does not. This drives the permission audit.
* ``id_fields`` are identifiers that look secret but aren't, and must stay
  visible — an AWS access key ID is useless without its secret and you need
  it to find the key in the IAM console.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from .model import PathSpec, Probe, Store
from .resolve import config_home, display

# --------------------------------------------------------------------------
# cloud
# --------------------------------------------------------------------------

AWS = Store(
    id="aws",
    name="AWS CLI",
    kind="cloud",
    aliases=("amazon", "iam", "s3"),
    paths=(
        PathSpec(
            "~/.aws/credentials",
            fmt="ini",
            role="secrets",
            env="AWS_SHARED_CREDENTIALS_FILE",
            marker=True,
        ),
        PathSpec(
            "~/.aws/config",
            fmt="ini",
            role="config",
            env="AWS_CONFIG_FILE",
            marker=True,
            identities=True,  # SSO profiles live here, not in credentials
        ),
        PathSpec("~/.aws/sso/cache", fmt="jsondir", role="token-cache"),
        PathSpec("~/.aws/cli/cache", fmt="jsondir", role="token-cache"),
    ),
    secret_fields=frozenset(
        {"aws_secret_access_key", "aws_session_token", "aws_security_token"}
    ),
    # SSO wiring is configuration, not key material: the session name, the
    # role and the portal URL are all safe to print and useless without a token.
    id_fields=frozenset(
        {
            "aws_access_key_id",
            "sso_account_id",
            "role_arn",
            "sso_session",
            "sso_role_name",
            "sso_start_url",
            "sso_region",
            "sso_registration_scopes",
            # A command line, a file path and a label. None of the three can
            # hold key material, and all three are what you need to see to
            # work out where a profile actually gets its credentials from.
            "credential_process",
            "web_identity_token_file",
            "role_session_name",
        }
    ),
    probe=Probe(
        (
            "aws",
            "sts",
            "get-caller-identity",
            "--profile",
            "{profile}",
            "--output",
            "json",
        ),
        extract="Account",
    ),
    docs="https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html",
    fix=(
        "aws configure           # static IAM keys\n"
        "aws configure sso      # IAM Identity Center"
    ),
)

GCLOUD = Store(
    id="gcloud",
    name="Google Cloud SDK",
    kind="cloud",
    aliases=("gcp", "google"),
    paths=(
        PathSpec(
            "{config}/gcloud/credentials.db",
            fmt="sqlite-gcloud",
            role="secrets",
            root_env="CLOUDSDK_CONFIG",
            rel="credentials.db",
            marker=True,
        ),
        PathSpec(
            "{config}/gcloud/access_tokens.db",
            fmt="sqlite-gcloud",
            role="token-cache",
            root_env="CLOUDSDK_CONFIG",
            rel="access_tokens.db",
        ),
        PathSpec(
            "{config}/gcloud/configurations",
            fmt="inidir",
            role="config",
            root_env="CLOUDSDK_CONFIG",
            rel="configurations",
        ),
    ),
    probe=Probe(("gcloud", "auth", "list", "--format=json"), timeout=10),
    bloat=(("{config}/gcloud/logs", 500),),
    docs="https://cloud.google.com/sdk/docs/authorizing",
    note="OAuth tokens live in SQLite, not a JSON key file",
    fix="gcloud auth login",
)

GCLOUD_ADC = Store(
    id="gcloud-adc",
    name="Google Application Default Credentials",
    kind="cloud",
    aliases=("adc", "gcp-adc", "google-adc"),
    paths=(
        PathSpec(
            "{config}/gcloud/application_default_credentials.json",
            fmt="json",
            role="secrets",
            env="GOOGLE_APPLICATION_CREDENTIALS",
            root_env="CLOUDSDK_CONFIG",
            rel="application_default_credentials.json",
            marker=True,
        ),
    ),
    secret_fields=frozenset({"client_secret", "refresh_token", "private_key"}),
    id_fields=frozenset(
        {"client_id", "client_email", "project_id", "quota_project_id"}
    ),
    docs="https://cloud.google.com/docs/authentication/application-default-credentials",
    note="what SDKs pick up automatically; separate lifecycle from gcloud CLI login",
    fix="gcloud auth application-default login",
)

AZURE = Store(
    id="azure",
    name="Azure CLI",
    kind="cloud",
    aliases=("az", "microsoft"),
    paths=(
        PathSpec(
            "~/.azure/azureProfile.json",
            fmt="json",
            role="config",
            root_env="AZURE_CONFIG_DIR",
            rel="azureProfile.json",
            select="subscriptions",
            marker=True,
        ),
        PathSpec(
            "~/.azure/msal_token_cache.json",
            fmt="json",
            role="token-cache",
            root_env="AZURE_CONFIG_DIR",
            rel="msal_token_cache.json",
        ),
    ),
    probe=Probe(("az", "account", "show", "--output", "json"), extract="id"),
    docs="https://learn.microsoft.com/cli/azure/authenticate-azure-cli",
    note=(
        "~/.azure is also created by VS Code extensions — "
        "the profile file is the real marker"
    ),
    fix="az login",
)

DOCTL = Store(
    id="doctl",
    name="DigitalOcean",
    kind="cloud",
    aliases=("digitalocean", "do"),
    paths=(
        PathSpec("{config}/doctl/config.yaml", fmt="yaml", role="secrets", marker=True),
    ),
    secret_fields=frozenset({"access-token"}),
    fix="doctl auth init",
)

# --------------------------------------------------------------------------
# infra
# --------------------------------------------------------------------------

KUBE = Store(
    id="kube",
    name="Kubernetes",
    kind="infra",
    aliases=("k8s", "kubectl", "kubeconfig"),
    paths=(
        PathSpec(
            "~/.kube/config",
            fmt="yaml",
            role="secrets",
            env="KUBECONFIG",
            multi=True,
            select="contexts",
            marker=True,
        ),
    ),
    secret_fields=frozenset(
        {"token", "password", "client-key-data", "client-certificate-data"}
    ),
    probe=Probe(("kubectl", "config", "current-context")),
    docs="https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/",
    fix="kubectl config use-context <name>",
)

DOCKER = Store(
    id="docker",
    name="Docker",
    kind="infra",
    aliases=("registry", "dockerhub"),
    paths=(
        PathSpec(
            "~/.docker/config.json",
            fmt="json",
            role="secrets",
            root_env="DOCKER_CONFIG",
            rel="config.json",
            select="auths",
            marker=True,
        ),
    ),
    secret_fields=frozenset({"auth", "password", "identitytoken"}),
    docs="https://docs.docker.com/reference/cli/docker/login/",
    note=(
        "with a credsStore set, the file holds no secrets — they're in the OS keychain"
    ),
    fix="docker login",
)

TERRAFORM = Store(
    id="terraform",
    name="Terraform",
    kind="infra",
    aliases=("tf", "hashicorp"),
    paths=(
        PathSpec(
            "~/.terraform.d/credentials.tfrc.json",
            fmt="json",
            role="secrets",
            select="credentials",
            marker=True,
        ),
        PathSpec("~/.terraformrc", fmt="opaque", role="config"),
    ),
    secret_fields=frozenset({"token"}),
    fix="terraform login",
)

PULUMI = Store(
    id="pulumi",
    name="Pulumi",
    kind="infra",
    paths=(
        PathSpec("~/.pulumi/credentials.json", fmt="json", role="secrets", marker=True),
    ),
    secret_fields=frozenset({"accessToken", "accessTokens"}),
    fix="pulumi login",
)

VAULT = Store(
    id="vault",
    name="HashiCorp Vault",
    kind="infra",
    paths=(PathSpec("~/.vault-token", fmt="raw", role="secrets", marker=True),),
    secret_fields=frozenset({"token"}),
    fix="vault login",
)

# --------------------------------------------------------------------------
# vcs / packages
# --------------------------------------------------------------------------

SSH = Store(
    id="ssh",
    name="SSH keys",
    kind="vcs",
    paths=(PathSpec("~/.ssh", fmt="keydir", role="keys", marker=True),),
    docs="https://www.openssh.com/manual.html",
    fix="ssh-keygen -t ed25519 -C <comment>",
)

GNUPG = Store(
    id="gnupg",
    name="GnuPG",
    kind="vcs",
    aliases=("gpg",),
    paths=(
        PathSpec(
            "~/.gnupg",
            fmt="opaque",
            role="keys",
            root_env="GNUPGHOME",
            rel=".",
            marker=True,
        ),
    ),
    fix="gpg --list-secret-keys",
)

GH = Store(
    id="gh",
    name="GitHub CLI",
    kind="vcs",
    aliases=("github",),
    paths=(
        PathSpec(
            "{config}/gh/hosts.yml",
            fmt="yaml",
            role="secrets",
            root_env="GH_CONFIG_DIR",
            rel="hosts.yml",
            select=".",
            marker=True,
        ),
    ),
    secret_fields=frozenset({"oauth_token"}),
    id_fields=frozenset({"user", "git_protocol"}),
    probe=Probe(("gh", "auth", "status")),
    fix="gh auth login",
)

GIT_CREDENTIALS = Store(
    id="git-credentials",
    name="Git credential store",
    kind="vcs",
    paths=(PathSpec("~/.git-credentials", fmt="opaque", role="secrets", marker=True),),
    note="plaintext URLs with embedded passwords; prefer a credential helper",
    fix="git config --global credential.helper osxkeychain",
)

NETRC = Store(
    id="netrc",
    name="netrc",
    kind="vcs",
    aliases=("heroku", "wandb", "machine"),
    paths=(
        PathSpec("~/.netrc", fmt="netrc", role="secrets", env="NETRC", marker=True),
        PathSpec("~/.authinfo", fmt="netrc", role="secrets"),
    ),
    secret_fields=frozenset({"password", "account"}),
    id_fields=frozenset({"login"}),
    note="shared by curl, heroku, wandb and others — one file, many services",
)

NPM = Store(
    id="npm",
    name="npm",
    kind="pkg",
    paths=(PathSpec("~/.npmrc", fmt="opaque", role="secrets", marker=True),),
    fix="npm login",
)

PYPI = Store(
    id="pypi",
    name="PyPI",
    kind="pkg",
    aliases=("twine", "pypirc"),
    paths=(PathSpec("~/.pypirc", fmt="ini", role="secrets", marker=True),),
    secret_fields=frozenset({"password"}),
    id_fields=frozenset({"username", "repository"}),
)

CARGO = Store(
    id="cargo",
    name="Cargo / crates.io",
    kind="pkg",
    aliases=("rust", "crates"),
    paths=(
        PathSpec(
            "~/.cargo/credentials.toml", fmt="opaque", role="secrets", marker=True
        ),
    ),
    fix="cargo login",
)

# --------------------------------------------------------------------------
# paas / saas
# --------------------------------------------------------------------------

FIREBASE = Store(
    id="firebase",
    name="Firebase CLI",
    kind="paas",
    paths=(
        PathSpec(
            "{config}/configstore/firebase-tools.json",
            fmt="json",
            role="secrets",
            marker=True,
        ),
    ),
    secret_fields=frozenset({"refresh_token", "access_token", "tokens"}),
    id_fields=frozenset({"user", "email"}),
    fix="firebase login",
)

SUPABASE = Store(
    id="supabase",
    name="Supabase CLI",
    kind="paas",
    paths=(
        PathSpec("~/.supabase/access-token", fmt="raw", role="secrets", marker=True),
        PathSpec("~/.supabase", fmt="opaque", role="config"),
    ),
    fix="supabase login",
)

VERCEL = Store(
    id="vercel",
    name="Vercel",
    kind="paas",
    paths=(
        PathSpec(
            "~/Library/Application Support/com.vercel.cli/auth.json",
            fmt="json",
            role="secrets",
            marker=True,
        ),
        PathSpec("{config}/vercel/auth.json", fmt="json", role="secrets", marker=True),
    ),
    secret_fields=frozenset({"token"}),
    fix="vercel login",
)

FLY = Store(
    id="fly",
    name="Fly.io",
    kind="paas",
    aliases=("flyctl",),
    paths=(PathSpec("~/.fly/config.yml", fmt="yaml", role="secrets", marker=True),),
    secret_fields=frozenset({"access_token"}),
    fix="fly auth login",
)

STRIPE = Store(
    id="stripe",
    name="Stripe CLI",
    kind="paas",
    paths=(
        PathSpec(
            "{config}/stripe/config.toml", fmt="opaque", role="secrets", marker=True
        ),
    ),
    fix="stripe login",
)

CLOUDFLARE = Store(
    id="wrangler",
    name="Cloudflare Wrangler",
    kind="paas",
    aliases=("cloudflare", "cf"),
    paths=(
        PathSpec(
            "{config}/.wrangler/config/default.toml",
            fmt="opaque",
            role="secrets",
            marker=True,
        ),
        PathSpec(
            "~/.wrangler/config/default.toml", fmt="opaque", role="secrets", marker=True
        ),
    ),
    fix="wrangler login",
)

# --------------------------------------------------------------------------
# ai
# --------------------------------------------------------------------------

HUGGINGFACE = Store(
    id="huggingface",
    name="Hugging Face",
    kind="ai",
    aliases=("hf",),
    paths=(
        PathSpec("{cache}/huggingface/token", fmt="raw", role="secrets", marker=True),
        PathSpec("{config}/huggingface/token", fmt="raw", role="secrets", marker=True),
    ),
    secret_fields=frozenset({"token"}),
    fix="huggingface-cli login",
)

CLAUDE = Store(
    id="claude",
    name="Claude Code",
    kind="ai",
    aliases=("anthropic",),
    paths=(
        PathSpec(
            "~/.claude/.credentials.json", fmt="json", role="secrets", marker=True
        ),
    ),
    secret_fields=frozenset({"accessToken", "refreshToken"}),
    fix="claude login",
)


BUILTIN: tuple[Store, ...] = (
    AWS,
    GCLOUD,
    GCLOUD_ADC,
    AZURE,
    DOCTL,
    KUBE,
    DOCKER,
    TERRAFORM,
    PULUMI,
    VAULT,
    SSH,
    GNUPG,
    GH,
    GIT_CREDENTIALS,
    NETRC,
    NPM,
    PYPI,
    CARGO,
    FIREBASE,
    SUPABASE,
    VERCEL,
    FLY,
    STRIPE,
    CLOUDFLARE,
    HUGGINGFACE,
    CLAUDE,
)


# --------------------------------------------------------------------------
# user overlay
# --------------------------------------------------------------------------


# Why the last load() ignored the overlay, for the CLI to print once on
# stderr. Empty when the overlay was absent, or read normally.
OVERLAY_WARNING = ""


def overlay_path() -> Path:
    return config_home() / "credmap" / "registry.toml"


def _unsafe_overlay(path: Path) -> str:
    """Why this overlay must not be trusted, or "" if it is fine.

    The overlay names files to read and, under ``--check``, argv to execute.
    If anyone but the owner can write it, that is arbitrary file read into
    stdout and arbitrary execution as the owner, from a file nobody looks at.
    Refusing to read it is cheap; the alternative is trusting the mode.

    The directory counts too. Write permission on a directory is permission to
    unlink and recreate what is in it, so a group-writable
    ``~/.config/credmap`` hands over the same power as a group-writable
    ``registry.toml`` — the 0600 mode on the file it replaces is whatever the
    attacker chose. Both are checked by the same rule, and the message says
    which one is at fault so the reader knows what to chmod.
    """

    def mode_of(target: Path) -> int | None:
        try:
            return target.stat().st_mode & 0o777
        except OSError:
            return None

    mode = mode_of(path)
    if mode is not None and mode & 0o022:
        return (
            f"ignoring {display(path)}: mode {mode:04o} is writable by group "
            "or others, and this file names paths to read and commands to run"
        )

    parent = path.parent
    mode = mode_of(parent)
    if mode is not None and mode & 0o022:
        return (
            f"ignoring {display(path)}: its directory {display(parent)} has "
            f"mode {mode:04o}, writable by group or others, so anyone can "
            "replace the file whatever mode the file itself has"
        )
    return ""


def _as_list(value: object) -> list[str]:
    """Coerce a TOML value to a list of strings.

    A bare string is one element, not one element per character:
    ``aliases = "acme"`` used to iterate into the four aliases a, c, m, e.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple, set, frozenset)):
        return [str(v) for v in value]
    return [str(value)]


def _probe_from_toml(raw: dict) -> Probe | None:
    argv = raw.get("argv")
    if not isinstance(argv, list) or not argv:
        return None
    try:
        timeout = int(raw.get("timeout", 5))
    except (TypeError, ValueError):
        timeout = 5
    extract = raw.get("extract")
    return Probe(
        argv=tuple(str(a) for a in argv),
        extract=str(extract) if extract else None,
        timeout=timeout,
    )


def _bloat_from_toml(raw: list) -> tuple[tuple[str, int], ...]:
    out = []
    for entry in raw:
        if not isinstance(entry, dict) or "path" not in entry:
            continue
        try:
            out.append((str(entry["path"]), int(entry.get("threshold_mb", 500))))
        except (TypeError, ValueError):
            continue
    return tuple(out)


def _store_from_toml(sid: str, raw: dict, base: Store | None = None) -> Store:
    """Build a Store from an overlay entry.

    Anything the entry does not mention is inherited from ``base``, the
    built-in of the same id. Overriding one field of a shipped store must not
    silently discard the rest of it — renaming ``aws`` used to drop its
    liveness probe, its secret_fields and its docs along with the name.

    Mentioning a key with an empty value is how you remove an inherited one,
    and that has to hold for ``paths`` as well: ``paths = []`` means "look
    nowhere", not "fall back to the built-in list I just tried to replace".
    """
    if "paths" in raw:
        declared = raw["paths"] if isinstance(raw["paths"], list) else []
        paths = tuple(
            PathSpec(
                path=p["path"],
                fmt=p.get("fmt", "opaque"),
                role=p.get("role", "config"),
                env=p.get("env"),
                root_env=p.get("root_env"),
                rel=p.get("rel"),
                select=p.get("select"),
                marker=p.get("marker", False),
                multi=p.get("multi", False),
                identities=p.get("identities"),
            )
            for p in declared
            if isinstance(p, dict) and "path" in p
        )
    else:
        paths = base.paths if base else ()

    probe = base.probe if base else None
    if isinstance(raw.get("probe"), dict):
        probe = _probe_from_toml(raw["probe"])

    bloat = base.bloat if base else ()
    if isinstance(raw.get("bloat"), list):
        bloat = _bloat_from_toml(raw["bloat"])

    def inherit(key: str, fallback):
        if key in raw:
            return raw[key]
        return getattr(base, key) if base else fallback

    return Store(
        id=sid,
        name=str(inherit("name", sid)),
        kind=str(inherit("kind", "misc")),
        paths=paths,
        aliases=tuple(_as_list(inherit("aliases", ()))),
        secret_fields=frozenset(_as_list(inherit("secret_fields", frozenset()))),
        id_fields=frozenset(_as_list(inherit("id_fields", frozenset()))),
        probe=probe,
        bloat=bloat,
        docs=str(inherit("docs", "")),
        note=str(inherit("note", "")),
        fix=str(inherit("fix", "")),
    )


def load() -> tuple[Store, ...]:
    """Built-in stores, with any user overlay merged over them by id."""
    global OVERLAY_WARNING
    OVERLAY_WARNING = ""

    stores = {s.id: s for s in BUILTIN}
    path = overlay_path()
    if not path.is_file():
        return tuple(stores.values())

    unsafe = _unsafe_overlay(path)
    if unsafe:
        OVERLAY_WARNING = unsafe
        return tuple(stores.values())

    try:
        # Read bytes and let tomllib decode: a file that is not UTF-8 raises
        # UnicodeDecodeError, and read_text() raised it out here where nothing
        # caught it, so one stray byte crashed every command.
        with path.open("rb") as handle:
            doc = tomllib.load(handle)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return tuple(stores.values())

    for sid, raw in doc.items():
        if not isinstance(raw, dict):
            continue
        store = _store_from_toml(sid, raw, stores.get(sid))
        # A store with nowhere to look is meaningless, whether it is new or an
        # override that dropped the inherited paths with `paths = []`. Drop it
        # entirely rather than keep a store that can never be found.
        if not store.paths:
            stores.pop(sid, None)
            continue
        stores[sid] = store
    return tuple(stores.values())


def find(stores: tuple[Store, ...], query: str) -> list[Store]:
    """Fuzzy lookup by id, alias, name or kind — ranked exact-first."""
    q = query.strip().lower()
    # An empty query is a substring of every id, so it used to match the whole
    # registry. Nothing is a better answer than everything.
    if not q:
        return []
    exact = [s for s in stores if q == s.id or q in s.aliases]
    partial = [
        s
        for s in stores
        if s not in exact
        and (
            q in s.id
            or q in s.name.lower()
            or q == s.kind
            or any(q in a for a in s.aliases)
        )
    ]
    return exact + partial
