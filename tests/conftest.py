"""A synthetic home directory covering every format the registry can parse.

Fixtures are generated rather than committed: nothing in this repo should look
like a credential file, to a human or to a secret scanner. Every value below is
obviously fake and the constants are asserted against in the leak test.

The provider prefixes are deliberately broken -- ``ghox_`` and ``hfx_`` rather
than ``gho_`` and ``hf_`` -- so that gitleaks, trufflehog and GitHub push
protection do not match this file. The lengths are kept, because what these
sentinels exercise is masking, and masking is a function of length.
"""

from __future__ import annotations

import json
import sqlite3
import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path

from credmap.registry import BUILTIN


def override_vars() -> tuple[str, ...]:
    """Every environment variable that can relocate a store, plus the XDG roots.

    Derived from the registry so it cannot fall behind a newly added ``Store``.
    """
    found = {"XDG_CONFIG_HOME", "XDG_CACHE_HOME"}
    for store in BUILTIN:
        for spec in store.paths:
            found.update(v for v in (spec.env, spec.root_env) if v)
    return tuple(sorted(found))

import pytest

# Sentinels. If any of these ever reaches default output, the leak test fails.
AWS_SECRET = "FAKEwJalrXUtnFEMIKAAABBBCCCDDDEEEFFFGGGH"  # 40 chars, like a real one
GH_TOKEN = "ghox_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE000"  # length of a real one, prefix broken
NETRC_PASSWORD = "FAKE-netrc-password-0123456789"
HF_TOKEN = "hfx_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0"  # length of a real one, prefix broken
ADC_REFRESH = "1//FAKE-refresh-token-abcdefghijklmnop"

# Sentinels that live in a *parseable* field, so `show --reveal` can print them.
AWS_CONTINUED = "FAKE-folded-onto-the-previous-key-01234"
PULUMI_TOKEN = "FAKE-pulumi-whole-file-scalar-0123456789"
FLY_TOKEN = "FAKE-fly-whole-file-scalar-0123456789"

# Sentinels that only ever exist inside a file that fails to parse. Nothing
# can reveal these: the parser produced no field to hold them, and the error
# message that mentions the file must not quote it. They belong to the leak
# test only.
PYPI_BROKEN = "FAKE-pypi-secret-on-the-broken-line-0123"
DOCTL_BROKEN = "FAKE-doctl-secret-broken-line-0123"
AUTHINFO_BROKEN = "FAKE-authinfo-secret-broken-line-0123"

REVEALABLE_SECRETS = (
    AWS_SECRET,
    GH_TOKEN,
    NETRC_PASSWORD,
    HF_TOKEN,
    ADC_REFRESH,
    AWS_CONTINUED,
    PULUMI_TOKEN,
    FLY_TOKEN,
)
UNPARSED_SECRETS = (PYPI_BROKEN, DOCTL_BROKEN, AUTHINFO_BROKEN)

ALL_SECRETS = REVEALABLE_SECRETS + UNPARSED_SECRETS

AWS_KEY_ID = "AKIAFAKEFAKEFAKEFAKE"  # an identifier — must stay visible


def _iso(delta_days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=delta_days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _write(path: Path, text: str, mode: int = 0o600) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    path.chmod(mode)
    return path


@pytest.fixture
def fake_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    # Ensure no real env override leaks into the test. The list is derived from
    # the registry rather than written out, because a hand-maintained copy drifts:
    # it silently omitted AZURE_CONFIG_DIR and GNUPGHOME, so a developer with
    # either one set got different results for those two stores.
    for var in override_vars():
        monkeypatch.delenv(var, raising=False)

    config = home / ".config"
    cache = home / ".cache"

    # --- AWS: duplicate key across two profiles, plus an SSO session block ---
    _write(
        home / ".aws/credentials",
        f"""
        [default]
        aws_access_key_id = {AWS_KEY_ID}
        aws_secret_access_key = {AWS_SECRET}

        [duplicate-of-default]
        aws_access_key_id = {AWS_KEY_ID}
        aws_secret_access_key = {AWS_SECRET}

        [indented-continuation]
        aws_access_key_id = {AWS_KEY_ID}
          aws_secret_access_key = {AWS_CONTINUED}
        """,
        mode=0o644,  # deliberately loose, for the permission check
    )
    _write(
        home / ".aws/config",
        """
        [default]
        region = eu-north-1

        [profile with-sso]
        sso_session = corp
        sso_account_id = 000000000000

        [sso-session corp]
        sso_start_url = https://example.awsapps.com/start/
        """,
    )
    # SSO cache holding *only* a client registration: a login that never finished.
    _write(
        home / ".aws/sso/cache/abc123.json",
        json.dumps(
            {"clientId": "fake-client", "clientSecret": "FAKE", "expiresAt": _iso(30)}
        ),
    )

    # --- gcloud: SQLite, not JSON ---
    gdir = config / "gcloud"
    gdir.mkdir(parents=True)
    con = sqlite3.connect(gdir / "credentials.db")
    con.execute("CREATE TABLE credentials (account_id TEXT PRIMARY KEY, value BLOB)")
    con.executemany(
        "INSERT INTO credentials VALUES (?, ?)",
        [("someone@example.com", b"fake"), ("robot@example.iam.gserviceaccount.com", b"fake")],
    )
    con.commit()
    con.close()

    con = sqlite3.connect(gdir / "access_tokens.db")
    con.execute(
        "CREATE TABLE access_tokens (account_id TEXT PRIMARY KEY,"
        " access_token TEXT, token_expiry TIMESTAMP)"
    )
    con.executemany(
        "INSERT INTO access_tokens VALUES (?, ?, ?)",
        [
            ("someone@example.com", "fake", _iso(-5)),  # expired
            ("deadbeef" * 8, "fake", _iso(-9)),  # opaque id — must be summarised
        ],
    )
    con.commit()
    con.close()

    _write(gdir / "configurations/config_default", "[core]\nproject = fake-project\n")
    _write(
        gdir / "application_default_credentials.json",
        json.dumps(
            {
                "type": "authorized_user",
                "client_id": "fake.apps.googleusercontent.com",
                "client_secret": "FAKE-client-secret",
                "refresh_token": ADC_REFRESH,
                "quota_project_id": "fake-project",
            }
        ),
    )

    # --- azure: the false positive. Directory exists, marker file does not. ---
    (home / ".azure/ms-azuretools.vscode-azureresourcegroups").mkdir(parents=True)

    # --- docker: secrets delegated to a credential helper ---
    _write(
        home / ".docker/config.json",
        json.dumps({"auths": {}, "credsStore": "desktop"}),
    )

    # --- kube: contexts as a list of dicts ---
    _write(
        home / ".kube/config",
        """
        apiVersion: v1
        kind: Config
        current-context: alpha
        contexts:
          - name: alpha
            context:
              cluster: alpha-cluster
              user: alpha-user
          - name: beta
            context:
              cluster: beta-cluster
              user: beta-user
        """,
    )

    # --- gh: root-keyed mapping ---
    _write(
        config / "gh/hosts.yml",
        f"""
        github.com:
            user: fakeuser
            oauth_token: {GH_TOKEN}
            git_protocol: ssh
        """,
    )

    # --- netrc ---
    _write(
        home / ".netrc",
        f"""
        machine api.example.com
          login fakeuser
          password {NETRC_PASSWORD}
        """,
    )

    # --- authinfo: malformed netrc. NetrcParseError repr's the token it could
    # not place, which is the password when the line above it is broken.
    _write(
        home / ".authinfo",
        f"""
        machine api.example.com
          login fakeuser
          {AUTHINFO_BROKEN}
        """,
    )

    # --- ssh key directory ---
    _write(home / ".ssh/id_ed25519.pub", "ssh-ed25519 AAAAFAKEKEY fake@example.com\n", 0o644)
    _write(home / ".ssh/id_ed25519", "FAKE PRIVATE KEY\n")
    (home / ".ssh").chmod(0o700)

    # --- huggingface: a bare token file ---
    _write(cache / "huggingface/token", HF_TOKEN + "\n")

    # --- pulumi: the whole file is one JSON scalar, with no key to judge ---
    _write(home / ".pulumi/credentials.json", json.dumps(PULUMI_TOKEN))

    # --- fly: the whole file is one YAML scalar ---
    _write(home / ".fly/config.yml", FLY_TOKEN + "\n")

    # --- pypi: malformed INI, secret on the line configparser complains about.
    # No section header, so MissingSectionHeaderError quotes the whole line.
    _write(
        home / ".pypirc",
        f"""
        password = {PYPI_BROKEN}
        [pypi]
        username = fakeuser
        """,
    )

    # --- doctl: malformed YAML, secret on the line the mark points at.
    # A literal tab is a classic hand-edit failure, and PyYAML's mark quotes
    # the whole offending line back at you, sentinel included.
    _write(
        config / "doctl/config.yaml",
        f"access-token:\t{DOCTL_BROKEN}\ncontext: default\n",
    )

    return home
