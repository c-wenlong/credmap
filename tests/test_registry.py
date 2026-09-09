"""Registry semantics: marker files, env overrides, lookup, and the TOML overlay."""

from __future__ import annotations

import os
import textwrap

import pytest

from credmap import registry
from credmap.doctor import diagnose
from credmap.redact import is_secret
from credmap.registry import find, load
from credmap.resolve import config_home, resolve
from credmap.scan import scan, scan_store


def result_for(sid: str):
    return scan_store(next(s for s in load() if s.id == sid))


# --------------------------------------------------------------------------
# marker semantics
# --------------------------------------------------------------------------


def test_directory_without_marker_is_not_found(fake_home):
    """~/.azure exists (VS Code made it) but holds no credential."""
    assert (fake_home / ".azure").is_dir()
    assert not result_for("azure").found


def test_marker_present_means_found(fake_home):
    assert result_for("aws").found
    assert result_for("gcloud").found


def test_absent_store_is_not_found(fake_home):
    # vault, not pulumi: the fixture home now carries a ~/.pulumi holding a
    # bare-scalar credential, which the whole-file-scalar leak test needs.
    assert not result_for("vault").found


# --------------------------------------------------------------------------
# path resolution
# --------------------------------------------------------------------------


def test_env_var_relocates_a_store(fake_home, monkeypatch, tmp_path):
    elsewhere = tmp_path / "elsewhere/credentials"
    elsewhere.parent.mkdir(parents=True)
    elsewhere.write_text("[moved]\naws_access_key_id = AKIAFAKE\n", encoding="utf-8")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(elsewhere))

    result = result_for("aws")
    assert "moved" in {p.name for p in result.profiles}


def test_root_env_relocates_a_whole_store(fake_home, monkeypatch, tmp_path):
    monkeypatch.setenv("CLOUDSDK_CONFIG", str(tmp_path / "nowhere"))
    assert not result_for("gcloud").found


def test_xdg_config_home_is_honoured(fake_home, monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    assert config_home() == tmp_path / "xdg"
    assert not result_for("gh").found, "gh lives under XDG config"


def test_kubeconfig_accepts_a_path_list(fake_home, monkeypatch, tmp_path):
    second = tmp_path / "second.yaml"
    second.write_text("apiVersion: v1\ncontexts: []\n", encoding="utf-8")
    monkeypatch.setenv(
        "KUBECONFIG", os.pathsep.join([str(fake_home / ".kube/config"), str(second)])
    )
    spec = next(s for s in load() if s.id == "kube").paths[0]
    assert len(resolve(spec)) == 2


# --------------------------------------------------------------------------
# lookup
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "query,expected",
    [
        ("gcp", "gcloud"),
        ("aws", "aws"),
        ("k8s", "kube"),
        ("github", "gh"),
        ("hf", "huggingface"),
    ],
)
def test_alias_lookup_prefers_exact(query, expected):
    matches = find(load(), query)
    assert matches and matches[0].id == expected


def test_unknown_query_returns_nothing():
    assert find(load(), "definitely-not-a-provider") == []


@pytest.mark.parametrize("query", ["", "   ", "\t\n"])
def test_an_empty_query_matches_nothing(query):
    """It is a substring of every id, so it used to match the whole registry."""
    assert find(load(), query) == []


def test_kind_lookup_returns_a_group():
    ids = {s.id for s in find(load(), "cloud")}
    assert {"aws", "gcloud", "azure"} <= ids


# --------------------------------------------------------------------------
# overlay
# --------------------------------------------------------------------------


def test_toml_overlay_adds_a_store(fake_home):
    overlay = config_home() / "credmap/registry.toml"
    overlay.parent.mkdir(parents=True, exist_ok=True)
    overlay.write_text(
        """
        [acme]
        name = "ACME"
        kind = "cloud"
        aliases = ["acme-corp"]

          [[acme.paths]]
          path = "~/.acme/creds.json"
          fmt = "json"
          role = "secrets"
          marker = true
        """,
        encoding="utf-8",
    )
    overlay.chmod(0o600)
    overlay.parent.chmod(0o700)
    stores = load()
    acme = next((s for s in stores if s.id == "acme"), None)
    assert acme is not None
    assert acme.paths[0].marker
    assert find(stores, "acme-corp")[0].id == "acme"


def test_broken_overlay_is_ignored_not_fatal(fake_home):
    overlay = config_home() / "credmap/registry.toml"
    overlay.parent.mkdir(parents=True, exist_ok=True)
    overlay.write_text("this is not [ valid toml", encoding="utf-8")
    overlay.chmod(0o600)
    overlay.parent.chmod(0o700)
    assert len(load()) > 0


def write_overlay(text: str, mode: int = 0o600, dir_mode: int = 0o700) -> None:
    overlay = config_home() / "credmap/registry.toml"
    overlay.parent.mkdir(parents=True, exist_ok=True)
    overlay.write_text(textwrap.dedent(text), encoding="utf-8")
    # Both modes are set explicitly, because load() refuses an overlay anyone
    # else can write — file or directory — and what write_text and mkdir leave
    # behind depends on the developer's umask. A machine with umask 002 would
    # otherwise fail every overlay test here for a reason unrelated to the test.
    overlay.chmod(mode)
    overlay.parent.chmod(dir_mode)


def write_overlay_bytes(data: bytes, mode: int = 0o600) -> None:
    overlay = config_home() / "credmap/registry.toml"
    overlay.parent.mkdir(parents=True, exist_ok=True)
    overlay.write_bytes(data)
    overlay.chmod(mode)
    overlay.parent.chmod(0o700)


def store(sid: str):
    return next(s for s in load() if s.id == sid)


def test_overriding_a_builtin_keeps_what_it_did_not_mention(fake_home):
    """Renaming aws must not silently drop its probe, fields or docs."""
    builtin = store("aws")
    write_overlay('[aws]\nname = "Work AWS"\n')

    overridden = store("aws")
    assert overridden.name == "Work AWS"
    assert overridden.probe == builtin.probe
    assert overridden.secret_fields == builtin.secret_fields
    assert overridden.id_fields == builtin.id_fields
    assert overridden.paths == builtin.paths
    assert overridden.docs == builtin.docs


def test_overlay_can_declare_a_probe(fake_home):
    write_overlay(
        """
        [acme]
        name = "ACME"

          [acme.probe]
          argv = ["acme", "whoami", "--profile", "{profile}"]
          extract = "Account"
          timeout = 3

          [[acme.paths]]
          path = "~/.acme/creds.json"
          fmt = "json"
          role = "secrets"
          marker = true
        """
    )
    probe = store("acme").probe
    assert probe is not None
    assert probe.argv == ("acme", "whoami", "--profile", "{profile}")
    assert probe.extract == "Account" and probe.timeout == 3


def test_overlay_can_declare_identities_and_bloat(fake_home):
    write_overlay(
        """
        [acme]
        name = "ACME"

          [[acme.bloat]]
          path = "~/.acme/logs"
          threshold_mb = 250

          [[acme.paths]]
          path = "~/.acme/config"
          fmt = "ini"
          role = "config"
          marker = true
          identities = true
        """
    )
    acme = store("acme")
    assert acme.bloat == (("~/.acme/logs", 250),)
    assert acme.paths[0].has_identities(), "a config path can opt into probing"


def test_overlay_can_drop_a_probe_explicitly(fake_home):
    """Inheritance must not make removal impossible."""
    write_overlay("[aws]\nprobe = {}\n")
    assert store("aws").probe is None


def test_new_store_still_requires_paths(fake_home):
    write_overlay('[ghost]\nname = "Nowhere"\n')
    assert not any(s.id == "ghost" for s in load())


def test_an_empty_paths_list_drops_the_inherited_paths(fake_home):
    """"Assign an empty value to remove an inherited one" has to hold here too.

    It used to fall back to the built-in list, so the one key you would reach
    for to stop credmap looking at a store was the one key with no effect. A
    store left with nowhere to look is dropped: keeping it would put a store
    in the registry that can never be found.
    """
    write_overlay("[aws]\npaths = []\n")
    assert not any(s.id == "aws" for s in load())


def test_omitting_paths_still_inherits_them(fake_home):
    """Absent is not empty: mentioning nothing must change nothing."""
    builtin = store("aws")
    write_overlay('[aws]\nname = "Work AWS"\n')
    assert store("aws").paths == builtin.paths


def test_replacing_paths_replaces_them_wholesale(fake_home):
    write_overlay(
        """
        [aws]
        [[aws.paths]]
        path = "~/.aws-elsewhere/credentials"
        fmt = "ini"
        role = "secrets"
        marker = true
        """
    )
    paths = store("aws").paths
    assert len(paths) == 1 and paths[0].path == "~/.aws-elsewhere/credentials"


def test_a_bare_string_is_one_value_not_one_per_character(fake_home):
    """`aliases = "acme"` used to become the four aliases a, c, m and e."""
    write_overlay(
        """
        [acme]
        aliases = "acme-corp"
        secret_fields = "api_token"
        id_fields = "account_id"

          [[acme.paths]]
          path = "~/.acme/creds.json"
          fmt = "json"
          role = "secrets"
          marker = true
        """
    )
    acme = store("acme")
    assert acme.aliases == ("acme-corp",)
    assert acme.secret_fields == frozenset({"api_token"})
    assert acme.id_fields == frozenset({"account_id"})


def test_a_non_utf8_overlay_is_ignored_not_fatal(fake_home):
    """One stray byte in the file used to crash every command."""
    write_overlay_bytes(b'[aws]\nname = "Caf\xe9 AWS"\n')
    stores = load()
    assert any(s.id == "aws" for s in stores)
    assert store("aws").name == "AWS CLI"


def test_a_group_writable_overlay_is_refused(fake_home):
    """Another local user could name any file to read and any argv to run."""
    write_overlay('[aws]\nname = "Work AWS"\n', mode=0o664)
    assert store("aws").name == "AWS CLI"
    assert "writable by group" in registry.OVERLAY_WARNING
    assert "mode 0664 is writable" in registry.OVERLAY_WARNING


def test_an_owner_only_overlay_leaves_no_warning(fake_home):
    write_overlay('[aws]\nname = "Work AWS"\n', mode=0o600)
    assert store("aws").name == "Work AWS"
    assert registry.OVERLAY_WARNING == ""


@pytest.mark.parametrize("dir_mode", [0o775, 0o707, 0o777])
def test_a_group_or_world_writable_overlay_directory_is_refused(fake_home, dir_mode):
    """Write on the directory is permission to unlink the 0600 file and recreate it."""
    write_overlay('[aws]\nname = "Work AWS"\n', mode=0o600, dir_mode=dir_mode)
    try:
        assert store("aws").name == "AWS CLI"
        assert "writable by group or others" in registry.OVERLAY_WARNING
        # The message must name the directory, not the file that is fine.
        assert f"its directory ~/.config/credmap has mode {dir_mode:04o}" in (
            registry.OVERLAY_WARNING
        )
    finally:
        (config_home() / "credmap").chmod(0o700)


def test_a_0755_overlay_directory_is_fine(fake_home):
    """0755 is the ordinary mode mkdir leaves; only *write* bits are a problem."""
    write_overlay('[aws]\nname = "Work AWS"\n', mode=0o600, dir_mode=0o755)
    try:
        assert store("aws").name == "Work AWS"
        assert registry.OVERLAY_WARNING == ""
    finally:
        (config_home() / "credmap").chmod(0o700)


# --------------------------------------------------------------------------
# curated fields
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field", ["credential_process", "web_identity_token_file", "role_session_name"]
)
def test_aws_identifiers_stay_visible(field):
    """A command, a file path and a label. None of them can hold key material."""
    assert not is_secret(field, next(s for s in load() if s.id == "aws"))


# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------


def test_doctor_flags_a_reused_secret(fake_home):
    findings = diagnose(scan(load()))
    dupes = [f for f in findings if "shared by" in f.message]
    assert dupes, "the same key in two profiles should be reported once"
    assert "duplicate-of-default" in dupes[0].message


def test_doctor_flags_loose_permissions(fake_home):
    findings = diagnose(scan(load()))
    assert any("0644" in f.message and "credentials" in f.message for f in findings)


def test_doctor_flags_incomplete_sso(fake_home):
    findings = diagnose(scan(load()))
    assert any("never completed" in f.message for f in findings)


def test_doctor_reports_keychain_as_info_not_a_problem(fake_home):
    findings = diagnose(scan(load()))
    keychain = [f for f in findings if "Keychain" in f.message]
    assert keychain and all(f.level == "info" for f in keychain)


def test_doctor_ignores_stores_that_are_not_present(fake_home):
    findings = diagnose(scan(load()))
    assert not any(f.store == "azure" for f in findings)


def test_doctor_reports_a_parse_error_with_no_note(fake_home):
    """A file can fail to parse and have nothing else to say about itself.

    The error used to be reported only when a note happened to exist beside
    it, so the most broken files were the quietest.
    """
    (fake_home / ".kube/config").write_text("{{{ not yaml", encoding="utf-8")
    findings = [f for f in diagnose(scan(load())) if f.store == "kube"]
    broken = [f for f in findings if "unparsable YAML" in f.message]
    assert broken, "an unparsable file must be reported on its own"
    assert broken[0].level == "warn"
    assert "config" in broken[0].message, "say which file"
