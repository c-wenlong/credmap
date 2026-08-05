"""Registry semantics: marker files, env overrides, lookup, and the TOML overlay."""

from __future__ import annotations

import os

import pytest

from credmap.doctor import diagnose
from credmap.model import PathSpec
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
    assert not result_for("pulumi").found


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
    stores = load()
    acme = next((s for s in stores if s.id == "acme"), None)
    assert acme is not None
    assert acme.paths[0].marker
    assert find(stores, "acme-corp")[0].id == "acme"


def test_broken_overlay_is_ignored_not_fatal(fake_home):
    overlay = config_home() / "credmap/registry.toml"
    overlay.parent.mkdir(parents=True, exist_ok=True)
    overlay.write_text("this is not [ valid toml", encoding="utf-8")
    assert len(load()) > 0


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
