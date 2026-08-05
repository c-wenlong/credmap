"""Parser behaviour, one test per format plus the rules that are easy to break."""

from __future__ import annotations

import pytest

from credmap.model import EXPIRED
from credmap.registry import find, load
from credmap.scan import scan, scan_store


def result_for(sid: str):
    stores = [s for s in load() if s.id == sid]
    assert stores, f"no store {sid} in registry"
    return scan_store(stores[0])


def profile_names(result) -> set[str]:
    return {p.name for p in result.profiles}


# --------------------------------------------------------------------------
# ini
# --------------------------------------------------------------------------


def test_ini_normalises_aws_section_prefixes(fake_home):
    result = result_for("aws")
    names = profile_names(result)
    assert "default" in names
    assert "with-sso" in names, "'[profile with-sso]' should drop the prefix"
    assert "corp" in names, "'[sso-session corp]' should drop the prefix"
    assert "profile with-sso" not in names


def test_sso_session_is_marked_as_not_a_profile(fake_home):
    result = result_for("aws")
    corp = next(p for p in result.profiles if p.name == "corp")
    assert corp.detail == "sso-session"


def test_aws_config_declares_identities(fake_home):
    """SSO profiles live in config, so it must opt into liveness probing."""
    result = result_for("aws")
    config = next(fp for fp in result.paths if fp.path.name == "config")
    assert config.spec.has_identities()


# --------------------------------------------------------------------------
# json
# --------------------------------------------------------------------------


def test_docker_credshelper_produces_note_not_profiles(fake_home):
    result = result_for("docker")
    assert result.found, "an empty auths block still means docker is configured"
    assert result.profiles == []
    assert any("Keychain" in n for n in result.notes)


def test_adc_named_from_its_type_not_the_filename(fake_home):
    result = result_for("gcloud-adc")
    assert profile_names(result) == {"authorized_user"}


# --------------------------------------------------------------------------
# yaml
# --------------------------------------------------------------------------


def test_kube_contexts_are_a_list_of_dicts(fake_home):
    result = result_for("kube")
    assert profile_names(result) == {"alpha", "beta"}
    assert any("alpha" in n for n in result.notes), "current-context should surface"


def test_gh_hosts_are_root_keys(fake_home):
    result = result_for("gh")
    assert profile_names(result) == {"github.com"}


# --------------------------------------------------------------------------
# sqlite
# --------------------------------------------------------------------------


def test_gcloud_reads_accounts_from_sqlite(fake_home):
    result = result_for("gcloud")
    names = profile_names(result)
    assert "someone@example.com" in names
    assert "robot@example.iam.gserviceaccount.com" in names


def test_gcloud_summarises_opaque_token_ids(fake_home):
    """Hash-keyed cache rows are noise and must not appear as profiles."""
    result = result_for("gcloud")
    assert not any("deadbeef" in n for n in profile_names(result))
    assert any("opaque id" in n for n in result.notes)


def test_gcloud_expiry_detected_offline(fake_home):
    result = result_for("gcloud")
    someone = next(p for p in result.profiles if p.name == "someone@example.com")
    assert someone.status == EXPIRED


# --------------------------------------------------------------------------
# jsondir / netrc / keydir / raw
# --------------------------------------------------------------------------


def test_registration_only_sso_cache_is_flagged(fake_home):
    result = result_for("aws")
    cache = next(fp for fp in result.paths if fp.path.name == "cache" and fp.exists)
    assert "never completed" in cache.note


def test_netrc_machines_become_profiles(fake_home):
    result = result_for("netrc")
    assert profile_names(result) == {"api.example.com"}


def test_keydir_pairs_public_with_private(fake_home):
    result = result_for("ssh")
    key = next(p for p in result.profiles if p.name == "id_ed25519")
    assert key.fields["type"] == "ssh-ed25519"
    assert key.fields["private_key_present"] is True


def test_raw_token_file(fake_home):
    result = result_for("huggingface")
    assert profile_names(result) == {"token"}


# --------------------------------------------------------------------------
# robustness
# --------------------------------------------------------------------------


def test_malformed_file_does_not_raise(fake_home):
    (fake_home / ".kube/config").write_text("{{{ not yaml", encoding="utf-8")
    result = result_for("kube")
    found = next(fp for fp in result.paths if fp.exists)
    assert found.profiles == []
    assert found.note, "a broken file should explain itself, not crash the scan"


def test_scan_covers_every_registered_store(fake_home):
    results = scan(load())
    assert len(results) == len(load())
