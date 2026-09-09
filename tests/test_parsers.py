"""Parser behaviour, one test per format plus the rules that are easy to break."""

from __future__ import annotations

import os
import sqlite3
import urllib.parse
from pathlib import Path

import pytest

from credmap.model import EXPIRED, PathSpec
from credmap.parsers import parse_ini, parse_sqlite_gcloud
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
    assert found.error, "a broken file should explain itself, not crash the scan"


def test_failure_lands_in_error_not_note(fake_home):
    """The two channels are distinct: prose must not decide severity."""
    (fake_home / ".kube/config").write_text("{{{ not yaml", encoding="utf-8")
    found = next(fp for fp in result_for("kube").paths if fp.exists)
    assert "unparsable YAML" in found.error
    assert found.note == "", "a parse failure is not a note"


def test_context_lands_in_note_not_error(fake_home):
    """The converse: a healthy store with something to say sets no error."""
    docker = next(fp for fp in result_for("docker").paths if fp.exists)
    assert "Keychain" in docker.note
    assert not docker.error


def test_partial_read_keeps_what_it_parsed():
    """A parser that fails midway still reports the profiles it did get."""
    from credmap.model import Profile
    from credmap.parsers import ParseResult, _fail

    partial = _fail("query failed: no such column", [Profile(name="someone")])
    assert partial.error == "query failed: no such column"
    assert [p.name for p in partial.profiles] == ["someone"]
    assert ParseResult().profiles == []


def test_scan_covers_every_registered_store(fake_home):
    results = scan(load())
    assert len(results) == len(load())


# --------------------------------------------------------------------------
# unreadable files (issue 6) and hostile paths (issues 7, 25)
# --------------------------------------------------------------------------

INI_SPEC = PathSpec(path="~/.aws/credentials", fmt="ini", role="secrets")
SQLITE_SPEC = PathSpec(path="{config}/gcloud/credentials.db", fmt="sqlite-gcloud")

_UNREADABLE_SENTINEL = "FAKE-unreadable-ini-secret-0123456789"


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root reads a mode-000 file regardless of its mode",
)
def test_permission_denied_ini_is_an_error_not_an_empty_file(tmp_path):
    """`ConfigParser.read` swallows OSError; an empty result would be a lie."""
    path = tmp_path / "credentials"
    path.write_text(
        f"[default]\naws_secret_access_key = {_UNREADABLE_SENTINEL}\n",
        encoding="utf-8",
    )
    path.chmod(0o000)
    try:
        result = parse_ini(path, INI_SPEC)
    finally:
        path.chmod(0o600)  # so tmp_path cleanup can remove it

    assert result.profiles == []
    assert "unreadable INI" in result.error
    assert "PermissionError" in result.error
    assert _UNREADABLE_SENTINEL not in result.error


def test_undecodable_ini_is_an_error_that_quotes_nothing(tmp_path):
    path = tmp_path / "credentials"
    path.write_bytes(b"[default]\naws_secret_access_key = \xff\xfe\n")
    result = parse_ini(path, INI_SPEC)
    assert result.profiles == []
    assert "unreadable INI" in result.error
    assert "UnicodeDecodeError" in result.error


def test_readable_ini_still_parses(tmp_path):
    path = tmp_path / "credentials"
    path.write_text("[default]\nregion = eu-north-1\n", encoding="utf-8")
    result = parse_ini(path, INI_SPEC)
    assert not result.error
    assert [p.name for p in result.profiles] == ["default"]
    assert result.profiles[0].fields["region"] == "eu-north-1"


def _gcloud_db(path: Path, account: str) -> Path:
    """The two tables `parse_sqlite_gcloud` looks for, same schema as conftest."""
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE credentials (account_id TEXT PRIMARY KEY, value BLOB)")
    con.execute("INSERT INTO credentials VALUES (?, ?)", (account, b"fake"))
    con.execute(
        "CREATE TABLE access_tokens (account_id TEXT PRIMARY KEY,"
        " access_token TEXT, token_expiry TIMESTAMP)"
    )
    con.commit()
    con.close()
    return path


def test_sqlite_path_with_query_and_fragment_still_opens(tmp_path):
    """`?` and `#` in a CLOUDSDK_CONFIG path are path characters, not URI syntax.

    This one did not fail closed. `file:.../cfg?v=1#frag/credentials.db?mode=ro`
    parses as path `.../cfg` with the real `mode=ro` stranded in the fragment,
    so SQLite fell back to read-write-create and *created* a database at the
    truncation point — a write, from a tool that has no write path.
    """
    root = tmp_path / "cfg?v=1#frag"
    db = _gcloud_db(root / "credentials.db", "someone@example.com")
    result = parse_sqlite_gcloud(db, SQLITE_SPEC)
    assert not result.error
    assert [p.name for p in result.profiles] == ["someone@example.com"]
    assert [p.name for p in tmp_path.iterdir()] == [root.name], "scan created a file"


def test_sqlite_path_percent_escape_is_not_decoded(tmp_path):
    """SQLite percent-decodes a URI, so `%41` must not become `A` and open a peer."""
    real = _gcloud_db(tmp_path / "st%41ge" / "credentials.db", "real@example.com")
    _gcloud_db(tmp_path / "stAge" / "credentials.db", "decoy@example.com")
    result = parse_sqlite_gcloud(real, SQLITE_SPEC)
    assert not result.error
    assert [p.name for p in result.profiles] == ["real@example.com"]


def test_sqlite_stays_read_only_on_an_escaped_path(tmp_path):
    db = _gcloud_db(tmp_path / "st%41ge ? #" / "credentials.db", "someone@example.com")
    uri = "file:" + urllib.parse.quote(str(db), safe="/") + "?mode=ro"
    con = sqlite3.connect(uri, uri=True)
    try:
        with pytest.raises(sqlite3.OperationalError):
            con.execute("delete from credentials")
    finally:
        con.close()
