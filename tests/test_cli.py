"""CLI surface: default verb, exit codes, JSON validity."""

from __future__ import annotations

import json

import pytest

from credmap.cli import main

from .conftest import ALL_SECRETS


def run(capsys, *argv) -> tuple[int, str]:
    code = main(list(argv))
    return code, capsys.readouterr().out


def run_err(capsys, *argv) -> tuple[int, str, str]:
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def write_overlay(home, text: str, mode: int = 0o600, dir_mode: int = 0o700) -> None:
    """An overlay at the mode we mean, not the mode the umask happened to give.

    Both the file and its directory are set explicitly: the loader refuses an
    overlay whose *directory* is group-writable, and a developer running with
    umask 002 gets 0775 out of ``mkdir``. Leaving that to chance made this
    helper pass on CI and fail on such a machine.
    """
    overlay = home / ".config/credmap/registry.toml"
    overlay.parent.mkdir(parents=True, exist_ok=True)
    overlay.write_text(text, encoding="utf-8")
    overlay.chmod(mode)
    overlay.parent.chmod(dir_mode)


def test_bare_invocation_defaults_to_scan(fake_home, capsys):
    code, out = run(capsys)
    assert code == 0
    assert "AWS CLI" in out


def test_flags_work_without_naming_the_default_verb(fake_home, capsys):
    code, out = run(capsys, "--all")
    assert code == 0
    assert "not found" in out


def test_where_locates_a_provider(fake_home, capsys):
    code, out = run(capsys, "where", "gcp")
    assert code == 0
    assert "credentials.db" in out


def test_where_rejects_an_unknown_provider(fake_home, capsys):
    assert run(capsys, "where", "nonsense-provider")[0] == 2


def test_show_masks_by_default(fake_home, capsys):
    code, out = run(capsys, "show", "aws")
    assert code == 0
    assert "<redacted" in out
    assert not any(secret in out for secret in ALL_SECRETS)


def test_doctor_exits_nonzero_only_on_errors(fake_home, capsys):
    """Offline, this fixture has warnings but nothing provably dead."""
    code, _ = run(capsys, "doctor")
    assert code == 0


@pytest.mark.parametrize(
    "argv",
    [
        ("scan", "--json"),
        ("paths", "--json"),
        ("doctor", "--json"),
        ("where", "aws", "--json"),
    ],
)
def test_json_output_parses(fake_home, capsys, argv):
    code, out = run(capsys, *argv)
    assert code in (0, 1)
    json.loads(out)


def test_json_scan_reports_found_flag(fake_home, capsys):
    _, out = run(capsys, "scan", "--json", "--all")
    payload = {entry["id"]: entry for entry in json.loads(out)}
    assert payload["aws"]["found"] is True
    assert payload["azure"]["found"] is False


def test_paths_lists_absent_paths_too(fake_home, capsys):
    _, out = run(capsys, "paths")
    assert "pulumi" in out


# --------------------------------------------------------------------------
# the missing verb
# --------------------------------------------------------------------------


def test_a_provider_name_alone_means_where(fake_home, capsys):
    """`credmap aws` used to become `scan aws` and die on argparse."""
    code, out = run(capsys, "aws")
    assert code == 0
    assert ".aws/credentials" in out


def test_an_alias_alone_means_where(fake_home, capsys):
    code, out = run(capsys, "gcp")
    assert code == 0
    assert "credentials.db" in out


def test_a_provider_name_keeps_its_flags(fake_home, capsys):
    code, out = run(capsys, "aws", "--json")
    assert code == 0
    assert [entry["id"] for entry in json.loads(out)] == ["aws"]


def test_an_unknown_first_token_is_still_rejected(fake_home, capsys):
    """Falling through to `where` for everything would hide a typo."""
    with pytest.raises(SystemExit) as exc:
        main(["definitely-not-a-provider"])
    assert exc.value.code == 2


def test_a_bare_flag_still_means_scan(fake_home, capsys):
    code, out = run(capsys, "--json")
    assert code == 0
    assert any(entry["id"] == "aws" for entry in json.loads(out))


# --------------------------------------------------------------------------
# paths --found
# --------------------------------------------------------------------------


def test_found_filters_the_json_the_same_way_as_the_table(fake_home, capsys):
    """--found was read by the renderer and ignored by the JSON branch."""
    _, out = run(capsys, "paths", "--found", "--json")
    payload = json.loads(out)
    assert payload, "the fixture home has paths that exist"
    assert all(p["exists"] for entry in payload for p in entry["paths"])
    assert "vault" not in {entry["id"] for entry in payload}


def test_without_found_absent_paths_are_still_in_the_json(fake_home, capsys):
    _, out = run(capsys, "paths", "--json")
    payload = {entry["id"]: entry for entry in json.loads(out)}
    assert "vault" in payload
    assert not any(p["exists"] for p in payload["vault"]["paths"])


# --------------------------------------------------------------------------
# an overlay anyone can write is not read
# --------------------------------------------------------------------------


def test_a_group_writable_overlay_is_ignored_and_explained(fake_home, capsys):
    """It names files to read and, under --check, commands to run."""
    write_overlay(fake_home, '[aws]\nname = "Work AWS"\n', mode=0o666)
    code, out, err = run_err(capsys, "scan")
    assert code == 0
    assert "Work AWS" not in out and "AWS CLI" in out
    assert err.count("ignoring") == 1, "say why, once"


def test_the_warning_is_printed_once_when_the_verb_was_inferred(fake_home, capsys):
    """`credmap aws` resolves the registry twice; the user hears about it once."""
    write_overlay(fake_home, '[aws]\nname = "Work AWS"\n', mode=0o666)
    _, _, err = run_err(capsys, "aws")
    assert err.count("ignoring") == 1


def test_an_owner_only_overlay_is_applied_silently(fake_home, capsys):
    write_overlay(fake_home, '[aws]\nname = "Work AWS"\n', mode=0o600)
    code, out, err = run_err(capsys, "scan")
    assert code == 0
    assert "Work AWS" in out
    assert err == ""
