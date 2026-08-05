"""CLI surface: default verb, exit codes, JSON validity."""

from __future__ import annotations

import json

import pytest

from credmap.cli import main

from .conftest import ALL_SECRETS


def run(capsys, *argv) -> tuple[int, str]:
    code = main(list(argv))
    return code, capsys.readouterr().out


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
    [("scan", "--json"), ("paths", "--json"), ("doctor", "--json"), ("where", "aws", "--json")],
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
