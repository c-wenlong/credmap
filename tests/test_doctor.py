"""doctor's checks: what counts as one problem, and what its fix line says.

Most of these build a ``Store`` and a home directory by hand rather than using
``fake_home``: the properties under test are about a single store's shape (one
profile holding a secret twice, a path that failed to parse, a directory with
a space in its name), and a synthetic home covering every provider makes them
harder to read, not more realistic.
"""

from __future__ import annotations

import shlex
from pathlib import Path

import pytest

from credmap.doctor import _human_size, diagnose
from credmap.model import FoundPath, PathSpec, Profile, Store, StoreResult


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A home directory that is empty and definitely ours, so ~ collapses."""
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    for var in ("XDG_CONFIG_HOME", "XDG_CACHE_HOME"):
        monkeypatch.delenv(var, raising=False)
    return h


def a_store(
    sid: str = "acme",
    *,
    role: str = "secrets",
    bloat: tuple[tuple[str, int], ...] = (),
    fmt: str = "json",
) -> Store:
    return Store(
        id=sid,
        name=sid.upper(),
        kind="misc",
        paths=(PathSpec(f"~/.{sid}/creds", fmt=fmt, role=role, marker=True),),
        secret_fields=frozenset({"api_secret", "api_secret_again"}),
        bloat=bloat,
        fix=f"{sid} login",
    )


def a_result(store: Store, *path_profiles: list[Profile]) -> StoreResult:
    """One StoreResult with a synthetic FoundPath per profile list given."""
    spec = store.paths[0]
    return StoreResult(
        store=store,
        paths=[
            FoundPath(
                spec=spec,
                path=Path.home() / f".{store.id}/creds",
                exists=True,
                mode=0o600,
                profiles=profiles,
            )
            for profiles in path_profiles
        ],
    )


def shared(findings) -> list:
    return [f for f in findings if "shared by" in f.message]


# --------------------------------------------------------------------------
# duplicate secrets: count owners, not sightings
# --------------------------------------------------------------------------


def test_one_profile_holding_a_secret_twice_is_not_a_duplicate(home):
    """The bug: a profile with the same string in two fields accused itself.

    It read "one secret is shared by 2 profiles (acme:only, acme:only)", which
    names a single profile twice and suggests a revocation that fixes nothing.
    """
    prof = Profile(
        name="only",
        fields={"api_secret": "FAKE-shared-value-01234", "api_secret_again": "FAKE-shared-value-01234"},
    )
    assert shared(diagnose([a_result(a_store(), [prof])])) == []


def test_one_profile_seen_in_two_files_of_a_store_is_not_a_duplicate(home):
    """AWS 'default' lives in both credentials and config. Still one identity."""
    fields = {"api_secret": "FAKE-shared-value-01234"}
    result = a_result(a_store(), [Profile(name="default", fields=dict(fields))],
                      [Profile(name="default", fields=dict(fields))])
    assert shared(diagnose([result])) == []


def test_two_profiles_sharing_a_secret_are_still_reported(home):
    """The check has to keep working: dedup must not silence the real case."""
    value = "FAKE-shared-value-01234"
    result = a_result(
        a_store(),
        [
            Profile(name="alpha", fields={"api_secret": value}),
            Profile(name="beta", fields={"api_secret": value}),
        ],
    )
    findings = shared(diagnose([result]))
    assert len(findings) == 1
    assert "shared by 2 profiles" in findings[0].message
    assert "acme:alpha" in findings[0].message and "acme:beta" in findings[0].message


def test_two_profiles_sharing_across_stores_are_reported(home):
    """The same key pasted into two providers is the case worth catching."""
    value = "FAKE-shared-value-01234"
    results = [
        a_result(a_store("acme"), [Profile(name="alpha", fields={"api_secret": value})]),
        a_result(a_store("beta"), [Profile(name="prod", fields={"api_secret": value})]),
    ]
    findings = shared(diagnose(results))
    assert len(findings) == 1
    assert "acme:alpha" in findings[0].message and "beta:prod" in findings[0].message


# --------------------------------------------------------------------------
# an unparsable file is one problem, not two
# --------------------------------------------------------------------------


def _write(path: Path, text: str, mode: int = 0o600) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


def scanned(store: Store) -> StoreResult:
    from credmap.scan import scan_store

    return scan_store(store)


def test_a_parse_error_does_not_also_report_an_empty_store(home):
    """The file is broken; "no profiles were parsed" adds nothing but noise."""
    _write(home / ".acme/creds", "{{{ not json")
    findings = diagnose([scanned(a_store())])
    assert any("json" in f.message.lower() for f in findings), "the error still shows"
    assert not any("no profiles were parsed" in f.message for f in findings)


def test_a_readable_store_with_no_profiles_is_still_reported_as_empty(home):
    """Nothing wrong with the file, nothing in it: that is the empty check."""
    _write(home / ".acme/creds", "")
    findings = diagnose([scanned(a_store(fmt="ini"))])
    assert any("no profiles were parsed" in f.message for f in findings)
    assert all(f.level == "info" for f in findings)


# --------------------------------------------------------------------------
# fix lines are meant to be pasted
# --------------------------------------------------------------------------


def test_chmod_fix_survives_a_space_in_the_path(home):
    """An unquoted chmod line silently targets two paths that do not exist."""
    _write(home / ".acme/creds file", "{}", mode=0o644)
    store = Store(
        id="acme",
        name="ACME",
        kind="misc",
        paths=(PathSpec("~/.acme/creds file", fmt="json", role="secrets", marker=True),),
    )
    fix = next(f.fix for f in diagnose([scanned(store)]) if f.fix.startswith("chmod"))
    assert shlex.split(fix) == ["chmod", "600", "~/.acme/creds file"]
    assert fix.startswith("chmod 600 ~/"), "the tilde must stay outside the quotes"


def test_an_ordinary_path_is_not_quoted(home):
    """Quoting must not make the common line look like something to edit."""
    _write(home / ".acme/creds", "{}", mode=0o644)
    fixes = [f.fix for f in diagnose([scanned(a_store())]) if f.fix.startswith("chmod")]
    assert fixes == ["chmod 600 ~/.acme/creds"]


def test_bloat_fix_survives_a_space_in_the_path(home):
    """`rm -rf ~/my logs/*` pasted into a shell deletes the wrong thing."""
    _write(home / ".acme/creds", "{}")
    logs = home / ".acme/my logs"
    logs.mkdir(parents=True)
    (logs / "one.log").write_bytes(b"x" * 2048)

    store = a_store(bloat=(("~/.acme/my logs", 0),))
    fix = next(f.fix for f in diagnose([scanned(store)]) if f.fix.startswith("rm -rf"))
    assert shlex.split(fix) == ["rm", "-rf", "~/.acme/my logs/*"]


# --------------------------------------------------------------------------
# sizes people can act on
# --------------------------------------------------------------------------


def test_bloat_size_reads_in_megabytes(home):
    """Everything used to print as GB, so 60 MB of logs read as "0.1 GB"."""
    _write(home / ".acme/creds", "{}")
    logs = home / ".acme/logs"
    logs.mkdir(parents=True)
    (logs / "one.log").write_bytes(b"x" * (2 * 1024 * 1024))

    store = a_store(bloat=(("~/.acme/logs", 1),))
    message = next(f.message for f in diagnose([scanned(store)]) if "of logs" in f.message)
    assert "2 MB" in message
    assert "GB" not in message


@pytest.mark.parametrize(
    "size,expected",
    [
        (60 * 1024**2, "60 MB"),
        (1023 * 1024**2, "1023 MB"),
        (1024 * 1024**2, "1.0 GB"),
        (3 * 1024**3, "3.0 GB"),
    ],
)
def test_size_picks_its_unit_by_magnitude(size, expected):
    assert _human_size(size) == expected


# --------------------------------------------------------------------------
# severity
# --------------------------------------------------------------------------


def test_offline_findings_never_reach_error_level(fake_home):
    """Only a probe can prove a credential dead, and only error exits 1."""
    from credmap.registry import load
    from credmap.scan import scan

    findings = diagnose(scan(load()))
    assert findings, "the fixture home has problems worth reporting"
    assert not any(f.level == "error" for f in findings)
