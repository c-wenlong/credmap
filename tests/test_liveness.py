"""Liveness probes: subprocess handling, name matching, and status fan-out.

Every probe here is a shell script written into a temporary directory that is
put at the front of ``PATH``. No real provider CLI is ever invoked, and no
test touches the real home: the store and result objects are built straight
from :mod:`credmap.model`.
"""

from __future__ import annotations

import os
import shutil
import textwrap
import threading
from pathlib import Path

import pytest

from credmap import liveness
from credmap.liveness import MAX_OUTPUT, _run, check
from credmap.model import (
    DEAD,
    LIVE,
    NO_CLI,
    UNKNOWN,
    VALID,
    FoundPath,
    PathSpec,
    Probe,
    Profile,
    Store,
    StoreResult,
)

# --------------------------------------------------------------------------
# harness
# --------------------------------------------------------------------------


# The stub scripts shell out to a handful of coreutils. Those sit in /usr/bin
# on a developer machine and in the nix store inside a flake build sandbox,
# where /usr/bin does not exist, so the fallback is resolved rather than
# assumed. Only these directories are added, so a real provider CLI somewhere
# else on PATH still cannot be the thing that answers.
_STUB_UTILS = ("sh", "cat", "touch", "sleep", "yes", "head")
_FALLBACK_PATH = os.pathsep.join(
    dict.fromkeys(
        [
            "/usr/bin",
            "/bin",
            *(
                os.path.dirname(found)
                for found in (shutil.which(name) for name in _STUB_UTILS)
                if found
            ),
        ]
    )
)


@pytest.fixture
def stub(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Write an executable stub CLI and make it the only one on PATH.

    PATH is replaced rather than prepended, so a real ``aws`` or ``kubectl``
    on the developer's machine can never be the thing that answers.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{_FALLBACK_PATH}")

    def make(name: str, body: str) -> Path:
        script = bin_dir / name
        script.write_text("#!/bin/sh\n" + textwrap.dedent(body).lstrip())
        script.chmod(0o755)
        return script

    return make


def make_store(argv, extract=None, timeout=5) -> Store:
    return Store(
        id="test",
        name="Test store",
        kind="cloud",
        paths=(),
        probe=Probe(tuple(argv), extract=extract, timeout=timeout),
    )


def make_path(profiles, role="secrets", exists=True, identities=None) -> FoundPath:
    spec = PathSpec("~/test", fmt="ini", role=role, identities=identities)
    return FoundPath(
        spec=spec, path=Path("/nonexistent/test"), exists=exists, profiles=profiles
    )


def make_result(store: Store, *paths: FoundPath) -> StoreResult:
    return StoreResult(store=store, paths=list(paths))


def one(store: Store, *names: str) -> tuple[StoreResult, list[Profile]]:
    """A result with a single path holding one profile per name."""
    profiles = [Profile(name=n) for n in names]
    return make_result(store, make_path(profiles)), profiles


# --------------------------------------------------------------------------
# per-profile probes
# --------------------------------------------------------------------------


def test_per_profile_success_is_live(stub):
    stub("prov", 'echo \'{"Account": "1234"}\'\n')
    store = make_store(["prov", "--profile", "{profile}"])
    result, (prof,) = one(store, "default")

    check([result])

    assert prof.status == LIVE


def test_per_profile_failure_is_dead_with_last_stderr_line(stub):
    stub(
        "prov",
        """
        echo "some noise" >&2
        echo "The security token is invalid." >&2
        exit 255
        """,
    )
    store = make_store(["prov", "--profile", "{profile}"])
    result, (prof,) = one(store, "default")

    check([result])

    assert prof.status == DEAD
    assert prof.detail == "The security token is invalid."


def test_missing_cli_is_not_death(stub):
    store = make_store(["credmap-no-such-cli", "--profile", "{profile}"])
    result, (prof,) = one(store, "default")

    check([result])

    assert prof.status == NO_CLI
    assert prof.detail == "CLI not installed"


def test_profile_name_reaches_the_cli_as_one_argv_element(stub, tmp_path):
    """A name with spaces and shell metacharacters cannot change what runs."""
    seen = tmp_path / "argv.txt"
    stub(
        "prov",
        f"""
        printf '%s\\n' "$#" > "{seen}"
        printf '%s\\n' "$2" >> "{seen}"
        """,
    )
    hostile = "we ird; touch /tmp/credmap-should-not-exist"
    store = make_store(["prov", "--profile", "{profile}"])
    result, (prof,) = one(store, hostile)

    check([result])

    assert seen.read_text().splitlines() == ["2", hostile]
    assert prof.status == LIVE


def test_dash_prefixed_profile_is_skipped(stub, tmp_path):
    """An option-shaped name would make the CLI answer about something else."""
    ran = tmp_path / "ran.txt"
    stub("prov", f'touch "{ran}"\n')
    store = make_store(["prov", "--profile", "{profile}"])
    result, (prof,) = one(store, "-secret")

    check([result])

    assert prof.status == UNKNOWN
    assert prof.detail == "profile name starts with '-'"
    assert not ran.exists()


def test_extract_becomes_the_detail(stub):
    stub("prov", 'echo \'{"Account": "123456789012"}\'\n')
    store = make_store(["prov", "--profile", "{profile}"], extract="Account")
    result, (prof,) = one(store, "default")

    check([result])

    assert prof.status == LIVE
    assert prof.detail == "Account 123456789012"


def test_extract_is_scrubbed(stub):
    """`extract` is an overlay-controlled key into arbitrary stdout."""
    token = "A" * 40
    stub("prov", f'echo \'{{"Account": "{token}"}}\'\n')
    store = make_store(["prov", "--profile", "{profile}"], extract="Account")
    result, (prof,) = one(store, "default")

    check([result])

    assert token not in prof.detail
    assert prof.detail.startswith("Account <redacted, 40 chars")


# --------------------------------------------------------------------------
# store-level probes: name matching
# --------------------------------------------------------------------------


def test_store_match_is_on_word_boundaries(stub):
    """`dev` is not live just because the current context is `devops`."""
    stub("prov", "echo devops\n")
    store = make_store(["prov", "current-context"])
    result, (dev, devops) = one(store, "dev", "devops")

    check([result])

    assert devops.status == LIVE
    assert dev.status == UNKNOWN


def test_store_match_does_not_split_a_punctuated_name(stub):
    """Contexts carry `-`, `_` and `.`; a prefix of one is a different context."""
    stub("prov", "echo prod-us_east.1\n")
    store = make_store(["prov", "current-context"])
    result, (full, prefix) = one(store, "prod-us_east.1", "prod")

    check([result])

    assert full.status == LIVE
    assert prefix.status == UNKNOWN


def test_absence_of_mention_leaves_an_offline_status_alone(stub):
    """A valid kube context simply is not the current one."""
    stub("prov", "echo other\n")
    store = make_store(["prov", "current-context"])
    profiles = [Profile(name="dev", status=VALID, detail="expires in 4 days")]
    result = make_result(store, make_path(profiles))

    check([result])

    assert profiles[0].status == VALID
    assert profiles[0].detail == "expires in 4 days"


def test_store_failure_marks_every_profile_dead(stub):
    stub("prov", 'echo "not logged in" >&2\nexit 1\n')
    store = make_store(["prov", "status"])
    result, (a, b) = one(store, "alpha", "beta")

    check([result])

    assert [a.status, b.status] == [DEAD, DEAD]
    assert a.detail == "not logged in"


def test_store_missing_cli_marks_every_profile(stub):
    store = make_store(["credmap-no-such-cli", "status"])
    result, (a, b) = one(store, "alpha", "beta")

    check([result])

    assert [a.status, b.status] == [NO_CLI, NO_CLI]


# --------------------------------------------------------------------------
# store-level probes: JSON
# --------------------------------------------------------------------------


GCLOUD_JSON = """
[{"account": "kai@example.com", "status": "ACTIVE"},
 {"account": "bot@example.com", "status": ""}]
"""


def test_json_output_matches_account_values_exactly(stub):
    """`gcloud auth list --format=json` names the accounts; use them."""
    stub("prov", f"cat <<'EOF'\n{GCLOUD_JSON.strip()}\nEOF\n")
    store = make_store(["prov", "auth", "list", "--format=json"])
    result, (kai, bot, active) = one(
        store, "kai@example.com", "bot@example.com", "ACTIVE"
    )

    check([result])

    assert kai.status == LIVE
    assert bot.status == LIVE
    # `ACTIVE` appears in the output as a status value, and boundary matching
    # alone would call it a live account.
    assert active.status == UNKNOWN


def test_non_json_output_falls_back_to_boundary_matching(stub):
    stub("prov", 'echo "Logged in to github.com account octocat (keyring)"\n')
    store = make_store(["prov", "auth", "status"])
    result, (octocat, other) = one(store, "octocat", "octo")

    check([result])

    assert octocat.status == LIVE
    assert other.status == UNKNOWN


def test_store_extract_is_no_longer_dead_configuration(stub):
    """Azure declares `extract = "id"` on a store-level probe."""
    stub("prov", 'echo \'{"id": "sub-01", "name": "Prod"}\'\n')
    store = make_store(["prov", "account", "show"], extract="id")
    result, (prod, dev) = one(store, "Prod", "Dev")

    check([result])

    assert prod.status == LIVE
    assert prod.detail == "id sub-01"
    assert dev.status == UNKNOWN
    assert dev.detail == ""


# --------------------------------------------------------------------------
# which profiles get probed, and which objects get the answer
# --------------------------------------------------------------------------


def test_one_identity_in_two_files_is_probed_once_and_marked_twice(stub, tmp_path):
    """AWS `default` lives in both `credentials` and `config`."""
    calls = tmp_path / "calls.txt"
    stub("prov", f'echo x >> "{calls}"\n')
    store = make_store(["prov", "--profile", "{profile}"])
    in_credentials = Profile(name="default")
    in_config = Profile(name="default")
    result = make_result(
        store,
        make_path([in_credentials]),
        make_path([in_config], role="config", identities=True),
    )

    check([result])

    assert in_credentials.status == LIVE
    assert in_config.status == LIVE
    assert calls.read_text().count("x") == 1


def test_store_mode_marks_every_copy_of_a_name(stub):
    stub("prov", "echo default\n")
    store = make_store(["prov", "current-context"])
    first = Profile(name="default")
    second = Profile(name="default")
    result = make_result(
        store,
        make_path([first]),
        make_path([second], role="config", identities=True),
    )

    check([result])

    assert [first.status, second.status] == [LIVE, LIVE]


def test_token_caches_and_config_blocks_are_not_probed(stub, tmp_path):
    ran = tmp_path / "ran.txt"
    stub("prov", f'touch "{ran}"\n')
    store = make_store(["prov", "--profile", "{profile}"])
    cached = Profile(name="a1b2c3-sso-cache")
    session = Profile(name="corp", detail="sso-session")
    result = make_result(
        store,
        make_path([cached], role="token-cache"),
        make_path([session]),
    )

    check([result])

    assert not ran.exists()
    assert cached.status == UNKNOWN
    assert session.status == UNKNOWN


def test_a_store_without_a_marker_is_not_probed(stub, tmp_path):
    ran = tmp_path / "ran.txt"
    stub("prov", f'touch "{ran}"\n')
    store = make_store(["prov", "--profile", "{profile}"])
    prof = Profile(name="default")
    result = make_result(store, make_path([prof], exists=False))

    check([result])

    assert not ran.exists()
    assert prof.status == UNKNOWN


# --------------------------------------------------------------------------
# subprocess robustness
# --------------------------------------------------------------------------


def test_a_hung_probe_times_out_and_is_dead(stub):
    stub("prov", "sleep 30\n")
    store = make_store(["prov", "--profile", "{profile}"], timeout=1)
    result, (prof,) = one(store, "default")

    check([result])

    assert prof.status == DEAD
    assert prof.detail == "timed out after 1s"


def test_probe_output_is_bounded(stub):
    """A chatty CLI drove memory to 800 MB inside its timeout."""
    stub("prov", "yes 0123456789abcdef | head -c 5242880\nexit 0\n")

    out, err = _run(["prov"], 30)

    assert err is None
    assert out is not None
    assert len(out) == MAX_OUTPUT


def test_a_probe_that_raises_is_reported_not_swallowed(monkeypatch):
    def boom(argv, timeout):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(liveness, "_run", boom)
    store = make_store(["prov", "--profile", "{profile}"])
    result, (prof,) = one(store, "default")

    check([result])

    assert prof.status == UNKNOWN
    assert prof.detail == "probe failed (RuntimeError)"


def test_check_gives_up_at_the_overall_deadline(monkeypatch):
    """A probe that never returns must not hold the whole command open."""
    release = threading.Event()

    def blocked(argv, timeout):
        release.wait(30)
        return "", None

    monkeypatch.setattr(liveness, "_run", blocked)
    monkeypatch.setattr(liveness, "DEADLINE_GRACE", 0)
    store = make_store(["prov", "--profile", "{profile}"], timeout=0)
    result, (prof,) = one(store, "default")

    try:
        check([result])
        # Asserted before the probe is released: once it returns it would
        # overwrite the verdict this test is about.
        assert prof.status == UNKNOWN
        assert prof.detail == "timed out"
    finally:
        release.set()
