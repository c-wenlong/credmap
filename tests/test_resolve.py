"""Path resolution and display.

The rules here decide which file gets read and which path gets printed, so a
quiet bug means the tool confidently reports on the wrong file, or tells you
to chmod one that does not exist.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from credmap.model import PathSpec
from credmap.resolve import display, expand, overridden_by, resolve


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A home with no inherited overrides, so the developer's env can't leak in."""
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    for var in ("XDG_CONFIG_HOME", "XDG_CACHE_HOME", "KUBECONFIG", "CLOUDSDK_CONFIG"):
        monkeypatch.delenv(var, raising=False)
    return h


# --------------------------------------------------------------------------
# display
# --------------------------------------------------------------------------


def test_display_collapses_the_real_home(home):
    assert display(home / ".aws/credentials") == "~/.aws/credentials"


def test_display_collapses_home_itself(home):
    assert display(home) == "~"


def test_display_does_not_collapse_a_sibling_that_shares_a_prefix(
    tmp_path, monkeypatch
):
    """With HOME=/Users/kai, /Users/kaichen/x used to render as ~chen/x."""
    monkeypatch.setenv("HOME", str(tmp_path / "kai"))
    sibling = tmp_path / "kaichen" / ".aws" / "credentials"
    assert display(sibling) == str(sibling)
    assert "~" not in display(sibling)


def test_display_does_not_collapse_a_prefix_of_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "kai"))
    assert display(tmp_path) == str(tmp_path)


def test_display_leaves_an_unrelated_path_alone(home, tmp_path):
    other = tmp_path / "elsewhere" / "config"
    assert display(other) == str(other)


# --------------------------------------------------------------------------
# resolve: the multi branch (KUBECONFIG)
# --------------------------------------------------------------------------


MULTI = PathSpec(path="~/.kube/config", fmt="yaml", env="KUBECONFIG", multi=True)


def test_multi_expands_both_tilde_and_dollar_var(home, monkeypatch):
    """`$HOME/b.yml` used to survive as a literal segment and never match."""
    monkeypatch.setenv("KUBECONFIG", f"~/a.yml{os.pathsep}$HOME/b.yml")
    assert resolve(MULTI) == [home / "a.yml", home / "b.yml"]


def test_multi_keeps_order_and_drops_empty_segments(home, monkeypatch):
    sep = os.pathsep
    monkeypatch.setenv("KUBECONFIG", f"{sep}~/b.yml{sep}{sep}$HOME/a.yml{sep}")
    assert resolve(MULTI) == [home / "b.yml", home / "a.yml"]


def test_multi_leaves_an_unset_var_literal(home, monkeypatch):
    """expandvars is not a lookup failure: an unknown name stays as typed."""
    monkeypatch.delenv("CREDMAP_NOT_SET", raising=False)
    monkeypatch.setenv("KUBECONFIG", "$CREDMAP_NOT_SET/a.yml")
    assert resolve(MULTI) == [Path("$CREDMAP_NOT_SET/a.yml")]


def test_empty_env_var_falls_through_to_the_template(home, monkeypatch):
    monkeypatch.setenv("KUBECONFIG", "")
    assert resolve(MULTI) == [home / ".kube/config"]


def test_unset_env_var_falls_through_to_the_template(home):
    assert resolve(MULTI) == [home / ".kube/config"]


# --------------------------------------------------------------------------
# resolve: the single and root_env branches
# --------------------------------------------------------------------------


SINGLE = PathSpec(
    path="~/.aws/credentials", fmt="ini", env="AWS_SHARED_CREDENTIALS_FILE"
)
ROOTED = PathSpec(
    path="{config}/gcloud/credentials.db",
    fmt="sqlite-gcloud",
    root_env="CLOUDSDK_CONFIG",
    rel="credentials.db",
)


def test_single_env_expands_var_and_tilde(home, monkeypatch):
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "$HOME/creds")
    assert resolve(SINGLE) == [home / "creds"]
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "~/creds")
    assert resolve(SINGLE) == [home / "creds"]


def test_root_env_expands_var_and_tilde(home, monkeypatch):
    monkeypatch.setenv("CLOUDSDK_CONFIG", "$HOME/gcloud")
    assert resolve(ROOTED) == [home / "gcloud" / "credentials.db"]
    monkeypatch.setenv("CLOUDSDK_CONFIG", "~/gcloud")
    assert resolve(ROOTED) == [home / "gcloud" / "credentials.db"]


def test_xdg_template_honours_the_override(home, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / "xdg"))
    assert expand("{config}/gcloud/credentials.db") == (
        home / "xdg" / "gcloud" / "credentials.db"
    )


def test_overridden_by_names_the_variable_in_use(home, monkeypatch):
    assert overridden_by(ROOTED) is None
    monkeypatch.setenv("CLOUDSDK_CONFIG", str(home / "gcloud"))
    assert overridden_by(ROOTED) == "CLOUDSDK_CONFIG"
