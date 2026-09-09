"""Path resolution.

Every provider lets you relocate its store with an environment variable, so a
hardcoded path list is wrong on any machine that uses one. This module is the
single place that knows the precedence rules.
"""

from __future__ import annotations

import os
from pathlib import Path

from .model import PathSpec


def _xdg(var: str, default: str) -> Path:
    raw = os.environ.get(var)
    return Path(raw).expanduser() if raw else Path.home() / default


def config_home() -> Path:
    return _xdg("XDG_CONFIG_HOME", ".config")


def cache_home() -> Path:
    return _xdg("XDG_CACHE_HOME", ".cache")


def _expand_path(raw: str) -> Path:
    """``$VAR`` then ``~``, in that order, for one path string.

    Both, always. An env var that holds ``$HOME/b.yml`` is as common as one
    holding ``~/b.yml``, and expanding only the tilde left the dollar form as
    a literal path segment that never matched a file.
    """
    return Path(os.path.expandvars(raw)).expanduser()


def expand(template: str) -> Path:
    """Expand ``{config}``, ``{cache}``, ``$VARS`` and ``~`` in a template."""
    s = template.replace("{config}", str(config_home()))
    s = s.replace("{cache}", str(cache_home()))
    return _expand_path(s)


def resolve(spec: PathSpec) -> list[Path]:
    """Resolve a spec to concrete paths.

    Returns a list because ``KUBECONFIG`` may hold several paths joined by
    ``os.pathsep``.
    """
    if spec.env:
        raw = os.environ.get(spec.env)
        if raw:
            if spec.multi:
                # Order is the search order the provider uses, so it is kept.
                # Empty segments ("a::b", a trailing colon) are dropped.
                return [_expand_path(p) for p in raw.split(os.pathsep) if p]
            return [_expand_path(raw)]

    if spec.root_env and spec.rel:
        root = os.environ.get(spec.root_env)
        if root:
            return [_expand_path(root) / spec.rel]

    return [expand(spec.path)]


def display(path: Path) -> str:
    """Render a path with ``~`` collapsed, for output.

    The comparison is on whole path components. A bare ``startswith`` made
    ``/Users/kaichen/x`` render as ``~chen/x`` for a user whose home is
    ``/Users/kai`` — wrong everywhere it is printed, and doctor prints it
    inside a ``chmod`` line meant to be pasted.
    """
    home = str(Path.home())
    s = str(path)
    if s == home:
        return "~"
    prefix = home if home.endswith(os.sep) else home + os.sep
    if s.startswith(prefix):
        return "~" + os.sep + s[len(prefix) :]
    return s


def overridden_by(spec: PathSpec) -> str | None:
    """Name of the env var currently redirecting this spec, if any."""
    for var in (spec.env, spec.root_env):
        if var and os.environ.get(var):
            return var
    return None
