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


def expand(template: str) -> Path:
    """Expand ``{config}``, ``{cache}``, ``$VARS`` and ``~`` in a template."""
    s = template.replace("{config}", str(config_home()))
    s = s.replace("{cache}", str(cache_home()))
    return Path(os.path.expandvars(s)).expanduser()


def resolve(spec: PathSpec) -> list[Path]:
    """Resolve a spec to concrete paths.

    Returns a list because ``KUBECONFIG`` may hold several paths joined by
    ``os.pathsep``.
    """
    if spec.env:
        raw = os.environ.get(spec.env)
        if raw:
            if spec.multi:
                return [Path(p).expanduser() for p in raw.split(os.pathsep) if p]
            return [Path(os.path.expandvars(raw)).expanduser()]

    if spec.root_env and spec.rel:
        root = os.environ.get(spec.root_env)
        if root:
            return [Path(os.path.expandvars(root)).expanduser() / spec.rel]

    return [expand(spec.path)]


def display(path: Path) -> str:
    """Render a path with ``~`` collapsed, for output."""
    home = str(Path.home())
    s = str(path)
    return "~" + s[len(home) :] if s.startswith(home) else s


def overridden_by(spec: PathSpec) -> str | None:
    """Name of the env var currently redirecting this spec, if any."""
    for var in (spec.env, spec.root_env):
        if var and os.environ.get(var):
            return var
    return None
