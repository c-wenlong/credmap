"""Core data types.

Two schemas live here: the *registry* schema (PathSpec/Probe/Store), which
describes where credentials are supposed to live, and the *result* schema
(Profile/FoundPath/StoreResult/Finding), which describes what was actually
found on disk.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

# Result statuses.
LIVE = "live"
DEAD = "dead"
EXPIRED = "expired"
VALID = "valid"  # not expired, but not network-verified
UNKNOWN = "unknown"
NO_CLI = "no-cli"


@dataclass(frozen=True)
class PathSpec:
    """One file or directory belonging to a credential store.

    Paths are templates. Supported tokens are ``~``, ``{config}`` (XDG config
    home) and ``{cache}`` (XDG cache home). Resolution prefers, in order:
    ``env`` (a full replacement path), ``root_env`` + ``rel`` (a relocated
    store root), then the template itself. See :mod:`credmap.resolve`.
    """

    path: str
    fmt: str
    role: str = "config"  # secrets | config | token-cache | keys
    env: str | None = None
    root_env: str | None = None
    rel: str | None = None
    select: str | None = None
    marker: bool = False
    multi: bool = False  # env var may hold an os.pathsep-separated list
    # Are the profiles here credential *identities* (probeable), or just named
    # config blocks? Defaults to "yes" for secrets. AWS config holds real
    # profiles and opts in; gcloud's configurations/ holds config names only.
    identities: bool | None = None

    def has_identities(self) -> bool:
        return self.role == "secrets" if self.identities is None else self.identities


@dataclass(frozen=True)
class Probe:
    """A command that answers "does this credential still work?"."""

    argv: tuple[str, ...]
    extract: str | None = None  # JSON key to pull out of stdout
    timeout: int = 5


@dataclass(frozen=True)
class Store:
    """A credential store: one provider's worth of paths and rules."""

    id: str
    name: str
    kind: str  # cloud | infra | vcs | pkg | paas | ai | misc
    paths: tuple[PathSpec, ...]
    aliases: tuple[str, ...] = ()
    secret_fields: frozenset[str] = frozenset()
    id_fields: frozenset[str] = frozenset()
    probe: Probe | None = None
    bloat: tuple[tuple[str, int], ...] = ()  # (path template, threshold MB)
    docs: str = ""
    note: str = ""
    fix: str = ""


@dataclass
class Profile:
    """A named credential inside a store: an AWS profile, a kube context, ..."""

    name: str
    fields: dict[str, Any] = field(default_factory=dict)
    expires_at: str | None = None
    status: str = UNKNOWN
    detail: str = ""

    def secret_values(self, store: Store) -> list[str]:
        """Secret-ish string values, used for cross-profile duplicate detection."""
        from .redact import is_secret

        return [
            v
            for k, v in self.fields.items()
            if isinstance(v, str) and v and is_secret(k, store)
        ]


@dataclass
class FoundPath:
    spec: PathSpec
    path: Path
    exists: bool
    is_dir: bool = False
    mode: int | None = None
    size: int = 0
    profiles: list[Profile] = field(default_factory=list)
    error: str | None = None
    note: str = ""
    # "info" or "warn". Set by the parser, never inferred from the note's
    # wording; see ParseResult in parsers.py.
    note_level: str = "info"


@dataclass
class StoreResult:
    store: Store
    paths: list[FoundPath] = field(default_factory=list)

    @property
    def found(self) -> bool:
        """True only if a *marker* path exists.

        Directory presence is not enough: ``~/.azure`` is routinely created by
        VS Code extensions that never write a credential.
        """
        markers = [p for p in self.paths if p.spec.marker]
        return any(p.exists for p in (markers or self.paths))

    @property
    def profiles(self) -> list[Profile]:
        """Profiles across every path, merged by name.

        One identity is often split across files: gcloud names the account in
        ``credentials.db`` but records its token expiry in
        ``access_tokens.db``. Returning whichever file was read first would
        silently drop the expiry, so take the union instead. Copies are
        returned; the per-path profiles stay untouched.
        """
        merged: dict[str, Profile] = {}
        for fp in self.paths:
            for prof in fp.profiles:
                existing = merged.get(prof.name)
                if existing is None:
                    merged[prof.name] = replace(prof, fields=dict(prof.fields))
                    continue
                existing.fields.update(prof.fields)
                if existing.expires_at is None:
                    existing.expires_at = prof.expires_at
                if existing.status == UNKNOWN:
                    existing.status = prof.status
                if not existing.detail:
                    existing.detail = prof.detail
        return list(merged.values())

    @property
    def notes(self) -> list[str]:
        return [fp.note for fp in self.paths if fp.note]


@dataclass
class Finding:
    level: str  # error | warn | info
    store: str
    message: str
    fix: str = ""
