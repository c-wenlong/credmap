"""Anomaly detection over a completed scan.

Every check here exists because a real machine exhibited the problem and the
filesystem alone did not make it obvious.
"""

from __future__ import annotations

import shlex
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .model import DEAD, EXPIRED, NO_CLI, Finding, StoreResult
from .parsers import parse_timestamp
from .resolve import display, expand
from .scan import dir_size


def _shell_path(path: Path) -> str:
    """A path as a shell word, safe to paste into the fix line we print.

    A bloat directory or a relocated store can hold a space, and the remedies
    here are meant to be copied straight into a shell: an unquoted
    ``rm -rf ~/my logs/*`` deletes the wrong thing. The leading ``~/`` stays
    outside the quotes because tilde expansion only happens unquoted, and
    ``~/'my logs'`` is both expanded and safe.
    """
    text = display(path)
    if text == "~":
        return text
    if text.startswith("~/"):
        return "~/" + shlex.quote(text[2:])
    return shlex.quote(text)


def _human_size(size: int) -> str:
    """Bytes as MB or GB, whichever keeps the number readable.

    Everything used to be printed as GB, so a 60 MB log directory reported
    itself as "0.1 GB" — a number nobody acts on.
    """
    mb = size / 1024 / 1024
    return f"{mb / 1024:.1f} GB" if mb >= 1024 else f"{mb:.0f} MB"


def _ago(raw: str | None) -> str:
    dt = parse_timestamp(raw)
    if dt is None:
        return ""
    delta = datetime.now(timezone.utc) - dt
    days = abs(delta.days)
    if days >= 1:
        return f"{days} day{'s' if days != 1 else ''} ago"
    hours = abs(delta.seconds) // 3600
    return f"{hours} hour{'s' if hours != 1 else ''} ago" if hours else "just now"


def _duplicates(results: list[StoreResult]) -> list[Finding]:
    """The same secret pasted into several profiles is one credential, not many."""
    index: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for result in results:
        for fp in result.paths:
            # Token caches legitimately repeat the client secret that minted
            # them; only durable key material counts as a real duplicate.
            if fp.spec.role != "secrets":
                continue
            for prof in fp.profiles:
                for value in prof.secret_values(result.store):
                    # One profile is one credential however many of its own
                    # fields hold the string, and the same profile can appear
                    # in two files of one store (AWS 'default' is in both
                    # credentials and config). Count owners, not sightings,
                    # or a lone profile reports itself as "shared by 2".
                    owner = (result.store.id, prof.name)
                    if owner not in index[value]:
                        index[value].append(owner)

    findings = []
    for uses in index.values():
        if len(uses) < 2:
            continue
        where = ", ".join(f"{sid}:{name}" for sid, name in uses)
        findings.append(
            Finding(
                level="warn",
                store=uses[0][0],
                message=f"one secret is shared by {len(uses)} profiles ({where})",
                fix="these are the same credential — revoking it breaks all of them",
            )
        )
    return findings


def _permissions(results: list[StoreResult]) -> list[Finding]:
    findings = []
    for result in results:
        if not result.found:
            continue
        for fp in result.paths:
            if not fp.exists or fp.mode is None:
                continue
            # A cached access token is as sensitive as the key that minted it.
            if fp.spec.role not in ("secrets", "keys", "token-cache"):
                continue
            if fp.mode & 0o077:
                target = "chmod 700" if fp.is_dir else "chmod 600"
                findings.append(
                    Finding(
                        level="warn",
                        store=result.store.id,
                        message=(
                            f"{display(fp.path)} is mode {fp.mode:04o} — "
                            "readable by group or others"
                        ),
                        fix=f"{target} {_shell_path(fp.path)}",
                    )
                )
    return findings


def _statuses(results: list[StoreResult]) -> list[Finding]:
    findings = []
    for result in results:
        for fp in result.paths:
            for prof in fp.profiles:
                if prof.status == DEAD:
                    detail = f" — {prof.detail}" if prof.detail else ""
                    findings.append(
                        Finding(
                            level="error",
                            store=result.store.id,
                            message=f"profile '{prof.name}' is not accepted{detail}",
                            fix=result.store.fix,
                        )
                    )
                elif prof.status == EXPIRED:
                    when = _ago(prof.expires_at)
                    suffix = f" ({when})" if when else ""
                    findings.append(
                        Finding(
                            level="warn",
                            store=result.store.id,
                            message=f"'{prof.name}' token expired{suffix}",
                            fix=result.store.fix,
                        )
                    )
                elif prof.status == NO_CLI:
                    findings.append(
                        Finding(
                            level="info",
                            store=result.store.id,
                            message="credentials exist but the CLI is not installed",
                        )
                    )
    return findings


# Notes that report a problem rather than context. Parse failures no longer
# need to appear here: they arrive structurally as FoundPath.error. What is
# left is the one case where a file parsed perfectly and still describes a
# broken state — an SSO login that registered a client and stopped.
_WARN_NOTE_MARKERS = ("never completed",)


def _notes(results: list[StoreResult]) -> list[Finding]:
    findings = []
    for result in results:
        if not result.found:
            continue
        for fp in result.paths:
            if fp.note:
                warn = any(marker in fp.note for marker in _WARN_NOTE_MARKERS)
                findings.append(
                    Finding(
                        level="warn" if warn else "info",
                        store=result.store.id,
                        message=fp.note,
                        fix=result.store.fix if warn else "",
                    )
                )
            # Independent of the note: a file can fail to parse and have
            # nothing else to say about itself.
            if fp.error:
                findings.append(
                    Finding(
                        level="warn",
                        store=result.store.id,
                        message=f"{display(fp.path)}: {fp.error}",
                        fix=result.store.fix,
                    )
                )
    return findings


def _bloat(results: list[StoreResult]) -> list[Finding]:
    findings = []
    for result in results:
        if not result.found:
            continue
        for template, threshold_mb in result.store.bloat:
            path = expand(template)
            if not path.is_dir():
                continue
            size = dir_size(path)
            if size > threshold_mb * 1024 * 1024:
                findings.append(
                    Finding(
                        level="info",
                        store=result.store.id,
                        message=(
                            f"{display(path)} is {_human_size(size)} "
                            "of logs, not credentials"
                        ),
                        fix=f"rm -rf {_shell_path(path)}/*",
                    )
                )
    return findings


def _empty(results: list[StoreResult]) -> list[Finding]:
    findings = []
    for result in results:
        if not result.found or result.profiles or result.notes:
            continue
        # A file that failed to parse already explains itself, and _notes has
        # said so. Adding "no profiles were parsed" on top of the parse error
        # reports one broken file as two problems.
        if any(fp.error for fp in result.paths):
            continue
        findings.append(
            Finding(
                level="info",
                store=result.store.id,
                message="store exists but no profiles were parsed from it",
            )
        )
    return findings


def diagnose(results: list[StoreResult]) -> list[Finding]:
    findings: list[Finding] = []
    for check in (_statuses, _duplicates, _notes, _permissions, _bloat, _empty):
        findings.extend(check(results))

    # The same profile can appear in two files of one store (AWS 'default'
    # lives in both credentials and config); report it once.
    seen: set[tuple[str, str, str]] = set()
    unique = []
    for finding in findings:
        key = (finding.level, finding.store, finding.message)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
