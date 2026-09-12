"""Terminal rendering: grouped scan output, flat tables, and JSON."""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Sequence
from typing import Any

from .model import (
    DEAD,
    EXPIRED,
    LIVE,
    NO_CLI,
    UNKNOWN,
    VALID,
    Finding,
    Profile,
    StoreResult,
)
from .redact import scrub
from .resolve import display, overridden_by, resolve

_ANSI = re.compile(r"\x1b\[[0-9;]*m")

MAX_NAMES = 4


class Style:
    def __init__(self, enabled: bool) -> None:
        self.on = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.on else text

    def dim(self, t: str) -> str:
        return self._wrap("2", t)

    def bold(self, t: str) -> str:
        return self._wrap("1", t)

    def green(self, t: str) -> str:
        return self._wrap("32", t)

    def red(self, t: str) -> str:
        return self._wrap("31", t)

    def yellow(self, t: str) -> str:
        return self._wrap("33", t)

    def cyan(self, t: str) -> str:
        return self._wrap("36", t)


def styler(stream: Any = None) -> Style:
    stream = stream or sys.stdout
    enabled = bool(getattr(stream, "isatty", lambda: False)()) and not os.environ.get(
        "NO_COLOR"
    )
    return Style(enabled)


def vis_len(text: str) -> int:
    return len(_ANSI.sub("", text))


def pad(text: str, width: int) -> str:
    return text + " " * max(0, width - vis_len(text))


def _size(n: int) -> str:
    value = float(n)
    for unit in ("B", "K", "M", "G"):
        if value < 1024:
            return f"{value:.0f}{unit}"
        value /= 1024
    return f"{value:.1f}T"


def table(headers: Sequence[str], rows: Sequence[Sequence[str]], style: Style) -> str:
    if not rows:
        return style.dim("  (nothing to show)")
    widths = [vis_len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], vis_len(cell))
    lines = [
        "  "
        + "  ".join(
            style.dim(pad(h.upper(), widths[i])) for i, h in enumerate(headers)
        ).rstrip()
    ]
    for row in rows:
        lines.append(
            "  " + "  ".join(pad(c, widths[i]) for i, c in enumerate(row)).rstrip()
        )
    return "\n".join(lines)


# --------------------------------------------------------------------------
# profile / status formatting
# --------------------------------------------------------------------------

_MARKS = {
    LIVE: ("✓", "green"),
    VALID: ("", "dim"),
    EXPIRED: ("⚠ expired", "yellow"),
    DEAD: ("✗ dead", "red"),
    NO_CLI: ("? no cli", "dim"),
    UNKNOWN: ("", "dim"),
}


def status_text(status: str, style: Style) -> str:
    mark, colour = _MARKS.get(status, ("", "dim"))
    if not mark:
        return ""
    return getattr(style, colour)(mark)


def _profile_label(prof: Profile, style: Style) -> str:
    label = prof.name
    mark = status_text(prof.status, style)
    if mark:
        label = f"{label} {mark}"
    if prof.detail and prof.status in (UNKNOWN, VALID):
        label = f"{label} {style.dim(f'({prof.detail})')}"
    return label


def summarise_profiles(profiles: list[Profile], style: Style) -> str:
    if not profiles:
        return style.dim("—")
    shown = [_profile_label(p, style) for p in profiles[:MAX_NAMES]]
    extra = len(profiles) - MAX_NAMES
    if extra > 0:
        shown.append(style.dim(f"+{extra} more"))
    return ", ".join(shown)


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


def render_scan(
    results: list[StoreResult], style: Style, show_all: bool = False
) -> str:
    out: list[str] = []
    found = [r for r in results if r.found]
    missing = [r for r in results if not r.found]

    # Align the path column across every store, not per store.
    locs: dict[int, str] = {}
    width = 0
    for result in found:
        for fp in result.paths:
            if not fp.exists:
                continue
            override = overridden_by(fp.spec)
            loc = display(fp.path) + (style.cyan(f" ←${override}") if override else "")
            locs[id(fp)] = loc
            width = max(width, vis_len(loc))
    width = min(width, 62)

    for result in found:
        out.append(
            f"{style.green('●')} {style.bold(result.store.name)} "
            f"{style.dim('(' + result.store.kind + ')')}"
        )
        for fp in result.paths:
            if not fp.exists:
                continue
            out.append(
                f"    {pad(locs[id(fp)], width)} {style.dim(pad(fp.spec.fmt, 14))}"
                f"{summarise_profiles(fp.profiles, style)}"
            )
            if fp.error:
                out.append(f"      {style.red('!')} {fp.error}")
        for note in result.notes:
            out.append(f"      {style.yellow('!')} {style.dim(note)}")
        out.append("")

    if show_all and missing:
        out.append(style.dim(f"not found ({len(missing)}):"))
        for result in missing:
            markers = [p for p in result.store.paths if p.marker] or list(
                result.store.paths
            )
            where = display(resolve(markers[0])[0])
            out.append(style.dim(f"    ○ {pad(result.store.name, 34)} {where}"))
        out.append("")

    if not found:
        out.append(style.dim("  no credential stores found"))

    summary = f"{len(found)} store{'s' if len(found) != 1 else ''} found"
    if not show_all and missing:
        summary += f", {len(missing)} known but absent (--all to list)"
    out.append(style.dim(summary))
    return "\n".join(out).rstrip() + "\n"


def render_paths(
    results: list[StoreResult], style: Style, only_found: bool = False
) -> str:
    rows = []
    for result in results:
        for fp in result.paths:
            if only_found and not fp.exists:
                continue
            present = style.green("yes") if fp.exists else style.dim("no")
            override = overridden_by(fp.spec)
            loc = display(fp.path) + (style.cyan(f" ←${override}") if override else "")
            rows.append(
                [
                    result.store.id,
                    loc,
                    fp.spec.fmt,
                    fp.spec.role,
                    "marker" if fp.spec.marker else "",
                    present,
                ]
            )
    header = ["store", "path", "format", "role", "", "present"]
    return table(header, rows, style) + "\n"


def render_show(result: StoreResult, style: Style, reveal: bool = False) -> str:
    store = result.store
    tag = style.dim(f"({store.id}, {store.kind})")
    out = [f"{style.bold(store.name)} {tag}"]
    if store.note:
        out.append(f"  {style.dim('note:')} {store.note}")
    if store.docs:
        out.append(f"  {style.dim('docs:')} {store.docs}")
    out.append("")

    for fp in result.paths:
        if not fp.exists:
            out.append(style.dim(f"  {display(fp.path)}  (absent)"))
            continue
        meta = [fp.spec.role, fp.spec.fmt]
        if fp.mode is not None:
            meta.append(f"{fp.mode:04o}")
        meta.append(_size(fp.size))
        meta_tag = style.dim(f"[{', '.join(meta)}]")
        out.append(f"  {style.bold(display(fp.path))}  {meta_tag}")
        if fp.note:
            out.append(f"    {style.yellow('!')} {fp.note}")
        if fp.error:
            out.append(f"    {style.red('!')} {fp.error}")

        for prof in fp.profiles:
            head = f"    [{prof.name}]"
            mark = status_text(prof.status, style)
            if mark:
                head += f"  {mark}"
            if prof.expires_at:
                head += style.dim(f"  expires {prof.expires_at}")
            out.append(head)
            fields = scrub(prof.fields, store, reveal)
            width = max((len(k) for k in fields), default=0)
            for key, value in fields.items():
                out.append(f"      {pad(key, width)} = {value}")
        out.append("")

    if store.fix:
        out.append(style.dim("  re-authenticate with:"))
        for line in store.fix.splitlines():
            out.append(f"    {line}")
    return "\n".join(out).rstrip() + "\n"


def render_findings(findings: list[Finding], style: Style) -> str:
    if not findings:
        return style.green("✓ no problems found") + "\n"
    order = {"error": 0, "warn": 1, "info": 2}
    colour = {"error": style.red, "warn": style.yellow, "info": style.cyan}
    mark = {"error": "✗", "warn": "⚠", "info": "·"}
    out = []
    for finding in sorted(findings, key=lambda f: order.get(f.level, 3)):
        paint = colour.get(finding.level, style.dim)
        bullet = paint(mark.get(finding.level, "·"))
        out.append(f"{bullet} {style.bold(finding.store)}  {finding.message}")
        if finding.fix:
            for line in finding.fix.splitlines():
                out.append(f"    {style.dim(line)}")
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.level] = counts.get(finding.level, 0) + 1
    out.append("")
    out.append(
        style.dim(
            ", ".join(
                f"{counts[level]} {level}"
                for level in ("error", "warn", "info")
                if level in counts
            )
        )
    )
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# json
# --------------------------------------------------------------------------


def result_to_dict(result: StoreResult, reveal: bool = False) -> dict[str, Any]:
    return {
        "id": result.store.id,
        "name": result.store.name,
        "kind": result.store.kind,
        "found": result.found,
        "note": result.store.note,
        "docs": result.store.docs,
        "paths": [
            {
                "path": str(fp.path),
                "exists": fp.exists,
                "format": fp.spec.fmt,
                "role": fp.spec.role,
                "marker": fp.spec.marker,
                "mode": f"{fp.mode:04o}" if fp.mode is not None else None,
                "size": fp.size,
                "env_override": overridden_by(fp.spec),
                "note": fp.note,
                "error": fp.error,
                "profiles": [
                    {
                        "name": prof.name,
                        "status": prof.status,
                        "detail": prof.detail,
                        "expires_at": prof.expires_at,
                        "fields": scrub(prof.fields, result.store, reveal),
                    }
                    for prof in fp.profiles
                ],
            }
            for fp in result.paths
        ],
    }


def to_json(payload: Any) -> str:
    return json.dumps(payload, indent=2, default=str, ensure_ascii=False) + "\n"


def findings_to_dict(findings: list[Finding]) -> list[dict[str, str]]:
    return [
        {"level": f.level, "store": f.store, "message": f.message, "fix": f.fix}
        for f in findings
    ]
