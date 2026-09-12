"""Format parsers.

Each parser takes a resolved path plus its spec and returns a
:class:`ParseResult`. The ``note`` carries store-level context that isn't a
profile — "secrets are in the Keychain", "no access token was ever cached".
The ``error`` carries a failure: the file is there but could not be read or
understood.

Parsers never raise on malformed input; they return an empty profile list and
put the reason in ``error``. A broken credential file should show up in the
scan, not crash it.
"""

from __future__ import annotations

import configparser
import json
import sqlite3
import urllib.parse
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .model import EXPIRED, UNKNOWN, VALID, PathSpec, Profile


@dataclass(frozen=True)
class ParseResult:
    """What a parser made of one file.

    ``note`` and ``error`` are separate channels on purpose. A note is
    context — the store is healthy and there is something you should know
    about it. An error is a failure. Callers that need to tell one from the
    other must not have to pattern-match on prose: before this split,
    ``doctor`` decided severity by searching notes for substrings like
    "unparsable", which silently misclassified any parser that reworded its
    message.

    ``note_level`` finishes that job. A few notes describe a state that is
    worth acting on rather than merely knowing about — an SSO login that
    registered a client and stopped, a directory where some profiles would
    not open. Those are still notes, because the file was understood, but
    they are not filed under "by the way". The parser says so here, in a
    field, so that rewording the sentence can never change how loudly it is
    reported.
    """

    profiles: list[Profile] = field(default_factory=list)
    note: str = ""
    error: str = ""
    note_level: str = "info"


def _ok(
    profiles: list[Profile] | None = None,
    note: str = "",
    note_level: str = "info",
) -> ParseResult:
    return ParseResult(profiles=profiles or [], note=note, note_level=note_level)


def _fail(error: str, profiles: list[Profile] | None = None) -> ParseResult:
    return ParseResult(profiles=profiles or [], error=error)


# --------------------------------------------------------------------------
# safe failure descriptions
# --------------------------------------------------------------------------
#
# An error string is printed by `scan`, `show` and `doctor` and never passes
# through `redact.scrub` — there is no field name to judge it by. So it must
# not be built from a library exception's text: every parser we use quotes the
# source it choked on. configparser's MissingSectionHeaderError embeds the
# whole offending line, PyYAML's marks carry a snippet plus a caret, and
# netrc's NetrcParseError repr's the token it could not place, which is the
# password when the file is broken one line above it. Report the format, the
# exception class and the line number instead — enough to open the file at the
# right place, with none of its contents.


def _fault_lines(exc: BaseException) -> list[int]:
    """Line numbers an exception reports *structurally*.

    Taken from attributes only, never parsed back out of ``str(exc)``, since
    that string is exactly what we are refusing to trust.
    """
    lines: list[int] = []

    lineno = getattr(exc, "lineno", None)
    if isinstance(lineno, int):
        lines.append(lineno)

    # configparser.ParsingError accumulates (lineno, line) pairs.
    for entry in getattr(exc, "errors", None) or ():
        if isinstance(entry, tuple) and entry and isinstance(entry[0], int):
            lines.append(entry[0])

    # PyYAML marks are 0-based and there are two: where the construct started
    # and where it went wrong.
    for attr in ("context_mark", "problem_mark"):
        mark = getattr(exc, attr, None)
        if mark is not None and isinstance(getattr(mark, "line", None), int):
            lines.append(mark.line + 1)

    return sorted(set(lines))


def _safe_error(what: str, exc: BaseException) -> str:
    """Describe a failure without quoting a single byte of the file."""
    lines = _fault_lines(exc)
    where = ""
    if lines:
        shown = ", ".join(str(n) for n in lines[:3])
        more = ", …" if len(lines) > 3 else ""
        where = f", line{'s' if len(lines) > 1 else ''} {shown}{more}"
    return f"{what}{where} ({type(exc).__name__})"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def parse_timestamp(raw: Any) -> datetime | None:
    """Parse the several timestamp shapes these files use, as aware UTC."""
    if raw in (None, ""):
        return None
    s = str(raw).strip().replace("Z", "+00:00")
    candidates = (None, "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S")
    for fmt in candidates:
        try:
            dt = datetime.fromisoformat(s) if fmt is None else datetime.strptime(s, fmt)
        except (ValueError, TypeError):
            continue
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    return None


def expiry_status(raw: Any) -> str:
    dt = parse_timestamp(raw)
    if dt is None:
        return UNKNOWN
    return EXPIRED if dt < datetime.now(UTC) else VALID


def _flatten(value: Any) -> dict[str, Any]:
    """One level of flattening, so nested config renders as ``a.b``."""
    if not isinstance(value, dict):
        # A whole-file scalar — ~/.pulumi/credentials.json holding a bare
        # "pul-..." string, ~/.fly/config.yml holding a bare token. There is
        # no key to judge it by, and a file that *is* one value is a secret by
        # construction, so name it something the default-deny hints catch.
        return {"token": value}
    out: dict[str, Any] = {}
    for key, val in value.items():
        if isinstance(val, dict):
            for sub, subval in val.items():
                out[f"{key}.{sub}"] = subval
        else:
            out[key] = val
    return out


def _select(doc: Any, select: str | None, stem: str) -> list[Profile]:
    """Pull profiles out of a parsed document per the spec's ``select`` rule.

    ``None`` -> the whole document is one profile named after the file.
    ``"."``  -> the root mapping's keys are profile names (gh hosts.yml).
    ``"a.b"`` -> descend, then use keys, or ``name`` fields if it's a list
    (kube contexts).
    """
    if select is None:
        # A whole-file credential: prefer an identity from inside it over the
        # filename, so ADC reads as "authorized_user" not the 40-char stem.
        name = stem
        if isinstance(doc, dict):
            for key in ("account", "client_email", "user", "type"):
                value = doc.get(key)
                if isinstance(value, str) and value:
                    name = value
                    break
        return [Profile(name=name, fields=_flatten(doc))]

    node = doc
    if select != ".":
        for part in select.split("."):
            if not isinstance(node, dict) or part not in node:
                return []
            node = node[part]

    if isinstance(node, list):
        out = []
        for item in node:
            if isinstance(item, dict):
                name = item.get("name") or item.get("id") or "?"
                out.append(Profile(name=str(name), fields=_flatten(item)))
        return out

    if isinstance(node, dict):
        return [Profile(name=str(k), fields=_flatten(v)) for k, v in node.items()]

    return []


# --------------------------------------------------------------------------
# parsers
# --------------------------------------------------------------------------


def parse_ini(path: Path, spec: PathSpec) -> ParseResult:
    cp = configparser.RawConfigParser()
    # Not cp.read(): it swallows OSError and returns the list of files it
    # managed to read, so a permission-denied ~/.aws/credentials came back as
    # a successful parse with zero profiles — indistinguishable from an empty
    # file. Open it ourselves so the failure has somewhere to go.
    try:
        with path.open(encoding="utf-8") as handle:
            cp.read_file(handle)
    except configparser.Error as exc:
        return _fail(_safe_error("unparsable INI", exc))
    except (OSError, UnicodeDecodeError) as exc:
        return _fail(_safe_error("unreadable INI", exc))
    profiles = []
    for section in cp.sections():
        # AWS config writes "[profile foo]" while credentials writes "[foo]",
        # and mixes in non-profile blocks like "[sso-session cortex]".
        name, detail = section, ""
        if section.startswith("profile "):
            name = section[len("profile ") :]
        else:
            for prefix in ("sso-session ", "services "):
                if section.startswith(prefix):
                    name, detail = section[len(prefix) :], prefix.strip()
                    break
        profiles.append(Profile(name=name, fields=dict(cp[section]), detail=detail))
    return _ok(profiles)


def _unreadable_summary(bad: list[str], total: int) -> str:
    """One sentence for the files in a directory that would not open.

    Same prose whichever channel it ends up in. Which field it is assigned to
    is what says how bad it is — a caller that greps this string for severity
    is the bug `note`/`error` exists to prevent. Only exception class names go
    in, never a message: see `_safe_error` above for why.
    """
    names = sorted(set(bad))
    shown = ", ".join(names[:3]) + (", …" if len(names) > 3 else "")
    return f"{len(bad)} of {total} profile files could not be read ({shown})"


def parse_inidir(path: Path, spec: PathSpec) -> ParseResult:
    """A directory of INI files, one per profile (gcloud configurations/)."""
    profiles = []
    try:
        entries = sorted(p for p in path.iterdir() if p.is_file())
    except OSError as exc:
        return _fail(str(exc))

    # One bad file must not cost us the others: unlike parse_ini this parser
    # holds many profiles, and a single mode-000 entry silently emptying the
    # directory is exactly the lie issue 6 was about. Parse what opens, count
    # what doesn't, and report the count at the end.
    failures: list[str] = []
    for entry in entries:
        name = entry.name
        if name.startswith("config_"):
            name = name[len("config_") :]
        cp = configparser.RawConfigParser()
        try:
            # Not cp.read(): it swallows OSError and reports success, so a
            # permission-denied profile looked like one that was never there.
            with entry.open(encoding="utf-8") as handle:
                cp.read_file(handle)
        except (configparser.Error, OSError, UnicodeDecodeError) as exc:
            failures.append(type(exc).__name__)
            continue
        fields = {
            f"{sect}.{key}": val
            for sect in cp.sections()
            for key, val in cp[sect].items()
        }
        profiles.append(Profile(name=name, fields=fields))

    if not failures:
        return _ok(profiles)
    summary = _unreadable_summary(failures, len(entries))
    # Nothing came out of the directory, so the path itself was not
    # understood — that is an error. If even one profile parsed, the store is
    # usable and the rest is context, which is what a note is for. It is still
    # a note the reader should act on, so it carries the warn level.
    if not profiles:
        return _fail(summary)
    return _ok(profiles, summary, note_level="warn")


def parse_json(path: Path, spec: PathSpec) -> ParseResult:
    try:
        doc = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        return _fail(f"unparsable JSON: {exc}")

    note = ""
    if isinstance(doc, dict):
        # Docker delegates to an external helper; the file itself is then empty
        # of secrets and "no auths" must not be read as "not logged in".
        helper = doc.get("credsStore") or doc.get("credentialsStore")
        if helper:
            where = "macOS Keychain" if helper == "desktop" else f"helper '{helper}'"
            note = f"secrets held in {where}, not in this file"

    return _ok(_select(doc, spec.select, path.stem), note)


def parse_yaml(path: Path, spec: PathSpec) -> ParseResult:
    import yaml

    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        return _fail(_safe_error("unparsable YAML", exc))

    note = ""
    if isinstance(doc, dict) and doc.get("current-context"):
        note = f"current context: {doc['current-context']}"
    return _ok(_select(doc, spec.select, path.stem), note)


def parse_sqlite_gcloud(path: Path, spec: PathSpec) -> ParseResult:
    """gcloud stores OAuth credentials in SQLite, not JSON.

    Opened read-only via URI so a scan can never mutate or lock the database
    out from under a running gcloud.

    The path is percent-encoded rather than interpolated: SQLite parses a URI,
    so a ``CLOUDSDK_CONFIG`` holding ``?`` or ``#`` would be cut into a query
    or a fragment, and a literal ``%`` would be decoded into some other file
    entirely. ``/`` stays safe so the path keeps its separators.
    """
    profiles: dict[str, Profile] = {}
    note = ""
    uri = "file:" + urllib.parse.quote(str(path), safe="/") + "?mode=ro"
    try:
        con = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        return _fail(f"unreadable SQLite: {exc}")

    try:
        tables = {
            row[0]
            for row in con.execute("select name from sqlite_master where type='table'")
        }
        if "credentials" in tables:
            for (account,) in con.execute("select account_id from credentials"):
                profiles[account] = Profile(
                    name=account, fields={"type": "oauth2 (sqlite blob)"}
                )
        if "access_tokens" in tables:
            rows = con.execute(
                "select account_id, token_expiry from access_tokens"
            ).fetchall()
            # Rows are keyed by account email *or* by an opaque hash for
            # tokens gcloud can no longer attribute. Listing the hashes as
            # profiles is pure noise, so summarise them instead.
            opaque = expired = 0
            for account, expiry in rows:
                if "@" not in str(account):
                    opaque += 1
                    expired += expiry_status(expiry) == EXPIRED
                    continue
                prof = profiles.setdefault(account, Profile(name=account))
                prof.expires_at = str(expiry) if expiry else None
                prof.status = expiry_status(expiry)
                prof.detail = "access token"
            if opaque:
                note = (
                    f"{opaque} cached token{'s' if opaque != 1 else ''} keyed by "
                    f"opaque id ({expired} expired) — stale cache, not accounts"
                )
    except sqlite3.Error as exc:
        # Whatever was read before the failure is still worth reporting.
        return _fail(f"query failed: {exc}", list(profiles.values()))
    finally:
        con.close()

    return _ok(list(profiles.values()), note)


def parse_netrc(path: Path, spec: PathSpec) -> ParseResult:
    import netrc

    try:
        parsed = netrc.netrc(str(path))
    except (OSError, netrc.NetrcParseError) as exc:
        return _fail(_safe_error("unparsable netrc", exc))
    profiles = []
    for machine, entry in parsed.hosts.items():
        login, account, password = entry
        profiles.append(
            Profile(
                name=machine,
                fields={
                    "login": login or "",
                    "account": account or "",
                    "password": password or "",
                },
            )
        )
    return _ok(profiles)


def parse_jsondir(path: Path, spec: PathSpec) -> ParseResult:
    """A directory of JSON blobs (AWS SSO / CLI caches).

    Distinguishes OAuth *client registrations* from actual *access tokens*: a
    cache holding only registrations means a login was started and never
    finished, which otherwise looks identical to being logged in.
    """
    profiles: list[Profile] = []
    tokens = 0
    try:
        files = sorted(path.glob("*.json"))
    except OSError as exc:
        return _fail(str(exc))

    for entry in files:
        try:
            doc = json.loads(entry.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(doc, dict):
            continue

        is_token = "accessToken" in doc or "Credentials" in doc
        kind = "access token" if is_token else "client registration"
        tokens += is_token

        label = doc.get("startUrl") or f"{entry.stem[:8]}…"
        prof = Profile(name=str(label), fields=dict(doc), detail=kind)
        expiry = doc.get("expiresAt") or doc.get("registrationExpiresAt")
        prof.expires_at = str(expiry) if expiry else None
        prof.status = expiry_status(expiry)
        profiles.append(prof)

    if profiles and not tokens:
        # Understood the files perfectly; what they describe is a half-finished
        # login. A note, but one worth acting on, so it is levelled here rather
        # than recognised downstream by its wording.
        return _ok(
            profiles,
            "client registrations only, no access token — SSO login never completed",
            note_level="warn",
        )
    return _ok(profiles)


def parse_keydir(path: Path, spec: PathSpec) -> ParseResult:
    """An SSH-style key directory: pair each ``*.pub`` with its private half."""
    profiles = []
    try:
        pubs = sorted(path.glob("*.pub"))
    except OSError as exc:
        return _fail(str(exc))
    for pub in pubs:
        private = pub.with_suffix("")
        try:
            parts = pub.read_text(encoding="utf-8").strip().split(None, 2)
        except (OSError, UnicodeDecodeError):
            continue
        profiles.append(
            Profile(
                name=private.name,
                fields={
                    "type": parts[0] if parts else "?",
                    "comment": parts[2] if len(parts) > 2 else "",
                    "private_key_present": private.exists(),
                },
            )
        )
    return _ok(profiles)


def parse_raw(path: Path, spec: PathSpec) -> ParseResult:
    """A file whose entire contents are one token."""
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as exc:
        return _fail(str(exc))
    if not value:
        return _fail("file is empty")
    return _ok([Profile(name=path.stem, fields={"token": value})])


def parse_opaque(path: Path, spec: PathSpec) -> ParseResult:
    """Known credential store in a format we deliberately don't crack open."""
    return _ok(note="present (contents not parsed)")


PARSERS = {
    "ini": parse_ini,
    "inidir": parse_inidir,
    "json": parse_json,
    "yaml": parse_yaml,
    "sqlite-gcloud": parse_sqlite_gcloud,
    "netrc": parse_netrc,
    "jsondir": parse_jsondir,
    "keydir": parse_keydir,
    "raw": parse_raw,
    "opaque": parse_opaque,
}


def parse(path: Path, spec: PathSpec) -> ParseResult:
    parser = PARSERS.get(spec.fmt)
    if parser is None:
        return _fail(f"no parser for format '{spec.fmt}'")
    try:
        return parser(path, spec)
    except Exception as exc:  # a bad file must not abort the whole scan
        return _fail(_safe_error(f"{spec.fmt} parser failed", exc))
