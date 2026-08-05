"""Format parsers.

Each parser takes a resolved path plus its spec and returns
``(profiles, note)``. The note carries store-level context that isn't a
profile — "secrets are in the Keychain", "no access token was ever cached".

Parsers never raise on malformed input; they return an empty profile list and
put the reason in the note. A broken credential file should show up in the
scan, not crash it.
"""

from __future__ import annotations

import configparser
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .model import EXPIRED, UNKNOWN, VALID, PathSpec, Profile

ParseResult = tuple[list[Profile], str]


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
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return None


def expiry_status(raw: Any) -> str:
    dt = parse_timestamp(raw)
    if dt is None:
        return UNKNOWN
    return EXPIRED if dt < datetime.now(timezone.utc) else VALID


def _flatten(value: Any) -> dict[str, Any]:
    """One level of flattening, so nested config renders as ``a.b``."""
    if not isinstance(value, dict):
        return {"value": value}
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
    try:
        cp.read(path, encoding="utf-8")
    except configparser.Error as exc:
        return [], f"unparsable INI: {exc}"
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
    return profiles, ""


def parse_inidir(path: Path, spec: PathSpec) -> ParseResult:
    """A directory of INI files, one per profile (gcloud configurations/)."""
    profiles = []
    try:
        entries = sorted(p for p in path.iterdir() if p.is_file())
    except OSError as exc:
        return [], str(exc)
    for entry in entries:
        name = entry.name
        if name.startswith("config_"):
            name = name[len("config_") :]
        cp = configparser.RawConfigParser()
        try:
            cp.read(entry, encoding="utf-8")
        except configparser.Error:
            continue
        fields = {
            f"{sect}.{key}": val
            for sect in cp.sections()
            for key, val in cp[sect].items()
        }
        profiles.append(Profile(name=name, fields=fields))
    return profiles, ""


def parse_json(path: Path, spec: PathSpec) -> ParseResult:
    try:
        doc = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        return [], f"unparsable JSON: {exc}"

    note = ""
    if isinstance(doc, dict):
        # Docker delegates to an external helper; the file itself is then empty
        # of secrets and "no auths" must not be read as "not logged in".
        helper = doc.get("credsStore") or doc.get("credentialsStore")
        if helper:
            where = "macOS Keychain" if helper == "desktop" else f"helper '{helper}'"
            note = f"secrets held in {where}, not in this file"

    return _select(doc, spec.select, path.stem), note


def parse_yaml(path: Path, spec: PathSpec) -> ParseResult:
    import yaml

    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        return [], f"unparsable YAML: {exc}"

    note = ""
    if isinstance(doc, dict) and doc.get("current-context"):
        note = f"current context: {doc['current-context']}"
    return _select(doc, spec.select, path.stem), note


def parse_sqlite_gcloud(path: Path, spec: PathSpec) -> ParseResult:
    """gcloud stores OAuth credentials in SQLite, not JSON.

    Opened read-only via URI so a scan can never mutate or lock the database
    out from under a running gcloud.
    """
    profiles: dict[str, Profile] = {}
    note = ""
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        return [], f"unreadable SQLite: {exc}"

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
        return list(profiles.values()), f"query failed: {exc}"
    finally:
        con.close()

    return list(profiles.values()), note


def parse_netrc(path: Path, spec: PathSpec) -> ParseResult:
    import netrc

    try:
        parsed = netrc.netrc(str(path))
    except (OSError, netrc.NetrcParseError) as exc:
        return [], f"unparsable netrc: {exc}"
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
    return profiles, ""


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
        return [], str(exc)

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

    note = ""
    if profiles and not tokens:
        note = "client registrations only, no access token — SSO login never completed"
    return profiles, note


def parse_keydir(path: Path, spec: PathSpec) -> ParseResult:
    """An SSH-style key directory: pair each ``*.pub`` with its private half."""
    profiles = []
    try:
        pubs = sorted(path.glob("*.pub"))
    except OSError as exc:
        return [], str(exc)
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
    return profiles, ""


def parse_raw(path: Path, spec: PathSpec) -> ParseResult:
    """A file whose entire contents are one token."""
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as exc:
        return [], str(exc)
    if not value:
        return [], "file is empty"
    return [Profile(name=path.stem, fields={"token": value})], ""


def parse_opaque(path: Path, spec: PathSpec) -> ParseResult:
    """Known credential store in a format we deliberately don't crack open."""
    return [], "present (contents not parsed)"


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
        return [], f"no parser for format '{spec.fmt}'"
    try:
        return parser(path, spec)
    except Exception as exc:  # a bad file must not abort the whole scan
        return [], f"{type(exc).__name__}: {exc}"
