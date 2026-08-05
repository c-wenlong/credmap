"""Secret masking.

Every path that prints a credential field goes through :func:`scrub`. Keeping
it to one chokepoint is what makes "no secret is ever printed by default"
testable as a single property rather than an audit of every call site.

The policy is default-deny: a field is masked if its name *looks* secret, even
if no registry entry declared it. That way a user-added store in
``registry.toml`` is safe before anyone has curated its field list.
"""

from __future__ import annotations

from typing import Any

from .model import Store

# Substrings that mark a field name as secret.
_HINTS = (
    "secret",
    "token",
    "password",
    "passwd",
    "private",
    "credential",
    "auth",
    "key",
    "cert",
    "session",
    "bearer",
    "signature",
)

# Names that trip a hint but are identifiers, not secrets. Identifiers must
# stay visible: an AWS access key ID is useless alone and you need it to find
# the key in the IAM console.
_NEVER = {
    "type",
    "name",
    "account",
    "login",
    "user",
    "username",
    "email",
    "keyring",
    "key_type",
    "public_key",
    "git_protocol",
    "private_key_present",
    "project",
    "region",
    "universe_domain",
}

_NEVER_SUFFIXES = ("_id", "_ids", "_present", "_expiry", "_domain", "_url", "_uri")


def is_secret(field: str, store: Store | None = None) -> bool:
    """Should this field's value be masked?

    Explicit registry declarations win; otherwise fall back to name hints.
    """
    name = field.lower().strip()
    if store is not None:
        if name in {f.lower() for f in store.id_fields}:
            return False
        if name in {f.lower() for f in store.secret_fields}:
            return True

    # For dotted names from flattening, judge on the leaf.
    leaf = name.rsplit(".", 1)[-1]
    if leaf in _NEVER or leaf.endswith(_NEVER_SUFFIXES):
        return False

    return any(hint in name for hint in _HINTS)


def mask(value: str) -> str:
    """Render a secret as a fingerprint: length plus last four characters.

    Enough to match a key against a provider console without putting the
    secret itself into a terminal transcript.
    """
    n = len(value)
    if n <= 8:
        return f"<redacted, {n} chars>"
    return f"<redacted, {n} chars, ends ...{value[-4:]}>"


def _scrub_value(key: str, value: Any, store: Store | None) -> Any:
    if isinstance(value, dict):
        return {k: _scrub_value(f"{key}.{k}", v, store) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub_value(key, item, store) for item in value]
    if isinstance(value, str) and value and is_secret(key, store):
        return mask(value)
    return value


def scrub(
    fields: dict[str, Any], store: Store | None = None, reveal: bool = False
) -> dict[str, Any]:
    """Mask every secret-looking value in ``fields``.

    ``reveal=True`` returns values untouched and is only ever set by an
    explicit ``--reveal`` flag — never implied by another option.
    """
    if reveal:
        return dict(fields)
    return {k: _scrub_value(k, v, store) for k, v in fields.items()}
