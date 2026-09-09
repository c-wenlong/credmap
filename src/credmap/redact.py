"""Secret masking.

Every path that prints a credential field goes through :func:`scrub`. Keeping
it to one chokepoint is what makes "no secret is ever printed by default"
testable as a single property rather than an audit of every call site.

The policy is default-deny: a field is masked if its name *looks* secret, even
if no registry entry declared it. That way a user-added store in
``registry.toml`` is safe before anyone has curated its field list.
"""

from __future__ import annotations

import re
from typing import Any

from .model import Store

# Substrings that mark a field name as secret.
#
# Split into two tiers because the allow-list below has to be allowed to
# override *some* hints and not others. A "strong" hint means the value is key
# material or a bearer no matter what else the name says: no identifier, URL or
# timestamp is legitimately called ``session`` or ``password``. A "weak" hint is
# a word that shows up in the names of real identifiers -- ``key_id``,
# ``public_key``, ``client_id`` -- so it must lose to the allow-list.
_STRONG_HINTS = (
    "secret",
    "token",
    "password",
    "passwd",
    # "pass" subsumes password/passwd/passphrase/passcode; the longer forms
    # stay listed above because they document what this list is for.
    "pass",
    "private",
    "session",
    "bearer",
    "jwt",
    "cookie",
    "mnemonic",
    "seed",
)

_WEAK_HINTS = (
    "key",
    "cert",
    "auth",
    "credential",
    "signature",
    "phrase",
    "dsn",
    "sas",
)

_HINTS = _STRONG_HINTS + _WEAK_HINTS

# Names that trip a hint but are identifiers, not secrets. Identifiers must
# stay visible: an AWS access key ID is useless alone and you need it to find
# the key in the IAM console. Membership here is absolute -- it beats even a
# strong hint -- so only add a name that can never hold key material.
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
    # Timestamps. A moment in time is not key material, and "expiration" has no
    # hint of its own, so without these it inherits masking from a parent named
    # "credentials" or "auth".
    "expiry",
    "expires",
    "expires_at",
    "expiration",
}

# Suffixes whose *shape* rules out key material: a presence flag is a boolean,
# an expiry is a timestamp, a domain is a hostname. Like _NEVER, these beat a
# strong hint, which is what keeps "private_key_present" and "token_expiry"
# readable.
_SAFE_SUFFIXES = ("_present", "_expiry", "_domain")

# Suffixes that usually mark an identifier but can carry a bearer: a session ID
# is a credential, and a callback or SAS URL carries a token in its query
# string. So these exempt a leaf only when no strong hint is present.
_ID_SUFFIXES = ("_id", "_ids", "_url", "_uri")

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _snake(name: str) -> str:
    """``AccessKeyId`` -> ``access_key_id``, so camelCase keys hit the same rules.

    The AWS CLI cache writes ``Credentials.AccessKeyId`` and
    ``Credentials.Expiration``. Without this they match no suffix and no
    allow-list entry, and an access key ID -- an identifier -- gets masked.
    Splitting only ever inserts underscores, so hints are matched against the
    original spelling as well and nothing can become visible by being split.
    """
    return _CAMEL_BOUNDARY.sub("_", name).lower()


def _leaf_verdict(raw: str, snake: str) -> bool | None:
    """Decide from the leaf alone, or return ``None`` if the leaf says nothing."""
    if raw in _NEVER or snake in _NEVER:
        return False
    if raw.endswith(_SAFE_SUFFIXES) or snake.endswith(_SAFE_SUFFIXES):
        return False
    if any(h in raw or h in snake for h in _STRONG_HINTS):
        return True
    if raw.endswith(_ID_SUFFIXES) or snake.endswith(_ID_SUFFIXES):
        return False
    if any(h in raw or h in snake for h in _WEAK_HINTS):
        return True
    return None


def is_secret(field: str, store: Store | None = None) -> bool:
    """Should this field's value be masked?

    The rule, first check that decides wins:

    1. The store declares the full name in ``id_fields`` (visible) or in
       ``secret_fields`` (masked). A curated list beats every heuristic.
    2. Otherwise judge the **leaf** of a dotted name, camelCase split so that
       ``Credentials.AccessKeyId`` is read as ``access_key_id``:

       a. leaf in ``_NEVER``, or ending ``_present``/``_expiry``/``_domain``:
          **visible**. A boolean, a timestamp and a hostname hold no secret.
       b. leaf contains a strong hint (``secret``, ``token``, ``pass*``,
          ``private``, ``session``, ``bearer``, ``jwt``, ``cookie``,
          ``mnemonic``, ``seed``): **masked**. This is what makes
          ``session_id``, ``secret_url`` and ``password_uri`` masked where the
          suffix allow-list used to exempt them.
       c. leaf ending ``_id``/``_ids``/``_url``/``_uri``: **visible**. Keeps
          ``key_id``, ``client_id``, ``callback_url`` and ``sso_start_url``
          readable.
       d. leaf contains a weak hint (``key``, ``cert``, ``auth``,
          ``credential``, ``signature``, ``phrase``, ``dsn``, ``sas``):
          **masked**.
    3. The leaf said nothing at all: inherit from the parent path, so
       ``auth.foo`` is masked. This is the only place the parent is consulted;
       a leaf that decided for itself is never overridden by its parent.

    Hints and allow-list therefore run over the same scope, which is what
    stops a parent named ``credentials`` from revealing a child ``session_id``
    or masking a child ``Expiration``.
    """
    name = field.lower().strip()
    if store is not None:
        if name in {f.lower() for f in store.id_fields}:
            return False
        if name in {f.lower() for f in store.secret_fields}:
            return True

    # For dotted names from flattening, judge on the leaf; ``field`` is
    # re-split from the original so camelCase survives the lowercasing above.
    raw_path = field.strip()
    raw_leaf = raw_path.rsplit(".", 1)[-1]
    verdict = _leaf_verdict(raw_leaf.lower(), _snake(raw_leaf))
    if verdict is not None:
        return verdict

    parent = name.rsplit(".", 1)[0] if "." in name else ""
    if not parent:
        return False
    snake_parent = _snake(raw_path.rsplit(".", 1)[0])
    return any(h in parent or h in snake_parent for h in _HINTS)


# Below this length a four-character tail gives away too much of a
# hand-chosen password. Machine tokens are all far longer.
_TAIL_FLOOR = 16


def mask(value: str) -> str:
    """Render a secret as a fingerprint: length plus last four characters.

    Enough to match a key against a provider console without putting the
    secret itself into a terminal transcript.

    The tail only appears from 16 characters up. Four characters of a machine
    token is a rounding error; four characters of a 9-character human password
    is nearly half of it, and short values here are overwhelmingly the
    hand-chosen kind.
    """
    n = len(value)
    if n < _TAIL_FLOOR:
        return f"<redacted, {n} chars>"
    return f"<redacted, {n} chars, ends ...{value[-4:]}>"


def _scrub_value(key: str, value: Any, store: Store | None) -> Any:
    if isinstance(value, dict):
        return {k: _scrub_value(f"{key}.{k}", v, store) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub_value(key, item, store) for item in value]
    if isinstance(value, str) and value:
        # A multi-line value is masked whatever it is called. configparser
        # folds an indented line into the previous key's value, so a leading
        # space in front of "aws_secret_access_key" parks the secret inside
        # "aws_access_key_id" — a declared id_field, and therefore visible.
        # Nothing legitimate in these formats spans lines, so the newline is a
        # reliable tell and this is the safety net under id_fields.
        if "\n" in value or "\r" in value:
            return mask(value)
        if is_secret(key, store):
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


# Anything long enough and drawn only from the token alphabet: base64url,
# hex, JWTs, the "ghp_..." family. Twenty characters is above every English
# word and below every credential worth protecting.
_TOKENISH = re.compile(r"[A-Za-z0-9_\-+/=.]{20,}")


def scrub_text(text: str, limit: int = 160) -> str:
    """Make free text from an external process safe to print.

    ``scrub`` judges a value by the name of the field holding it. Probe stdout
    and stderr have no field name: a provider CLI can echo the token straight
    into its failure message, and the overlay's ``extract`` key pulls an
    arbitrary stdout value into the same place. So judge the *shape* instead,
    mask every token-shaped run, and cap the result — a diagnostic line is
    worth reading, a dump of a CLI's output is not.

    A long filesystem path is token-shaped and gets masked too. That is the
    price of not needing to know what the CLI decided to print.
    """
    if not text:
        return ""
    out = _TOKENISH.sub(lambda m: mask(m.group()), text.strip())
    return out if len(out) <= limit else out[: limit - 1] + "…"
