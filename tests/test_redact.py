"""The leak test.

This is the one file that must never be allowed to go soft: it asserts the
whole-program property that no secret reaches default output. It works on the
rendered strings, not on internals, so it stays true regardless of how the
renderers are refactored.
"""

from __future__ import annotations

import pytest

from credmap.model import Store
from credmap.redact import is_secret, mask, scrub
from credmap.registry import load
from credmap.render import render_scan, render_show, result_to_dict, styler, to_json
from credmap.scan import scan

from .conftest import ALL_SECRETS, AWS_KEY_ID


def _all_output(reveal: bool = False) -> str:
    """Every renderer's output for every store, concatenated."""
    results = scan(load())
    style = styler(None)
    chunks = [render_scan(results, style, show_all=True)]
    for result in results:
        chunks.append(render_show(result, style, reveal=reveal))
        chunks.append(to_json(result_to_dict(result, reveal=reveal)))
    return "\n".join(chunks)


@pytest.mark.parametrize("secret", ALL_SECRETS)
def test_no_secret_appears_in_default_output(fake_home, secret):
    assert secret not in _all_output(reveal=False)


@pytest.mark.parametrize("secret", ALL_SECRETS)
def test_reveal_does_emit_secrets(fake_home, secret):
    """The escape hatch must actually work, or people will cat the file instead."""
    assert secret in _all_output(reveal=True)


def test_identifiers_stay_visible(fake_home):
    """An access key ID is how you find the key upstream. Masking it is unhelpful."""
    assert AWS_KEY_ID in _all_output(reveal=False)


def test_mask_keeps_length_and_tail():
    out = mask("0123456789abcdef")
    assert "16 chars" in out
    assert out.endswith("cdef>")
    assert "0123456789" not in out


def test_short_secrets_expose_no_tail():
    assert mask("abc") == "<redacted, 3 chars>"


def test_unknown_fields_are_masked_by_default():
    """Default-deny: a store nobody has curated is still safe."""
    assert is_secret("some_new_api_token")
    assert is_secret("weird_private_thing")
    assert not is_secret("region")
    assert not is_secret("project_id")


def test_declared_id_fields_beat_the_heuristic():
    aws = next(s for s in load() if s.id == "aws")
    assert is_secret("aws_secret_access_key", aws)
    assert not is_secret("aws_access_key_id", aws)
    assert not is_secret("sso_session", aws), "a session *name* is not a secret"


def test_scrub_recurses_into_nested_structures():
    fields = {"outer": {"inner_token": "supersecretvalue"}, "list": [{"password": "p"}]}
    out = scrub(fields, None)
    assert "supersecretvalue" not in to_json(out)
    assert out["list"][0]["password"] != "p"
