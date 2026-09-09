"""The leak test.

This is the one file that must never be allowed to go soft: it asserts the
whole-program property that no secret reaches default output. It works on the
rendered strings, not on internals, so it stays true regardless of how the
renderers are refactored.
"""

from __future__ import annotations

import pytest

from credmap.doctor import diagnose
from credmap.model import Store
from credmap.redact import is_secret, mask, scrub, scrub_text
from credmap.registry import load
from credmap.render import (
    findings_to_dict,
    render_findings,
    render_scan,
    render_show,
    result_to_dict,
    styler,
    to_json,
)
from credmap.scan import scan

from .conftest import ALL_SECRETS, AWS_KEY_ID, REVEALABLE_SECRETS


def _all_output(reveal: bool = False) -> str:
    """Every renderer's output for every store, concatenated.

    ``doctor``'s two renderers are here because they format text of their own
    from parser errors and probe details, neither of which a field-level
    ``scrub`` can reach. A renderer absent from this list is a renderer the
    leak test does not cover.
    """
    results = scan(load())
    style = styler(None)
    chunks = [render_scan(results, style, show_all=True)]
    for result in results:
        chunks.append(render_show(result, style, reveal=reveal))
        chunks.append(to_json(result_to_dict(result, reveal=reveal)))
    findings = diagnose(results)
    chunks.append(render_findings(findings, style))
    chunks.append(to_json(findings_to_dict(findings)))
    return "\n".join(chunks)


@pytest.mark.parametrize("secret", ALL_SECRETS)
def test_no_secret_appears_in_default_output(fake_home, secret):
    assert secret not in _all_output(reveal=False)


@pytest.mark.parametrize("secret", REVEALABLE_SECRETS)
def test_reveal_does_emit_secrets(fake_home, secret):
    """The escape hatch must actually work, or people will cat the file instead.

    Only the sentinels that landed in a parsed field can come back: a secret
    sitting on the line that made the file unparsable has no field to be
    revealed from, and the error naming that file must not quote it.
    """
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


def test_multi_line_values_are_masked_whatever_the_key(fake_home):
    """configparser folds an indented line into the value above it.

    That parks a secret inside ``aws_access_key_id``, which is a declared
    id_field and would otherwise print in full.
    """
    aws = next(s for s in load() if s.id == "aws")
    folded = f"AKIAFAKEFAKEFAKEFAKE\naws_secret_access_key = {'s' * 30}"
    out = scrub({"aws_access_key_id": folded}, aws)
    assert out["aws_access_key_id"].startswith("<redacted")
    assert "s" * 30 not in out["aws_access_key_id"]


def test_passphrase_is_secret():
    """The sharp one: ``password`` and ``passwd`` were listed, ``passphrase`` was not."""
    assert is_secret("passphrase")
    assert is_secret("mnemonic")
    assert is_secret("session_cookie")
    assert not is_secret("username"), "the never-list still wins on the leaf"


def test_scrub_text_masks_token_shaped_runs():
    """Probe output has no field name, so it is judged by shape."""
    out = scrub_text("could not authenticate with FAKEtokenABCDEFGH0123456789")
    assert "FAKEtokenABCDEFGH0123456789" not in out
    assert "could not authenticate with" in out


def test_scrub_text_caps_length():
    assert len(scrub_text("word " * 200, limit=40)) == 40
