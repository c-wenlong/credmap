## Summary

<!-- What does this PR do, and why? One or two sentences. -->

## Type of change

- [ ] Bug fix
- [ ] New store / parser / probe
- [ ] Redaction or doctor change
- [ ] Documentation
- [ ] Refactor / chore

## Checklist

- [ ] `uv run pytest -q` passes locally
- [ ] `uv lock` is in sync with `pyproject.toml` (CI runs `uv sync --frozen`)
- [ ] No credential-like file committed. Fixtures are generated in `tests/conftest.py`
- [ ] The read-only invariant holds: no write, rename, unlink or mkdir against a credential path
- [ ] No new output channel bypasses `redact.scrub`, and any new renderer is in `tests/test_redact.py`'s `_all_output()`
- [ ] Docs and `credmap --help` updated if user-facing behaviour changed
- [ ] `CHANGELOG.md` has an entry
- [ ] One concern per PR

## Test plan

<!-- How did you verify this? Run against a throwaway $HOME, not your real one. -->

```bash
HOME="$(mktemp -d)" uv run credmap ...
uv run pytest -q
```
