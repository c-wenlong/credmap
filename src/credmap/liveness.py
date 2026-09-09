"""Opt-in liveness probes.

Off by default, because a scan should be instant and work on a plane. The
``--check`` flag buys the one thing the filesystem cannot tell you: whether a
credential still works. A key that was revoked upstream looks byte-identical
to one that works.

Every probe is a subprocess with a hard timeout, run in a thread pool.
"""

from __future__ import annotations

import concurrent.futures
import json
import subprocess

from .model import DEAD, LIVE, NO_CLI, Profile, Store, StoreResult
from .redact import scrub_text


# Section names that are configuration blocks, not credential identities.
NON_PROFILE = {"sso-session", "services"}


def probeable(result: StoreResult) -> list[Profile]:
    """Profiles worth asking a provider about.

    Excludes token caches and named config blocks — running
    ``aws sts get-caller-identity --profile <sso-cache-hash>`` is nonsense and
    its failure says nothing about whether your credentials work.
    """
    out = []
    seen: set[str] = set()
    for fp in result.paths:
        if not fp.exists or not fp.spec.has_identities():
            continue
        for prof in fp.profiles:
            if prof.detail in NON_PROFILE or prof.name in seen:
                continue
            seen.add(prof.name)
            out.append(prof)
    return out


def _short(text: str, limit: int = 160) -> str:
    """Last line of a probe's output, capped and stripped of token-shaped runs.

    Everything this returns ends up in ``Profile.detail``, which ``doctor``
    and ``--json`` print verbatim and which redaction cannot reach: there is
    no field name to judge it by. A provider CLI is free to echo the
    credential into its own failure text, so mask by shape here, at the one
    point where external output enters the program.
    """
    line = text.strip().splitlines()[-1] if text.strip() else ""
    return scrub_text(line, limit)


def _run(argv: list[str], timeout: int) -> tuple[str | None, str | None]:
    """Return (stdout, error). Exactly one is non-None."""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return None, NO_CLI
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout}s"
    except OSError as exc:
        return None, str(exc)

    if proc.returncode != 0:
        detail = _short(proc.stderr) or _short(proc.stdout) or f"exit {proc.returncode}"
        return None, detail
    return proc.stdout, None


def _probe_profile(store: Store, prof: Profile) -> None:
    """Run a per-profile probe (AWS: one call per named profile)."""
    probe = store.probe
    assert probe is not None
    argv = [arg.replace("{profile}", prof.name) for arg in probe.argv]
    out, err = _run(argv, probe.timeout)

    if err == NO_CLI:
        prof.status = NO_CLI
        prof.detail = "CLI not installed"
        return
    if err:
        prof.status = DEAD
        prof.detail = err
        return

    prof.status = LIVE
    if probe.extract and out:
        try:
            doc = json.loads(out)
        except json.JSONDecodeError:
            doc = None
        if isinstance(doc, dict) and probe.extract in doc:
            # `extract` is an overlay-controlled key into arbitrary stdout.
            # Same treatment as stderr for the same reason.
            prof.detail = f"{probe.extract} {scrub_text(str(doc[probe.extract]))}"


def _probe_store(result: StoreResult) -> None:
    """Run one probe for the whole store, then match profiles by name.

    Works for ``gcloud auth list``, ``gh auth status`` and
    ``kubectl config current-context``, all of which echo the identity back.
    """
    store = result.store
    probe = store.probe
    assert probe is not None
    out, err = _run(list(probe.argv), probe.timeout)

    profiles = probeable(result)
    if err == NO_CLI:
        for prof in profiles:
            prof.status = NO_CLI
            prof.detail = "CLI not installed"
        return
    if err:
        for prof in profiles:
            prof.status = DEAD
            prof.detail = err
        return

    haystack = (out or "").lower()
    for prof in profiles:
        if prof.name.lower() in haystack:
            prof.status = LIVE
        # Not mentioned is not proof of death: a perfectly valid kube context
        # simply isn't the current one. Leave the offline status alone.


def check(results: list[StoreResult], workers: int = 8) -> None:
    """Probe every found store in parallel, mutating profile statuses in place."""
    jobs: list[concurrent.futures.Future] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for result in results:
            probe = result.store.probe
            if probe is None or not result.found:
                continue
            profiles = probeable(result)
            if not profiles:
                continue
            if any("{profile}" in arg for arg in probe.argv):
                for prof in profiles:
                    jobs.append(pool.submit(_probe_profile, result.store, prof))
            else:
                jobs.append(pool.submit(_probe_store, result))
        concurrent.futures.wait(jobs)
