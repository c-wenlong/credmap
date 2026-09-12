"""Opt-in liveness probes.

Off by default, because a scan should be instant and work on a plane. The
``--check`` flag buys the one thing the filesystem cannot tell you: whether a
credential still works. A key that was revoked upstream looks byte-identical
to one that works.

Every probe is a subprocess with a hard timeout and a bounded read, run in a
thread pool under an overall deadline.
"""

from __future__ import annotations

import concurrent.futures
import contextlib
import json
import os
import re
import signal
import subprocess
import threading
import time

from .model import DEAD, LIVE, NO_CLI, UNKNOWN, Profile, Store, StoreResult
from .redact import scrub_text

# Section names that are configuration blocks, not credential identities.
NON_PROFILE = {"sso-session", "services"}

# Most bytes kept from one stream of one probe. A chatty CLI can emit
# hundreds of megabytes inside its timeout; only the first lines are ever
# read, and `_short` keeps one of them. The child keeps running and its
# output keeps being drained, so the exit status still means what it says.
MAX_OUTPUT = 64 * 1024

# Grace added to the longest probe timeout to get the overall deadline, and
# how long to wait on a reader thread once the child is gone.
DEADLINE_GRACE = 5
JOIN_GRACE = 1.0

# POSIX gives a probe its own process group so a hung grandchild holding the
# pipe can be killed along with its parent. Windows has neither call.
_POSIX = hasattr(os, "killpg") and hasattr(os, "getpgid")

# Characters that can be part of an identity: account names carry `@` and
# `.`, kube contexts carry `-` and `_`. A name only counts as mentioned when
# it is not glued to one of these, so `dev` is not found inside `devops`.
_NAME_CHARS = r"A-Za-z0-9_.@\-"

# JSON keys a provider uses for the identity it is reporting back:
# `gcloud auth list` gives `account`, `az account show` gives `id`/`name`.
_IDENTITY_KEYS = ("account", "name", "id", "user", "username", "context")


def groups(result: StoreResult) -> dict[str, list[Profile]]:
    """Probeable profile objects, grouped by name.

    One identity is often several ``Profile`` objects: AWS ``default`` lives
    in both ``credentials`` and ``config``, and it is the per-path originals
    that liveness mutates, not the merged copies ``StoreResult.profiles``
    hands out. Probing once per name and applying the verdict to the whole
    group is what keeps both rows marked.

    Token caches and named config blocks are excluded: running
    ``aws sts get-caller-identity --profile <sso-cache-hash>`` is nonsense and
    its failure says nothing about whether your credentials work.
    """
    out: dict[str, list[Profile]] = {}
    for fp in result.paths:
        if not fp.exists or not fp.spec.has_identities():
            continue
        for prof in fp.profiles:
            if prof.detail in NON_PROFILE:
                continue
            out.setdefault(prof.name, []).append(prof)
    return out


def probeable(result: StoreResult) -> list[Profile]:
    """One profile per probeable name, in the order the paths were read."""
    return [profiles[0] for profiles in groups(result).values()]


def _mark(profiles: list[Profile], status: str, detail: str | None) -> None:
    """Apply one verdict to every object carrying the probed name.

    ``detail=None`` leaves the existing detail alone: a live profile has
    nothing to explain, and whatever the parser put there is worth more than
    an empty string.
    """
    for prof in profiles:
        prof.status = status
        if detail is not None:
            prof.detail = detail


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


def _drain(stream, sink: list[bytes], limit: int) -> None:
    """Read a pipe to EOF, keeping only the first ``limit`` bytes.

    Draining rather than stopping is deliberate: a reader that walks away
    from the pipe blocks the child on its next write, which would turn a
    chatty but healthy CLI into a timeout. Memory is what needed bounding.
    """
    kept = 0
    try:
        while True:
            chunk = stream.read1(65536)
            if not chunk:
                break
            if kept < limit:
                keep = chunk[: limit - kept]
                sink.append(keep)
                kept += len(keep)
    except (OSError, ValueError):
        pass
    finally:
        with contextlib.suppress(OSError):
            stream.close()


def _kill(proc: subprocess.Popen) -> None:
    """Kill the probe and anything it started.

    A grandchild inheriting the pipe outlives a plain ``proc.kill()``, so on
    POSIX the whole process group goes.
    """
    if _POSIX:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            return
        except OSError:
            pass
    with contextlib.suppress(OSError):
        proc.kill()


def _run(argv: list[str], timeout: int) -> tuple[str | None, str | None]:
    """Return (stdout, error). Exactly one is non-None."""
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=_POSIX,
        )
    except FileNotFoundError:
        return None, NO_CLI
    except OSError as exc:
        return None, str(exc)

    out_chunks: list[bytes] = []
    err_chunks: list[bytes] = []
    readers = [
        threading.Thread(
            target=_drain, args=(proc.stdout, out_chunks, MAX_OUTPUT), daemon=True
        ),
        threading.Thread(
            target=_drain, args=(proc.stderr, err_chunks, MAX_OUTPUT), daemon=True
        ),
    ]
    for reader in readers:
        reader.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill(proc)
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=JOIN_GRACE)
    finally:
        for reader in readers:
            reader.join(JOIN_GRACE)

    if timed_out:
        return None, f"timed out after {timeout}s"

    stdout = b"".join(out_chunks).decode("utf-8", "replace")
    stderr = b"".join(err_chunks).decode("utf-8", "replace")
    if proc.returncode != 0:
        return None, _short(stderr) or _short(stdout) or f"exit {proc.returncode}"
    return stdout, None


def _extract(probe, out: str | None) -> str | None:
    """Detail line from the probe's declared JSON key, or ``None``.

    Applies in both modes. A store-level probe that declares ``extract`` --
    Azure's ``id`` -- used to be silently ignored.
    """
    if not probe.extract or not out:
        return None
    try:
        doc = json.loads(out)
    except ValueError:
        return None
    if isinstance(doc, dict) and probe.extract in doc:
        # `extract` is an overlay-controlled key into arbitrary stdout.
        # Same treatment as stderr for the same reason.
        return f"{probe.extract} {scrub_text(str(doc[probe.extract]))}"
    return None


def _mentions(haystack: str, name: str) -> bool:
    """Is ``name`` in ``haystack`` as a whole identity rather than a fragment?"""
    if not name:
        return False
    pattern = rf"(?<![{_NAME_CHARS}]){re.escape(name)}(?![{_NAME_CHARS}])"
    return re.search(pattern, haystack, re.IGNORECASE) is not None


def _json_identities(out: str) -> set[str]:
    """Identities a probe named explicitly in JSON, case-folded.

    ``gcloud auth list --format=json`` returns a list of ``{account, status}``
    and ``az account show`` returns one object. Comparing against those exact
    values beats scanning the text, which cannot tell an account from any
    other string that happens to contain it.
    """
    try:
        doc = json.loads(out)
    except ValueError:
        return set()
    items = doc if isinstance(doc, list) else [doc]
    found: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        for key in _IDENTITY_KEYS:
            value = item.get(key)
            if isinstance(value, str) and value:
                found.add(value.casefold())
    return found


def _probe_profile(store: Store, profiles: list[Profile]) -> None:
    """Run a per-profile probe (AWS: one call per named profile)."""
    probe = store.probe
    assert probe is not None
    name = profiles[0].name

    if name.startswith("-"):
        # Substituted as its own argv element, so nothing can be injected,
        # but the provider CLI still reads it as an option and answers about
        # something other than this profile.
        _mark(profiles, UNKNOWN, "profile name starts with '-'")
        return

    argv = [arg.replace("{profile}", name) for arg in probe.argv]
    out, err = _run(argv, probe.timeout)

    if err == NO_CLI:
        _mark(profiles, NO_CLI, "CLI not installed")
        return
    if err:
        _mark(profiles, DEAD, err)
        return

    _mark(profiles, LIVE, _extract(probe, out))


def _probe_store(result: StoreResult) -> None:
    """Run one probe for the whole store, then match profiles by name.

    Works for ``gcloud auth list``, ``gh auth status`` and
    ``kubectl config current-context``, all of which echo the identity back.
    """
    store = result.store
    probe = store.probe
    assert probe is not None
    out, err = _run(list(probe.argv), probe.timeout)

    by_name = groups(result)
    if err == NO_CLI:
        for profiles in by_name.values():
            _mark(profiles, NO_CLI, "CLI not installed")
        return
    if err:
        for profiles in by_name.values():
            _mark(profiles, DEAD, err)
        return

    haystack = out or ""
    named = _json_identities(haystack)
    detail = _extract(probe, haystack)
    for name, profiles in by_name.items():
        live = name.casefold() in named if named else _mentions(haystack, name)
        if live:
            _mark(profiles, LIVE, detail)
        # Not mentioned is not proof of death: a perfectly valid kube context
        # simply isn't the current one. Leave the offline status alone.


def check(results: list[StoreResult], workers: int = 8) -> None:
    """Probe every found store in parallel, mutating profile statuses in place."""
    jobs: list[tuple[concurrent.futures.Future, list[Profile]]] = []
    budget = 0
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    try:
        for result in results:
            probe = result.store.probe
            if probe is None or not result.found:
                continue
            by_name = groups(result)
            if not by_name:
                continue
            budget = max(budget, probe.timeout)
            if any("{profile}" in arg for arg in probe.argv):
                for profiles in by_name.values():
                    jobs.append(
                        (pool.submit(_probe_profile, result.store, profiles), profiles)
                    )
            else:
                every = [prof for profiles in by_name.values() for prof in profiles]
                jobs.append((pool.submit(_probe_store, result), every))
        _collect(jobs, budget + DEADLINE_GRACE)
    finally:
        # Never block on a straggler: each probe kills its own child at its
        # own timeout, so a thread outliving the deadline still ends on its
        # own. Waiting here would give the deadline away.
        pool.shutdown(wait=False, cancel_futures=True)


def _collect(
    jobs: list[tuple[concurrent.futures.Future, list[Profile]]], deadline: float
) -> None:
    """Read every future, so a probe that raised says so instead of vanishing."""
    end = time.monotonic() + deadline
    for job, profiles in jobs:
        try:
            job.result(timeout=max(0.0, end - time.monotonic()))
        except concurrent.futures.TimeoutError:
            _mark(profiles, UNKNOWN, "timed out")
        except concurrent.futures.CancelledError:
            _mark(profiles, UNKNOWN, "timed out")
        except Exception as exc:  # a bug in a probe is a fact about it, not a crash
            _mark(profiles, UNKNOWN, f"probe failed ({type(exc).__name__})")
