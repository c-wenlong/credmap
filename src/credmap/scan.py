"""The scanner: walk the registry, stat what it points at, parse what exists."""

from __future__ import annotations

import os
from pathlib import Path

from .model import FoundPath, Store, StoreResult
from .parsers import parse
from .resolve import resolve


def scan_store(store: Store) -> StoreResult:
    result = StoreResult(store=store)
    for spec in store.paths:
        for path in resolve(spec):
            try:
                st = path.stat()
            except OSError:
                result.paths.append(FoundPath(spec=spec, path=path, exists=False))
                continue

            profiles, note = parse(path, spec)
            result.paths.append(
                FoundPath(
                    spec=spec,
                    path=path,
                    exists=True,
                    is_dir=path.is_dir(),
                    mode=st.st_mode & 0o777,
                    size=st.st_size,
                    profiles=profiles,
                    note=note,
                )
            )
    return result


def scan(stores: tuple[Store, ...]) -> list[StoreResult]:
    return [scan_store(store) for store in stores]


def dir_size(path: Path, limit_files: int = 200_000) -> int:
    """Recursive size in bytes, bounded so a pathological tree can't hang us."""
    total = 0
    seen = 0
    for root, _dirs, files in os.walk(path, onerror=lambda _e: None):
        for name in files:
            seen += 1
            if seen > limit_files:
                return total
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                continue
    return total
