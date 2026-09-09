"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys

from . import __version__, registry
from .doctor import diagnose
from .liveness import check as run_liveness
from .model import Store
from .registry import find, load
from .render import (
    findings_to_dict,
    render_findings,
    render_paths,
    render_scan,
    render_show,
    result_to_dict,
    styler,
    to_json,
)
from .scan import scan, scan_store

EPILOG = """\
examples:
  credmap                      what credential stores exist on this machine
  credmap where gcp            where do my Google credentials live
  credmap show aws             every AWS profile, secrets masked
  credmap doctor --check       find problems, verifying against each provider
  credmap paths                the full registry of known paths
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="credmap",
        description="Read-only discovery for credential stores scattered across your machine.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"credmap {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    def add(name: str, help_: str) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("--json", action="store_true", help="machine-readable output")
        return sp

    p_scan = add("scan", "list credential stores found on this machine (default)")
    p_scan.add_argument("--all", action="store_true", help="also list known-but-absent stores")
    p_scan.add_argument("--check", action="store_true", help="verify credentials still work")

    p_paths = add("paths", "the registry of known credential paths")
    p_paths.add_argument("--found", action="store_true", help="only paths that exist")

    p_where = add("where", "locate a provider's credentials")
    p_where.add_argument("query", help="provider name, alias or kind (e.g. gcp, aws, k8s)")

    p_show = add("show", "show one store in detail")
    p_show.add_argument("store", help="store id or alias")
    p_show.add_argument("--check", action="store_true", help="verify credentials still work")
    p_show.add_argument(
        "--reveal",
        action="store_true",
        help="print secret values in full (never implied by another flag)",
    )

    p_doctor = add("doctor", "report problems with the credentials found")
    p_doctor.add_argument("--check", action="store_true", help="verify credentials still work")

    return parser


def registry_stores() -> tuple[Store, ...]:
    """The registry, saying once on stderr if the overlay was refused.

    Silently ignoring an unsafe ``registry.toml`` would leave a user editing a
    file that has no effect, so the reason is printed — once per run, which is
    why the argv rewrite in :func:`main` uses ``load`` directly.
    """
    stores = load()
    if registry.OVERLAY_WARNING:
        print(f"credmap: {registry.OVERLAY_WARNING}", file=sys.stderr)
    return stores


def cmd_scan(args) -> int:
    results = scan(registry_stores())
    if args.check:
        run_liveness(results)
    if args.json:
        sys.stdout.write(
            to_json([result_to_dict(r) for r in results if args.all or r.found])
        )
        return 0
    sys.stdout.write(render_scan(results, styler(), show_all=args.all))
    return 0


def cmd_paths(args) -> int:
    results = scan(registry_stores())
    if args.json:
        payload = [result_to_dict(r) for r in results]
        if args.found:
            # --found is a filter on paths, and it has to mean the same thing
            # in both renderers: the table drops absent rows, so JSON drops
            # absent path entries and any store left with nothing to show.
            # "found" is left alone — whether a store is installed is judged
            # on its marker, which may be one of the paths just filtered out.
            for entry in payload:
                entry["paths"] = [p for p in entry["paths"] if p["exists"]]
            payload = [entry for entry in payload if entry["paths"]]
        sys.stdout.write(to_json(payload))
        return 0
    sys.stdout.write(render_paths(results, styler(), only_found=args.found))
    return 0


def cmd_where(args) -> int:
    matches = find(registry_stores(), args.query)
    if not matches:
        print(f"credmap: no store matches '{args.query}'", file=sys.stderr)
        print("try: credmap paths", file=sys.stderr)
        return 2

    results = [scan_store(store) for store in matches]
    if args.json:
        sys.stdout.write(to_json([result_to_dict(r) for r in results]))
        return 0

    style = styler()
    present = [r for r in results if r.found]
    sys.stdout.write(render_paths(results, style, only_found=False))
    if not present:
        sys.stdout.write(
            style.dim(f"\nnothing installed for '{args.query}' on this machine\n")
        )
    return 0


def cmd_show(args) -> int:
    matches = find(registry_stores(), args.store)
    if not matches:
        print(f"credmap: no store matches '{args.store}'", file=sys.stderr)
        return 2
    result = scan_store(matches[0])
    if args.check:
        run_liveness([result])
    if args.json:
        sys.stdout.write(to_json(result_to_dict(result, reveal=args.reveal)))
        return 0
    sys.stdout.write(render_show(result, styler(), reveal=args.reveal))
    return 0


def cmd_doctor(args) -> int:
    results = scan(registry_stores())
    if args.check:
        run_liveness(results)
    findings = diagnose(results)
    if args.json:
        sys.stdout.write(to_json(findings_to_dict(findings)))
    else:
        sys.stdout.write(render_findings(findings, styler()))
    return 1 if any(f.level == "error" for f in findings) else 0


HANDLERS = {
    "scan": cmd_scan,
    "paths": cmd_paths,
    "where": cmd_where,
    "show": cmd_show,
    "doctor": cmd_doctor,
}


def _rewrite(raw: list[str]) -> list[str]:
    """Supply the verb a bare invocation left out.

    Two shapes have no verb. ``credmap --all`` is scan with a flag, and
    ``credmap aws`` is a provider name — which used to become ``scan aws`` and
    die on argparse, when the only thing it could sensibly mean is ``where
    aws``. A first token that names nothing in the registry still falls
    through to ``scan``, so an unknown word is still rejected as one.
    """
    if not raw:
        return ["scan"]
    if raw[0] in HANDLERS or raw[0] in ("-h", "--help", "--version"):
        return raw
    if not raw[0].startswith("-") and find(load(), raw[0]):
        return ["where", *raw]
    return ["scan", *raw]


def main(argv: list[str] | None = None) -> int:
    raw = _rewrite(list(sys.argv[1:] if argv is None else argv))

    args = build_parser().parse_args(raw)
    try:
        return HANDLERS[args.cmd](args)
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
