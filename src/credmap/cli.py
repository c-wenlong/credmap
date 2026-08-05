"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .doctor import diagnose
from .liveness import check as run_liveness
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


def cmd_scan(args) -> int:
    results = scan(load())
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
    results = scan(load())
    if args.json:
        sys.stdout.write(to_json([result_to_dict(r) for r in results]))
        return 0
    sys.stdout.write(render_paths(results, styler(), only_found=args.found))
    return 0


def cmd_where(args) -> int:
    matches = find(load(), args.query)
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
    matches = find(load(), args.store)
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
    results = scan(load())
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


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    # "scan" is the default verb, so `credmap --all` means `credmap scan --all`.
    if not raw:
        raw = ["scan"]
    elif raw[0] not in HANDLERS and raw[0] not in ("-h", "--help", "--version"):
        raw = ["scan", *raw]

    args = build_parser().parse_args(raw)
    try:
        return HANDLERS[args.cmd](args)
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
