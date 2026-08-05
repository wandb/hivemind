"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .errors import ImporterError
from .importer import ImportConfig, run_import


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hivemind-weave",
        description="Import recent personal HiveMind chats into Weave Agents.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    import_parser = subparsers.add_parser(
        "import",
        help="import sessions active within the latest N days",
    )
    import_parser.add_argument("--days", type=int, required=True, help="activity window (1-365)")
    import_parser.add_argument(
        "--project",
        default="wandb/hivemind-chats",
        help="destination in entity/project form (default: %(default)s)",
    )
    import_parser.add_argument(
        "--idle-minutes",
        type=int,
        default=10,
        help="defer sessions active within this grace period (default: %(default)s)",
    )
    import_parser.add_argument(
        "--state-path",
        type=Path,
        default=Path("~/.hivemind/weave-importer/state.sqlite3"),
        help="SQLite checkpoint path (default: %(default)s)",
    )
    import_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="discover, redact, map, and count without Weave or state writes",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "import":
        parser.error("a command is required")
    try:
        config = ImportConfig(
            days=args.days,
            project=args.project,
            idle_minutes=args.idle_minutes,
            state_path=args.state_path,
            dry_run=args.dry_run,
        )
        config.validate()
        mode = "dry run" if config.dry_run else "live import"
        print(f"Weave destination ({mode}): {config.project}", flush=True)
        report = run_import(config)
    except (ImporterError, ValueError) as error:
        print(f"Import failed: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(
            "Import interrupted; a later run will resume the saved worklist and "
            "reconcile pending turns.",
            file=sys.stderr,
        )
        return 130
    print(report.render(dry_run=args.dry_run))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
