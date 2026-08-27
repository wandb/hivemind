"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path

from . import __version__
from .backfill import (
    BackfillApplyConfig,
    BackfillPreviewConfig,
    apply_backfill,
    preview_backfill,
    resolve_backfill_window,
)
from .errors import BackfillError, ImporterError, ReviewMirrorError
from .importer import ImportConfig, run_import
from .review import (
    REVIEW_PROJECT,
    ReviewApplyConfig,
    ReviewPreviewConfig,
    ReviewReconcileConfig,
    ReviewRecoverPreflightConfig,
    apply_review,
    preview_review,
    reconcile_review,
    recover_preflight_review,
    review_status,
)
from .review_audit import ReviewAuditConfig, audit_review
from .scheduled_sync import (
    ScheduledSyncError,
    SyncConfig,
    SyncPaths,
    configure_scheduled_sync,
    inspect_scheduled_sync,
    install_scheduled_sync,
    load_sync_config,
    reconcile_scheduled_sync,
    run_sync_once_from_file,
    set_project_keychain_secret,
)
from .utils import isoformat_z

_CANONICAL_BACKFILL_DISABLED = (
    "canonical backfill preview/apply is disabled in this experimental build; "
    "discard all pre-0.4 experimental state and use the explicitly noncanonical "
    "review workflow"
)
_CANONICAL_SYNC_DISABLED = (
    "canonical scheduled sync, scheduler authentication, status, and reconciliation "
    "are disabled in this experimental build; unload any previously installed "
    "LaunchAgent and do not reuse pre-0.4 experimental state"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hivemind-weave",
        description="Import recent personal HiveMind chats into Weave Agents.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    import_parser = subparsers.add_parser(
        "import",
        help="legacy discovery/mapping diagnostics (live writes disabled)",
    )
    import_parser.add_argument("--days", type=int, required=True, help="activity window (1-365)")
    import_parser.add_argument(
        "--project",
        required=True,
        help="explicit destination in entity/project form",
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
    import_parser.add_argument(
        "--confirm-project",
        default="",
        metavar="ENTITY/PROJECT",
        help="required for live import and must exactly match --project",
    )
    backfill_parser = subparsers.add_parser(
        "backfill",
        help="canonical historical backfill (disabled in this experimental build)",
    )
    backfill_parser.add_argument(
        "--project",
        default="",
        help="explicit destination for preview; optional on apply when --confirm-project is set",
    )
    backfill_parser.add_argument(
        "--preview",
        action="store_true",
        help="save a content-free plan without uploading",
    )
    backfill_parser.add_argument(
        "--plan",
        dest="plan_id",
        default="",
        help="apply an exact previously previewed plan by its printed alias or full ID",
    )
    backfill_parser.add_argument(
        "--plan-id",
        dest="plan_id",
        help=argparse.SUPPRESS,
    )
    backfill_parser.add_argument(
        "--since",
        help="inclusive ISO date or offset timestamp; mutually exclusive with --days",
    )
    backfill_parser.add_argument(
        "--until",
        help="exclusive ISO date or offset timestamp (default: captured current UTC time)",
    )
    backfill_parser.add_argument(
        "--days",
        type=int,
        help="deprecated calendar/UTC-day alias for --since (1-365)",
    )
    backfill_parser.add_argument(
        "--timezone",
        default=None,
        help="IANA timezone for date-only bounds (default: detected machine-local zone)",
    )
    backfill_parser.add_argument(
        "--canary",
        action="store_true",
        help="seal the first conservative whole-session canary instead of the full backlog",
    )
    backfill_parser.add_argument(
        "--agent",
        action="append",
        default=[],
        metavar="AGENT",
        help="exact source agent filter; repeat to match any listed agent",
    )
    backfill_parser.add_argument(
        "--repo",
        action="append",
        default=[],
        metavar="REPOSITORY",
        help="exact source repository filter; repeat to match any listed repository",
    )
    backfill_parser.add_argument(
        "--session-id",
        action="append",
        default=[],
        metavar="SESSION_ID",
        help="exact source session filter; repeat to select multiple sessions",
    )
    backfill_parser.add_argument(
        "--exclude-subagents",
        action="store_true",
        help="exclude sessions that have a parent HiveMind session",
    )
    backfill_parser.add_argument(
        "--max-sessions",
        type=int,
        default=None,
        help="maximum ordered plan sessions to apply this invocation (default: 1)",
    )
    backfill_parser.add_argument(
        "--state-path",
        type=Path,
        default=Path("~/.hivemind/weave-importer/state.sqlite3"),
        help="private SQLite plan/import state path (default: %(default)s)",
    )
    backfill_parser.add_argument(
        "--confirm-project",
        default="",
        metavar="ENTITY/PROJECT",
        help="required for apply and must exactly match --project",
    )

    review_parser = subparsers.add_parser(
        "review",
        help="manage the noncanonical content-object Agents review mirror",
    )
    review_subparsers = review_parser.add_subparsers(dest="review_command", required=True)
    review_state_default = Path("~/.hivemind/weave-importer/state.sqlite3")

    review_preview = review_subparsers.add_parser(
        "preview",
        help="seal a redacted, content-free review plan without uploading",
    )
    review_preview.add_argument("--since", required=True, help="inclusive RFC3339 timestamp")
    review_preview.add_argument(
        "--until",
        help="exclusive RFC3339 timestamp (default: captured current UTC time)",
    )
    review_preview.add_argument("--project", required=True)
    review_preview.add_argument("--agent", action="append", default=[])
    review_preview.add_argument("--repo", action="append", default=[])
    review_preview.add_argument("--session-id", action="append", default=[])
    review_preview.add_argument("--exclude-subagents", action="store_true")
    review_preview.add_argument("--canary", action="store_true")
    review_preview.add_argument(
        "--next-sessions",
        type=int,
        metavar="N",
        help=(
            "seal only the next 1-100 whole session revisions not already completed "
            "in this private project"
        ),
    )
    review_preview.add_argument(
        "--session-timeout-minutes",
        type=int,
        metavar="MINUTES",
        help=("hard 1-60 minute preparation deadline per session (default: 15)"),
    )
    review_preview.add_argument("--state-path", type=Path, default=review_state_default)

    review_apply = review_subparsers.add_parser(
        "apply",
        help="apply a bounded number of whole sessions from a sealed review plan",
    )
    review_apply.add_argument("--plan", dest="plan_id", required=True)
    review_apply.add_argument("--max-sessions", type=int, required=True)
    review_apply.add_argument("--confirm-project", required=True)
    review_apply.add_argument("--state-path", type=Path, default=review_state_default)

    review_status_parser = review_subparsers.add_parser(
        "status",
        help="show content-free local review progress",
    )
    review_status_parser.add_argument("--state-path", type=Path, default=review_state_default)

    review_audit = review_subparsers.add_parser(
        "audit",
        help="compare an exact HiveMind window with read-only local review evidence",
    )
    review_audit.add_argument("--since", required=True, help="inclusive RFC3339 timestamp")
    review_audit.add_argument(
        "--until",
        help="exclusive RFC3339 timestamp (default: captured current UTC time)",
    )
    review_audit.add_argument("--project", required=True)
    review_audit.add_argument("--exclude-subagents", action="store_true")
    review_audit.add_argument("--state-path", type=Path, default=review_state_default)

    review_reconcile = review_subparsers.add_parser(
        "reconcile",
        help="query exact root evidence without retrying an ambiguous submission",
    )
    review_reconcile.add_argument("--plan", dest="plan_id", required=True)
    review_reconcile.add_argument("--state-path", type=Path, default=review_state_default)

    review_recover = review_subparsers.add_parser(
        "recover-preflight",
        help="retire a proven zero-write source-drift plan without uploading",
    )
    review_recover.add_argument("--plan", dest="plan_id", required=True)
    review_recover.add_argument("--confirm-project", required=True)
    review_recover.add_argument("--state-path", type=Path, default=review_state_default)

    auth_parser = subparsers.add_parser(
        "auth",
        help="canonical scheduler authentication (disabled in this experimental build)",
    )
    auth_subparsers = auth_parser.add_subparsers(dest="auth_backend", required=True)
    keychain_parser = auth_subparsers.add_parser(
        "keychain", help="manage the project-scoped macOS Keychain item"
    )
    keychain_subparsers = keychain_parser.add_subparsers(dest="keychain_command", required=True)
    keychain_set = keychain_subparsers.add_parser("set", help="interactively store the W&B API key")
    keychain_set.add_argument("--project", required=True)

    default_sync_paths = SyncPaths.defaults()
    sync_parser = subparsers.add_parser(
        "sync",
        help="canonical incremental sync (disabled in this experimental build)",
    )
    sync_subparsers = sync_parser.add_subparsers(dest="sync_command", required=True)
    sync_configure = sync_subparsers.add_parser(
        "configure", help="save a secret-free incremental discovery policy"
    )
    sync_configure.add_argument("--since", required=True, help="inclusive date or timestamp")
    sync_configure.add_argument("--project", required=True)
    sync_configure.add_argument("--settle-minutes", type=int, default=60)
    sync_configure.add_argument("--timezone", default=None)
    sync_configure.add_argument(
        "--state-path",
        type=Path,
        default=Path("~/.hivemind/weave-importer/state.sqlite3"),
    )
    sync_configure.add_argument("--agent", action="append", default=[])
    sync_configure.add_argument("--repo", action="append", default=[])
    sync_configure.add_argument("--session-id", action="append", default=[])
    sync_configure.add_argument("--exclude-subagents", action="store_true")
    sync_configure.add_argument(
        "--config",
        type=Path,
        default=default_sync_paths.config_path,
        help=argparse.SUPPRESS,
    )

    sync_once = sync_subparsers.add_parser("once", help="run one bounded sync cycle")
    sync_once.add_argument(
        "--config",
        type=Path,
        default=default_sync_paths.config_path,
        help=argparse.SUPPRESS,
    )
    sync_install = sync_subparsers.add_parser(
        "install", help="install or update the macOS LaunchAgent"
    )
    sync_install.add_argument("--every-minutes", type=int, default=15)
    sync_install.add_argument(
        "--config",
        type=Path,
        default=default_sync_paths.config_path,
        help=argparse.SUPPRESS,
    )
    sync_status = sync_subparsers.add_parser("status", help="show content-free sync status")
    sync_status.add_argument(
        "--config",
        type=Path,
        default=default_sync_paths.config_path,
        help=argparse.SUPPRESS,
    )

    reconcile_parser = subparsers.add_parser(
        "reconcile",
        help="canonical sync reconciliation (disabled in this experimental build)",
    )
    reconcile_parser.add_argument(
        "--config",
        type=Path,
        default=default_sync_paths.config_path,
        help=argparse.SUPPRESS,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "import":
            config = ImportConfig(
                days=args.days,
                project=args.project,
                idle_minutes=args.idle_minutes,
                state_path=args.state_path,
                dry_run=args.dry_run,
                confirm_project=args.confirm_project,
            )
            config.validate()
            if not config.dry_run:
                raise ValueError(
                    "legacy live import is disabled; use backfill --preview and a sealed "
                    "--plan cohort"
                )
            mode = "dry run" if config.dry_run else "live import"
            print(f"Weave destination ({mode}): {config.project}", flush=True)
            report = run_import(config)
            rendered = report.render(dry_run=args.dry_run)
        elif args.command == "backfill":
            # Fail before project validation, HiveMind authentication/discovery, or
            # opening SQLite. The unreleased canonical planner previously derived a
            # durable plan binding from an account label, so none of its state may be
            # created or reused through the public CLI.
            raise ValueError(_CANONICAL_BACKFILL_DISABLED)
            if args.preview == bool(args.plan_id):
                raise ValueError("backfill requires exactly one of --preview or --plan")
            if args.preview:
                if not args.project:
                    raise ValueError("backfill preview requires --project")
                if args.max_sessions is not None or args.confirm_project:
                    raise ValueError(
                        "backfill preview does not accept apply-only --max-sessions or "
                        "--confirm-project"
                    )
                ImportConfig(days=1, project=args.project, dry_run=True).validate()
                if args.days is not None:
                    print(
                        "Warning: backfill --days is deprecated; use --since instead.",
                        file=sys.stderr,
                    )
                print(f"Weave destination (backfill preview): {args.project}", flush=True)
                report = preview_backfill(
                    BackfillPreviewConfig(
                        project=args.project,
                        state_path=args.state_path,
                        since=args.since,
                        until=args.until,
                        days=args.days,
                        timezone_name=args.timezone,
                        canary=args.canary,
                        agents=tuple(args.agent),
                        repositories=tuple(args.repo),
                        session_ids=tuple(args.session_id),
                        exclude_subagents=args.exclude_subagents,
                    )
                )
            else:
                if args.since is not None or args.until is not None or args.days is not None:
                    raise ValueError("--plan apply cannot override the sealed date window")
                if args.timezone is not None:
                    raise ValueError("--plan apply cannot override the sealed timezone")
                if args.canary:
                    raise ValueError("--canary is a preview-time membership selector")
                if args.agent or args.repo or args.session_id or args.exclude_subagents:
                    raise ValueError("--plan apply cannot override the sealed exact filters")
                project = args.project or args.confirm_project
                if not project:
                    raise ValueError("backfill apply requires --confirm-project")
                if args.project and args.project != args.confirm_project:
                    raise ValueError("--project and --confirm-project must exactly match")
                ImportConfig(days=1, project=project, dry_run=True).validate()
                print(f"Weave destination (backfill apply): {project}", flush=True)
                report = apply_backfill(
                    BackfillApplyConfig(
                        project=project,
                        confirm_project=args.confirm_project,
                        plan_id=args.plan_id,
                        state_path=args.state_path,
                        max_sessions=args.max_sessions if args.max_sessions is not None else 1,
                    )
                )
            rendered = report.render()
        elif args.command == "review":
            if args.review_command == "preview":
                if args.project != REVIEW_PROJECT:
                    raise ValueError(
                        f"review preview requires the fixed private project {REVIEW_PROJECT}"
                    )
                print(f"Weave destination (review preview): {args.project}", flush=True)
                report = preview_review(
                    ReviewPreviewConfig(
                        since=args.since,
                        until=args.until,
                        project=args.project,
                        state_path=args.state_path,
                        canary=args.canary,
                        next_sessions=args.next_sessions,
                        agents=tuple(args.agent),
                        repositories=tuple(args.repo),
                        session_ids=tuple(args.session_id),
                        exclude_subagents=args.exclude_subagents,
                        session_timeout_minutes=args.session_timeout_minutes,
                        progress=lambda message: print(message, flush=True),
                    )
                )
                rendered = report.render()
            elif args.review_command == "apply":
                if args.confirm_project != REVIEW_PROJECT:
                    raise ValueError(f"review apply requires --confirm-project {REVIEW_PROJECT}")
                print(
                    f"Weave destination (review apply): {args.confirm_project}",
                    flush=True,
                )
                report = apply_review(
                    ReviewApplyConfig(
                        plan_id=args.plan_id,
                        confirm_project=args.confirm_project,
                        state_path=args.state_path,
                        max_sessions=args.max_sessions,
                    )
                )
                rendered = report.render()
            elif args.review_command == "status":
                print(review_status(args.state_path, project=REVIEW_PROJECT))
                return 0
            elif args.review_command == "audit":
                if args.project != REVIEW_PROJECT:
                    raise ValueError(
                        f"review audit requires the fixed private project {REVIEW_PROJECT}"
                    )
                report = audit_review(
                    ReviewAuditConfig(
                        since=args.since,
                        until=args.until,
                        project=args.project,
                        state_path=args.state_path,
                        exclude_subagents=args.exclude_subagents,
                    )
                )
                rendered = report.render()
            elif args.review_command == "reconcile":
                print(
                    f"Weave destination (review reconcile): {REVIEW_PROJECT}",
                    flush=True,
                )
                report = reconcile_review(
                    ReviewReconcileConfig(
                        plan_id=args.plan_id,
                        state_path=args.state_path,
                    )
                )
                rendered = report.render()
            elif args.review_command == "recover-preflight":
                if args.confirm_project != REVIEW_PROJECT:
                    raise ValueError(
                        f"review recover-preflight requires --confirm-project {REVIEW_PROJECT}"
                    )
                print(
                    f"Weave destination (read-only preflight recovery): {REVIEW_PROJECT}",
                    flush=True,
                )
                report = recover_preflight_review(
                    ReviewRecoverPreflightConfig(
                        plan_id=args.plan_id,
                        confirm_project=args.confirm_project,
                        state_path=args.state_path,
                    )
                )
                rendered = report.render()
            else:  # pragma: no cover - guarded by argparse.
                parser.error("a review command is required")
        elif args.command == "auth":
            # This credential exists only for the disabled canonical scheduler.
            # Reject before prompting for, reading, or mutating a Keychain item.
            raise ValueError(_CANONICAL_SYNC_DISABLED)
            if args.auth_backend != "keychain" or args.keychain_command != "set":
                parser.error("an auth keychain command is required")
            set_project_keychain_secret(args.project)
            print(f"Keychain credential stored for project: {args.project}")
            return 0
        elif args.command == "sync":
            # The prior status implementation was not purely observational: it
            # checked Keychain state and opened a schema-migrating StateStore.
            # Disable every scheduler surface before config, status, SQLite,
            # Keychain, HiveMind, plist, or launchctl access.
            raise ValueError(_CANONICAL_SYNC_DISABLED)
            default_paths = SyncPaths.defaults()
            paths = replace(default_paths, config_path=args.config.expanduser())
            if args.sync_command == "configure":
                window = resolve_backfill_window(
                    since=args.since,
                    until=None,
                    days=None,
                    timezone_name=args.timezone,
                )
                config = SyncConfig(
                    project=args.project,
                    since=isoformat_z(window.since_utc),
                    timezone=window.timezone_name,
                    state_path=args.state_path,
                    settle_minutes=args.settle_minutes,
                    agents=tuple(args.agent),
                    repositories=tuple(args.repo),
                    session_ids=tuple(args.session_id),
                    include_subagents=not args.exclude_subagents,
                )
                configure_scheduled_sync(config, paths=paths)
                print(f"Incremental sync configured for project: {config.project}")
                return 0
            if args.sync_command == "once":
                config = load_sync_config(paths.config_path)
                print(f"Weave destination (incremental sync): {config.project}", flush=True)
                outcome = run_sync_once_from_file(paths.config_path, paths=paths)
                status = outcome.status
                if status is not None:
                    print(
                        f"Sync {status.state}: queued={status.eligible} "
                        f"deferred={status.deferred} imported={status.imported} "
                        f"attention={'yes' if status.requires_attention else 'no'}"
                    )
                return outcome.exit_code
            if args.sync_command == "install":
                if not 5 <= args.every_minutes <= 1_440:
                    raise ValueError("--every-minutes must be between 5 and 1440")
                config = replace(
                    load_sync_config(paths.config_path),
                    interval_seconds=args.every_minutes * 60,
                )
                inspection = install_scheduled_sync(config, paths=paths)
                print(
                    f"Incremental sync installed: every {args.every_minutes} minutes; "
                    f"loaded={'yes' if inspection.loaded else 'no'}"
                )
                return 0
            if args.sync_command == "status":
                config = load_sync_config(paths.config_path)
                inspection = inspect_scheduled_sync(paths=paths)
                print(f"Sync project: {config.project}")
                print(f"  state: {inspection.status.state}")
                print(f"  attention: {'yes' if inspection.status.requires_attention else 'no'}")
                print(f"  queued sessions: {inspection.queued_sessions}")
                print(f"  deferred sessions: {inspection.deferred_sessions}")
                print(f"  preflighted turns: {inspection.preflighted_turns}")
                print(f"  committed turns: {inspection.committed_turns}")
                print(f"  blocked items: {inspection.blocked_items}")
                print(f"  uncertain turns: {inspection.uncertain_turns}")
                print(f"  conflicted turns: {inspection.conflicted_turns}")
                print(f"  successful watermark: {inspection.successful_scan_watermark or '-'}")
                print(f"  next invocation: {inspection.next_scheduled_at or '-'}")
                print(f"  installed: {'yes' if inspection.installed else 'no'}")
                print(f"  loaded: {'yes' if inspection.loaded else 'no'}")
                print(f"  keychain available: {'yes' if inspection.keychain_available else 'no'}")
                return 0
            parser.error("a sync command is required")
        elif args.command == "reconcile":
            # Reject before loading scheduler config or attempting evidence-backed
            # source/Keychain/state reconciliation through the canonical planner.
            raise ValueError(_CANONICAL_SYNC_DISABLED)
            default_paths = SyncPaths.defaults()
            paths = replace(default_paths, config_path=args.config.expanduser())
            config = load_sync_config(paths.config_path)
            status = reconcile_scheduled_sync(config, paths=paths)
            print(
                "Sync reconciliation complete: "
                f"attention={'yes' if status.requires_attention else 'no'}"
            )
            return 0
        else:  # pragma: no cover - guarded by argparse's required subparser.
            parser.error("a command is required")
    except (ImporterError, ValueError) as error:
        if isinstance(
            error,
            (ValueError, BackfillError, ReviewMirrorError, ScheduledSyncError),
        ):
            message = str(error)
        else:
            message = "private failure details were withheld; inspect the private state/status"
        print(f"Import failed: {message}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(
            "Import interrupted; a later run will resume the saved worklist and "
            "reconcile pending turns.",
            file=sys.stderr,
        )
        return 130
    print(rendered)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
