from __future__ import annotations

import os
import sqlite3
import stat
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from hivemind_weave import state as state_module
from hivemind_weave.errors import StateConflictError
from hivemind_weave.state import (
    DB_APPLICATION_ID,
    DB_SCHEMA_VERSION,
    ImportRun,
    ImportRunSession,
    StateRow,
    StateStore,
    SyncDiscoveryRecord,
)

PROJECT = "wandb/hivemind-chats"
ACTIVITY = datetime(2026, 8, 1, tzinfo=UTC)


def _config(*, project: str = PROJECT) -> dict[str, Any]:
    return {
        "days": 45,
        "idle_minutes": 10,
        "project": project,
        "session_ids": [],
        "verification_timeout": 60.0,
    }


def _create_ready_run(
    state: StateStore,
    *,
    turns: list[tuple[str, str]] | None = None,
    project: str = PROJECT,
    session_id: str = "session-1",
) -> tuple[ImportRun, ImportRunSession]:
    certified_turns = turns if turns is not None else [("turn-1", "a" * 64)]
    run = state.create_run(
        project=project,
        cutoff=datetime(2026, 8, 3, 12, 0, tzinfo=UTC),
        days=45,
        idle_minutes=10,
        config=_config(project=project),
        sessions=[(session_id, ACTIVITY)],
        discovered_count=1,
        deferred_count=0,
    )
    entry = state.get_run_sessions(run.run_id)[0]
    entry = state.certify_run_session(
        run_id=run.run_id,
        session_id=session_id,
        expected_revision=entry.revision,
        turns=certified_turns,
    )
    return state.seal_run(run), entry


def _begin_pending(
    state: StateStore,
    *,
    project: str = PROJECT,
    session_id: str = "session-1",
    turn_key: str = "turn-1",
    payload_sha256: str = "a" * 64,
) -> tuple[ImportRun, ImportRunSession, StateRow]:
    run, entry = _create_ready_run(
        state,
        turns=[(turn_key, payload_sha256)],
        project=project,
        session_id=session_id,
    )
    row = state.begin_pending(
        run_id=run.run_id,
        project=project,
        session_id=session_id,
        turn_key=turn_key,
        payload_sha256=payload_sha256,
        verification_signature="b" * 64,
        source_last_activity_at=ACTIVITY,
        atif_schema_version="ATIF-v1.7",
    )
    return run, entry, row


def _insert_legacy_pending(
    state: StateStore,
    *,
    payload_sha256: str = "a" * 64,
) -> StateRow:
    now = "2026-08-03T12:00:00Z"
    state.connection.execute(
        """
        INSERT INTO imported_turns (
            project, session_id, turn_key, payload_sha256, source_payload_sha256,
            verification_signature, status, source_last_activity_at,
            atif_schema_version, importer_version, created_at, updated_at
        ) VALUES (?, 'legacy-session', 'legacy-turn', ?, ?, ?, 'pending', ?, ?, ?, ?, ?)
        """,
        (
            PROJECT,
            payload_sha256,
            payload_sha256,
            "b" * 64,
            "2026-08-01T00:00:00Z",
            "ATIF-v1.7",
            "0.1.0",
            now,
            now,
        ),
    )
    state.connection.commit()
    row = state.get(PROJECT, "legacy-session", "legacy-turn")
    assert row is not None
    return row


def _create_legacy_journal(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.execute(
        """
        CREATE TABLE imported_turns (
            project TEXT NOT NULL, session_id TEXT NOT NULL, turn_key TEXT NOT NULL,
            payload_sha256 TEXT NOT NULL, verification_signature TEXT NOT NULL,
            status TEXT NOT NULL, source_last_activity_at TEXT NOT NULL,
            atif_schema_version TEXT NOT NULL, trace_ids_json TEXT NOT NULL DEFAULT '[]',
            root_span_ids_json TEXT NOT NULL DEFAULT '[]', span_count INTEGER NOT NULL DEFAULT 0,
            importer_version TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            imported_at TEXT, last_error TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (project, session_id, turn_key)
        )
        """
    )
    connection.execute(
        """
        INSERT INTO imported_turns (
            project, session_id, turn_key, payload_sha256, verification_signature,
            status, source_last_activity_at, atif_schema_version, trace_ids_json,
            root_span_ids_json, span_count, importer_version, created_at, updated_at
        ) VALUES (
            'e/p', 's', 't', 'legacy-hash', 'sig', 'committed',
            '2026-08-01T00:00:00Z', 'ATIF-v1.7', '["trace"]', '["root"]', 1,
            '0.1.0', '2026-08-01T00:00:00Z', '2026-08-01T00:00:00Z'
        )
        """
    )
    connection.commit()
    connection.close()
    path.chmod(0o600)


def test_existing_journal_migrates_transactionally_and_records_contract_version(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy.sqlite3"
    _create_legacy_journal(path)

    with StateStore(path) as state:
        row = state.get("e/p", "s", "t")
        tables = {
            item[0]
            for item in state.connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'"
            ).fetchall()
        }
        application_id = state.connection.execute("PRAGMA application_id").fetchone()[0]
        user_version = state.connection.execute("PRAGMA user_version").fetchone()[0]

    assert row is not None
    assert row.payload_sha256 == "legacy-hash"
    assert row.source_payload_sha256 == ""
    assert {"import_runs", "import_run_sessions", "import_run_turns"} <= tables
    assert application_id == DB_APPLICATION_ID
    assert user_version == DB_SCHEMA_VERSION


def test_failed_unversioned_migration_rolls_back_all_schema_changes(tmp_path: Path) -> None:
    path = tmp_path / "partial.sqlite3"
    _create_legacy_journal(path)
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE import_runs (run_id TEXT PRIMARY KEY)")
    connection.commit()
    connection.close()

    with pytest.raises((StateConflictError, sqlite3.Error)):
        StateStore(path)

    connection = sqlite3.connect(path)
    try:
        names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'"
            ).fetchall()
        }
        assert "imported_turns" in names
        assert "imported_turns_legacy" not in names
        assert connection.execute("PRAGMA application_id").fetchone()[0] == 0
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
    finally:
        connection.close()


def test_state_lifecycle_exact_membership_and_permissions(tmp_path: Path) -> None:
    path = tmp_path / "private" / "state.sqlite3"
    with StateStore(path) as state:
        run, entry, pending = _begin_pending(state)
        emitted = state.record_emitted(
            row=pending,
            trace_ids=["trace-1"],
            root_span_ids=["span-1"],
            span_count=3,
        )
        committed = state.mark_committed(row=emitted)
        state.mark_run_session_terminal(entry=entry, status="imported")
        state.complete_run(run)

        assert committed.status == "committed"
        assert committed.trace_ids == ["trace-1"]
        assert committed.root_span_ids == ["span-1"]
        assert committed.span_count == 3
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
        for candidate in (path, Path(f"{path}.lock"), Path(f"{path}-wal"), Path(f"{path}-shm")):
            if candidate.exists():
                assert stat.S_IMODE(candidate.stat().st_mode) == 0o600

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(Path(f"{path}.lock").stat().st_mode) == 0o600


def test_empty_session_is_the_only_success_without_turn_evidence(tmp_path: Path) -> None:
    with StateStore(tmp_path / "state.sqlite3") as state:
        run, entry = _create_ready_run(state, turns=[])
        state.mark_run_session_terminal(entry=entry, status="empty")
        state.complete_run(run)


def test_success_status_rejects_missing_certified_turn_evidence(tmp_path: Path) -> None:
    with StateStore(tmp_path / "state.sqlite3") as state:
        _run, entry = _create_ready_run(state)
        with pytest.raises(sqlite3.IntegrityError, match="lacks certified turn evidence"):
            state.mark_run_session_terminal(entry=entry, status="imported")
        state.connection.rollback()


def test_completion_revalidates_the_exact_sealed_turn_manifest(tmp_path: Path) -> None:
    with StateStore(tmp_path / "state.sqlite3") as state:
        run, entry, pending = _begin_pending(state)
        committed = state.mark_committed(row=pending)
        state.mark_run_session_terminal(entry=entry, status="imported")

        # Simulate corruption that bypassed the defensive triggers. Completion
        # still checks the sealed ordered turn certificate, not session ID alone.
        state.connection.execute("DROP TRIGGER import_run_turns_no_delete")
        state.connection.execute(
            "DELETE FROM import_run_turns WHERE run_id = ?",
            (run.run_id,),
        )
        state.connection.commit()
        assert committed.status == "committed"

        with pytest.raises(StateConflictError, match="turn certificate is incomplete"):
            state.complete_run(run)


def test_resume_revalidates_sealed_turn_manifest_before_processing(tmp_path: Path) -> None:
    config = _config()
    with StateStore(tmp_path / "state.sqlite3") as state:
        run, _entry = _create_ready_run(state)
        state.connection.execute("DROP TRIGGER import_run_turns_no_delete")
        state.connection.execute(
            "DELETE FROM import_run_turns WHERE run_id = ?",
            (run.run_id,),
        )
        state.connection.commit()
        with pytest.raises(StateConflictError, match="turn certificate is incomplete"):
            state.find_resumable_run(project=PROJECT, config=config)


def test_orphan_committed_turn_does_not_satisfy_run_membership(tmp_path: Path) -> None:
    with StateStore(tmp_path / "state.sqlite3") as state:
        run, entry = _create_ready_run(state)
        orphan = _insert_legacy_pending(state, payload_sha256="f" * 64)
        state.mark_committed(row=orphan)
        with pytest.raises(sqlite3.IntegrityError, match="lacks certified turn evidence"):
            state.mark_run_session_terminal(entry=entry, status="skipped")
        state.connection.rollback()
        with pytest.raises(StateConflictError, match="pending or unsuccessful"):
            state.complete_run(run)


def test_run_turns_cannot_be_added_changed_or_deleted_after_certification(
    tmp_path: Path,
) -> None:
    with StateStore(tmp_path / "state.sqlite3") as state:
        run, _entry = _create_ready_run(state)
        with pytest.raises(sqlite3.IntegrityError, match="only be added during"):
            state.connection.execute(
                """
                INSERT INTO import_run_turns (
                    run_id, session_id, ordinal, turn_key, source_payload_sha256
                ) VALUES (?, 'session-1', 1, 'late-turn', ?)
                """,
                (run.run_id, "c" * 64),
            )
        state.connection.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="certificate is immutable"):
            state.connection.execute(
                "UPDATE import_run_turns SET turn_key = 'changed' WHERE run_id = ?",
                (run.run_id,),
            )
        state.connection.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="certificate is immutable"):
            state.connection.execute(
                "DELETE FROM import_run_turns WHERE run_id = ?",
                (run.run_id,),
            )
        state.connection.rollback()


def test_pending_turn_must_be_bound_to_exact_ready_run_certificate(tmp_path: Path) -> None:
    with StateStore(tmp_path / "state.sqlite3") as state:
        run, _entry = _create_ready_run(state)
        for changes in (
            {"run_id": "missing"},
            {"project": "other/project"},
            {"turn_key": "other-turn"},
            {"payload_sha256": "f" * 64},
        ):
            arguments: dict[str, Any] = {
                "run_id": run.run_id,
                "project": PROJECT,
                "session_id": "session-1",
                "turn_key": "turn-1",
                "payload_sha256": "a" * 64,
                "verification_signature": "b" * 64,
                "source_last_activity_at": ACTIVITY,
                "atif_schema_version": "ATIF-v1.7",
            }
            arguments.update(changes)
            with pytest.raises(StateConflictError, match="bound to the certified"):
                state.begin_pending(**arguments)


def test_conflict_retains_original_hash(tmp_path: Path) -> None:
    with StateStore(tmp_path / "state.sqlite3") as state:
        _run, _entry, pending = _begin_pending(state)
        conflict = state.mark_conflict(row=pending, new_payload_sha256="f" * 64)
        assert conflict.status == "conflict"
        assert conflict.payload_sha256 == "a" * 64
        assert "f" * 64 in conflict.last_error


def test_unemitted_legacy_pending_payload_can_be_replaced_after_remote_absence(
    tmp_path: Path,
) -> None:
    with StateStore(tmp_path / "state.sqlite3") as state:
        pending = _insert_legacy_pending(state)
        conflict = state.mark_conflict(row=pending, new_payload_sha256="c" * 64)
        replaced = state.replace_unemitted_pending_payload(
            row=conflict,
            payload_sha256="c" * 64,
            verification_signature="d" * 64,
            source_last_activity_at=ACTIVITY,
            atif_schema_version="ATIF-v1.7",
        )
        assert replaced.status == "pending"
        assert replaced.payload_sha256 == "c" * 64
        assert replaced.source_payload_sha256 == "c" * 64
        assert replaced.verification_signature == "d" * 64


def test_payload_replacement_rejects_any_recorded_emission(tmp_path: Path) -> None:
    with StateStore(tmp_path / "state.sqlite3") as state:
        pending = _insert_legacy_pending(state)
        emitted = state.record_emitted(
            row=pending,
            trace_ids=["trace"],
            root_span_ids=["root"],
            span_count=1,
        )
        with pytest.raises(StateConflictError, match="emission evidence or state changed"):
            state.replace_unemitted_pending_payload(
                row=emitted,
                payload_sha256="c" * 64,
                verification_signature="d" * 64,
                source_last_activity_at=ACTIVITY,
                atif_schema_version="ATIF-v1.7",
            )


def test_record_emitted_can_replace_ids_after_proven_remote_absence(tmp_path: Path) -> None:
    with StateStore(tmp_path / "state.sqlite3") as state:
        pending = _insert_legacy_pending(state)
        first = state.record_emitted(
            row=pending,
            trace_ids=["old-trace"],
            root_span_ids=["old-root"],
            span_count=1,
        )
        second = state.record_emitted(
            row=first,
            trace_ids=["new-trace"],
            root_span_ids=["new-root"],
            span_count=2,
        )
        assert second.trace_ids == ["new-trace"]
        assert second.root_span_ids == ["new-root"]
        assert second.span_count == 2


def test_turn_updates_are_compare_and_swap_and_reject_stale_rows(tmp_path: Path) -> None:
    with StateStore(tmp_path / "state.sqlite3") as state:
        _run, _entry, pending = _begin_pending(state)
        refreshed = state.record_error(row=pending, error="first")
        assert refreshed.revision == pending.revision + 1
        with pytest.raises(StateConflictError, match="changed before"):
            state.record_error(row=pending, error="stale")
        with pytest.raises(StateConflictError, match="changed before"):
            state.record_emitted(
                row=pending,
                trace_ids=["trace"],
                root_span_ids=["root"],
                span_count=1,
            )


def test_session_updates_are_compare_and_swap_and_certificate_bound(tmp_path: Path) -> None:
    with StateStore(tmp_path / "state.sqlite3") as state:
        _run, entry = _create_ready_run(state, turns=[])
        updated = state.mark_run_session_issue(entry=entry, status="failed", error="retry")
        with pytest.raises(StateConflictError, match="state changed unexpectedly"):
            state.mark_run_session_terminal(entry=entry, status="empty")
        with pytest.raises(StateConflictError, match="turn certificate"):
            state.mark_run_session_terminal(
                entry=replace(updated, turn_set_sha256="tampered"),
                status="empty",
            )


def test_revision_triggers_reject_non_cas_direct_updates(tmp_path: Path) -> None:
    with StateStore(tmp_path / "state.sqlite3") as state:
        _run, _entry, _pending = _begin_pending(state)
        with pytest.raises(sqlite3.IntegrityError, match="revision was not advanced"):
            state.connection.execute("UPDATE imported_turns SET last_error = 'tampered'")
        state.connection.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="revision was not advanced"):
            state.connection.execute("UPDATE import_run_sessions SET last_error = 'tampered'")
        state.connection.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="revision was not advanced"):
            state.connection.execute("UPDATE import_runs SET updated_at = updated_at")
        state.connection.rollback()


def test_state_process_lock_prevents_concurrent_importers(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    first = StateStore(path)
    try:
        with pytest.raises(StateConflictError, match="another importer"):
            StateStore(path)
    finally:
        first.close()
    with StateStore(path):
        pass


def test_manifest_summary_tamper_is_detected(tmp_path: Path) -> None:
    config = _config()
    with StateStore(tmp_path / "state.sqlite3") as state:
        run = state.create_run(
            project=PROJECT,
            cutoff=datetime(2026, 8, 3, tzinfo=UTC),
            days=45,
            idle_minutes=10,
            config=config,
            sessions=[("session-a", ACTIVITY)],
            discovered_count=1,
            deferred_count=0,
        )
        state.connection.execute("DROP TRIGGER import_run_sessions_immutable")
        state.connection.execute(
            """
            UPDATE import_run_sessions
            SET summary_last_activity_at = '2026-08-02T00:00:00Z', revision = revision + 1
            WHERE run_id = ?
            """,
            (run.run_id,),
        )
        state.connection.commit()
        with pytest.raises(StateConflictError, match="integrity check"):
            state.find_resumable_run(project=PROJECT, config=config)


def test_create_run_prevents_multiple_active_runs(tmp_path: Path) -> None:
    with StateStore(tmp_path / "state.sqlite3") as state:
        _create_ready_run(state)
        with pytest.raises(StateConflictError, match="unfinished import run"):
            state.create_run(
                project=PROJECT,
                cutoff=datetime(2026, 8, 4, tzinfo=UTC),
                days=45,
                idle_minutes=10,
                config=_config(),
                sessions=[("session-2", ACTIVITY)],
                discovered_count=1,
                deferred_count=0,
            )


def test_multiple_unfinished_runs_fail_closed_even_if_index_was_bypassed(
    tmp_path: Path,
) -> None:
    config = _config()
    with StateStore(tmp_path / "state.sqlite3") as state:
        run = state.create_run(
            project=PROJECT,
            cutoff=datetime(2026, 8, 3, tzinfo=UTC),
            days=45,
            idle_minutes=10,
            config=config,
            sessions=[("session-a", ACTIVITY)],
            discovered_count=1,
            deferred_count=0,
        )
        state.connection.execute("DROP INDEX import_runs_one_active_project")
        state.connection.execute(
            """
            INSERT INTO import_runs (
                run_id, project, cutoff, days, idle_minutes, config_json, config_sha256,
                importer_version, schema_version, status, phase, session_count,
                discovered_count, deferred_count, manifest_sha256, total_turn_count,
                turn_manifest_sha256, created_at, updated_at, certified_at, completed_at,
                revision
            )
            SELECT
                'duplicate-run', project, cutoff, days, idle_minutes, config_json,
                config_sha256, importer_version, schema_version, status, phase,
                session_count, discovered_count, deferred_count, manifest_sha256,
                total_turn_count, turn_manifest_sha256, created_at, updated_at,
                certified_at, completed_at, revision
            FROM import_runs WHERE run_id = ?
            """,
            (run.run_id,),
        )
        state.connection.commit()
        with pytest.raises(StateConflictError, match="multiple unfinished"):
            state.find_resumable_run(project=PROJECT, config=config)


@pytest.mark.parametrize("sidecar", ["-wal", "-shm", "-journal"])
def test_preexisting_sidecar_symlinks_are_rejected_without_touching_target(
    tmp_path: Path,
    sidecar: str,
) -> None:
    path = tmp_path / "state.sqlite3"
    path.touch(mode=0o600)
    victim = tmp_path / "victim"
    victim.write_text("do-not-touch", encoding="utf-8")
    Path(f"{path}{sidecar}").symlink_to(victim)
    with pytest.raises(StateConflictError, match="symlink"):
        StateStore(path)
    assert victim.read_text(encoding="utf-8") == "do-not-touch"


@pytest.mark.parametrize("target", ["database", "lock"])
def test_database_and_lock_symlinks_are_rejected_without_touching_target(
    tmp_path: Path,
    target: str,
) -> None:
    path = tmp_path / "state.sqlite3"
    victim = tmp_path / "victim"
    victim.write_text("do-not-touch", encoding="utf-8")
    link = path if target == "database" else Path(f"{path}.lock")
    link.symlink_to(victim)
    with pytest.raises(StateConflictError, match="symlink"):
        StateStore(path)
    assert victim.read_text(encoding="utf-8") == "do-not-touch"


def test_symlinked_state_directory_is_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(StateConflictError, match="directory could not be opened safely"):
        StateStore(linked / "state.sqlite3")
    assert list(real.iterdir()) == []


def test_symlinked_state_directory_ancestor_is_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(StateConflictError, match="directory could not be opened safely"):
        StateStore(linked / "nested" / "state.sqlite3")
    assert list(real.iterdir()) == []


@pytest.mark.parametrize("target", ["database", "lock"])
def test_hard_linked_state_files_are_rejected(tmp_path: Path, target: str) -> None:
    path = tmp_path / "state.sqlite3"
    victim = tmp_path / "victim"
    victim.write_text("do-not-touch", encoding="utf-8")
    linked = path if target == "database" else Path(f"{path}.lock")
    os.link(victim, linked)
    with pytest.raises(StateConflictError, match="hard-linked"):
        StateStore(path)
    assert victim.read_text(encoding="utf-8") == "do-not-touch"


@pytest.mark.parametrize("kind", ["directory", "fifo"])
def test_non_regular_database_nodes_are_rejected(tmp_path: Path, kind: str) -> None:
    path = tmp_path / "state.sqlite3"
    if kind == "directory":
        path.mkdir()
    else:
        os.mkfifo(path)
    with pytest.raises(StateConflictError, match="state database file"):
        StateStore(path)


def test_parent_traversal_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "child" / ".." / "state.sqlite3"
    with pytest.raises(StateConflictError, match="parent-directory traversal"):
        StateStore(path)


def test_hostile_umask_still_produces_private_modes(tmp_path: Path) -> None:
    path = tmp_path / "private" / "state.sqlite3"
    prior = os.umask(0)
    try:
        with StateStore(path) as state:
            state.connection.execute("CREATE TEMP TABLE force_write (value TEXT)")
            state.connection.execute("INSERT INTO force_write VALUES ('x')")
            for candidate in (
                path,
                Path(f"{path}.lock"),
                Path(f"{path}-wal"),
                Path(f"{path}-shm"),
            ):
                if candidate.exists():
                    assert stat.S_IMODE(candidate.stat().st_mode) == 0o600
            assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    finally:
        os.umask(prior)


def test_existing_state_directory_permissions_are_not_changed(tmp_path: Path) -> None:
    parent = tmp_path / "shared"
    parent.mkdir(mode=0o750)
    before = stat.S_IMODE(parent.stat().st_mode)

    with pytest.raises(StateConflictError, match="refusing to change"):
        StateStore(parent / "state.sqlite3")

    assert stat.S_IMODE(parent.stat().st_mode) == before


def test_existing_state_file_permissions_are_not_changed(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    path.write_bytes(b"")
    path.chmod(0o640)

    with pytest.raises(StateConflictError, match="refusing to change"):
        StateStore(path)

    assert stat.S_IMODE(path.stat().st_mode) == 0o640


def test_database_inode_swap_during_connect_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "state.sqlite3"
    displaced = tmp_path / "displaced.sqlite3"
    real_connect = sqlite3.connect
    swapped = False

    def swapping_connect(database: Any, *args: Any, **kwargs: Any) -> sqlite3.Connection:
        nonlocal swapped
        if not swapped and Path(database) == path:
            swapped = True
            path.rename(displaced)
            path.touch(mode=0o600)
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(state_module.sqlite3, "connect", swapping_connect)
    with pytest.raises(StateConflictError, match="changed while it was opened"):
        StateStore(path)
    assert displaced.exists()


def test_parent_directory_swap_during_connect_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    path = parent / "state.sqlite3"
    displaced = tmp_path / "private-displaced"
    real_connect = sqlite3.connect
    swapped = False

    def swapping_connect(database: Any, *args: Any, **kwargs: Any) -> sqlite3.Connection:
        nonlocal swapped
        if not swapped and Path(database) == path:
            swapped = True
            parent.rename(displaced)
            parent.mkdir(mode=0o700)
            path.touch(mode=0o600)
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(state_module.sqlite3, "connect", swapping_connect)
    with pytest.raises(StateConflictError, match="directory changed while it was opened"):
        StateStore(path)
    assert displaced.exists()


def test_schema_contract_rejects_same_named_wrong_trigger(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    with StateStore(path):
        pass
    connection = sqlite3.connect(path)
    connection.execute("DROP TRIGGER imported_turns_revision_guard")
    connection.execute(
        """
        CREATE TRIGGER imported_turns_revision_guard
        AFTER INSERT ON imported_turns BEGIN SELECT 1; END
        """
    )
    connection.commit()
    connection.close()
    with pytest.raises(StateConflictError, match="invalid contract"):
        StateStore(path)


def test_schema_contract_rejects_unexpected_objects(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    with StateStore(path):
        pass
    connection = sqlite3.connect(path)
    connection.execute("CREATE VIEW surprise AS SELECT 1 AS value")
    connection.commit()
    connection.close()
    with pytest.raises(StateConflictError, match="objects do not match"):
        StateStore(path)


def test_wrong_application_id_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA application_id=1234")
    connection.commit()
    connection.close()
    path.chmod(0o600)
    with pytest.raises(StateConflictError, match="different application"):
        StateStore(path)


def test_future_schema_version_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute(f"PRAGMA application_id={DB_APPLICATION_ID}")
    connection.execute(f"PRAGMA user_version={DB_SCHEMA_VERSION + 1}")
    connection.commit()
    connection.close()
    path.chmod(0o600)
    with pytest.raises(StateConflictError, match="newer than"):
        StateStore(path)


def test_atomic_turn_journal_guards_full_prepare_submit_get_ui_lifecycle(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    with StateStore(path) as state:
        planned = state.plan_atomic_turn(
            project=PROJECT,
            session_id="session-atomic",
            turn_key="turn-atomic",
            source_payload_sha256="a" * 64,
        )
        prepared = state.record_atomic_turn_prepared(
            planned,
            wire_sha256="b" * 64,
            logical_key="c" * 64,
            capability_version="historical-turn-v1",
            reference_count=2,
            span_count=4,
        )
        submitting = state.begin_atomic_turn_submit(prepared)
        uncertain = state.mark_atomic_turn_uncertain(submitting)
        resubmitting = state.begin_atomic_turn_submit(uncertain)
        uncertain = state.mark_atomic_turn_uncertain(resubmitting)
        acknowledged = state.record_atomic_turn_acknowledged(
            uncertain,
            commit_id="commit-1",
            trace_ids=["trace-1"],
            root_span_ids=["root-1"],
        )
        committed = state.commit_atomic_turn(acknowledged)

        assert planned.status == "planned"
        assert prepared.status == "prepared"
        assert submitting.status == "submitting"
        assert uncertain.status == "uncertain"
        assert acknowledged.status == "acknowledged"
        assert committed.status == "committed"
        assert committed.source_payload_sha256 == "a" * 64
        assert committed.wire_sha256 == "b" * 64
        assert committed.logical_key == "c" * 64
        assert committed.capability_version == "historical-turn-v1"
        assert committed.reference_count == 2
        assert committed.span_count == 4
        assert committed.commit_id == "commit-1"
        assert committed.trace_ids == ("trace-1",)
        assert committed.root_span_ids == ("root-1",)
        assert committed.revision == 7
        assert state.get_unresolved_atomic_turns(PROJECT) == []

        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            state.connection.execute(
                """
                UPDATE atomic_turn_certificates SET wire_sha256 = ?
                WHERE project = ? AND session_id = ? AND turn_key = ?
                """,
                ("d" * 64, PROJECT, "session-atomic", "turn-atomic"),
            )
        state.connection.rollback()


def test_atomic_turn_certificate_or_returned_evidence_drift_becomes_conflict(
    tmp_path: Path,
) -> None:
    with StateStore(tmp_path / "state.sqlite3") as state:
        planned = state.plan_atomic_turn(
            project=PROJECT,
            session_id="session-drift",
            turn_key="turn-drift",
            source_payload_sha256="a" * 64,
        )
        prepared = state.record_atomic_turn_prepared(
            planned,
            wire_sha256="b" * 64,
            logical_key="c" * 64,
            capability_version="historical-turn-v1",
            reference_count=0,
            span_count=2,
        )
        with pytest.raises(StateConflictError, match="prepared certificate changed"):
            state.record_atomic_turn_prepared(
                prepared,
                wire_sha256="d" * 64,
                logical_key="c" * 64,
                capability_version="historical-turn-v1",
                reference_count=0,
                span_count=2,
            )
        conflicted = state.get_atomic_turn(PROJECT, "session-drift", "turn-drift")
        assert conflicted is not None and conflicted.status == "conflict"

        planned_receipt = state.plan_atomic_turn(
            project=PROJECT,
            session_id="session-receipt",
            turn_key="turn-receipt",
            source_payload_sha256="e" * 64,
        )
        prepared_receipt = state.record_atomic_turn_prepared(
            planned_receipt,
            wire_sha256="f" * 64,
            logical_key="1" * 64,
            capability_version="historical-turn-v1",
            reference_count=0,
            span_count=1,
        )
        submitting = state.begin_atomic_turn_submit(prepared_receipt)
        acknowledged = state.record_atomic_turn_acknowledged(
            submitting,
            commit_id="commit-stable",
            trace_ids=["trace-stable"],
            root_span_ids=["root-stable"],
        )
        with pytest.raises(StateConflictError, match="returned evidence changed"):
            state.record_atomic_turn_acknowledged(
                acknowledged,
                commit_id="commit-changed",
                trace_ids=["trace-stable"],
                root_span_ids=["root-stable"],
            )
        receipt_conflict = state.get_atomic_turn(PROJECT, "session-receipt", "turn-receipt")
        assert receipt_conflict is not None
        assert receipt_conflict.status == "conflict"
        assert receipt_conflict.commit_id == "commit-stable"


def test_atomic_turn_invalid_or_stale_transitions_fail_closed(tmp_path: Path) -> None:
    with StateStore(tmp_path / "state.sqlite3") as state:
        planned = state.plan_atomic_turn(
            project=PROJECT,
            session_id="session-stale",
            turn_key="turn-stale",
            source_payload_sha256="a" * 64,
        )
        with pytest.raises(StateConflictError, match="prepared or proven absent"):
            state.begin_atomic_turn_submit(planned)
        prepared = state.record_atomic_turn_prepared(
            planned,
            wire_sha256="b" * 64,
            logical_key="c" * 64,
            capability_version="historical-turn-v1",
            reference_count=0,
            span_count=1,
        )
        with pytest.raises(StateConflictError, match="acknowledged"):
            state.commit_atomic_turn(prepared)
        state.begin_atomic_turn_submit(prepared)
        with pytest.raises(StateConflictError, match="changed unexpectedly"):
            state.begin_atomic_turn_submit(prepared)


def test_deferred_sync_worklist_and_candidate_digest_are_stable(tmp_path: Path) -> None:
    project = "wandb/sync-ledger"
    since = datetime(2026, 8, 1, tzinfo=UTC)
    cutoff = datetime(2026, 8, 5, tzinfo=UTC)
    records = [
        SyncDiscoveryRecord(
            session_id="later-id",
            started_at=since,
            last_activity_at=datetime(2026, 8, 4, 12, tzinfo=UTC),
            activity_known=True,
            eligible_after=datetime(2026, 8, 7, tzinfo=UTC),
            status="deferred",
        ),
        SyncDiscoveryRecord(
            session_id="earlier-id",
            started_at=since,
            last_activity_at=datetime(2026, 8, 4, 13, tzinfo=UTC),
            activity_known=True,
            eligible_after=datetime(2026, 8, 6, tzinfo=UTC),
            status="deferred",
        ),
    ]
    with StateStore(tmp_path / "state.sqlite3") as state:
        first = state.record_sync_scan(
            project=project,
            config_sha256="a" * 64,
            since_utc=since,
            scan_started_at=cutoff,
            cutoff=cutoff,
            records=records,
        )
        deferred = state.get_deferred_sync_sessions(project)
        second = state.record_sync_scan(
            project=project,
            config_sha256="a" * 64,
            since_utc=since,
            scan_started_at=cutoff,
            cutoff=cutoff,
            records=list(reversed(records)),
        )

    assert [item.session_id for item in deferred] == ["earlier-id", "later-id"]
    assert len(first.candidate_universe_sha256) == 64
    assert second.candidate_universe_sha256 == first.candidate_universe_sha256


def test_schema_v5_migrates_atomically_to_v7_attempt_and_review_journals(
    tmp_path: Path,
) -> None:
    path = tmp_path / "v5.sqlite3"
    connection = sqlite3.connect(path)
    old_sync_feeds_sql = """
    CREATE TABLE sync_feeds (
        project TEXT PRIMARY KEY,
        config_sha256 TEXT NOT NULL CHECK(length(config_sha256) = 64),
        since_utc TEXT NOT NULL,
        successful_scan_watermark TEXT NOT NULL DEFAULT '',
        last_scan_started_at TEXT NOT NULL DEFAULT '',
        last_scan_succeeded_at TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """
    later_statements = set(
        (*state_module._ATOMIC_TURN_SCHEMA_SQL, *state_module._REVIEW_SCHEMA_SQL)
    )
    for statement in state_module._SCHEMA_SQL:
        if statement in later_statements:
            continue
        connection.execute(
            old_sync_feeds_sql if statement == state_module._SYNC_FEEDS_SQL else statement
        )
    connection.execute(f"PRAGMA application_id={DB_APPLICATION_ID}")
    connection.execute("PRAGMA user_version=5")
    connection.commit()
    connection.close()
    path.chmod(0o600)

    with StateStore(path) as state:
        version = state.connection.execute("PRAGMA user_version").fetchone()[0]
        columns = {
            str(row["name"])
            for row in state.connection.execute("PRAGMA table_info(sync_feeds)").fetchall()
        }
        tables = {
            str(row[0])
            for row in state.connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'"
            ).fetchall()
        }

    assert version == DB_SCHEMA_VERSION
    assert "candidate_universe_sha256" in columns
    assert {
        "atomic_turn_attempts",
        "atomic_turn_certificates",
        "atomic_turn_receipts",
    } <= tables
