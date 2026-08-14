from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import tempfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .case_builder import (
    build_case_from_pack,
)
from .case_source_assurance import (
    CASE_SOURCE_BOUND,
    CASE_SOURCE_DERIVED,
    load_case_mutation_bundle,
    load_case_source_bundle,
)
from .controlled_references import load_controlled_reference_bundle
from .authorization_records import load_authorization_record_bundle
from .authorization_authenticity import load_authorization_trust_snapshot_bundle
from .engine import (
    run_case,
    run_case_with_reference_bundle,
    run_case_with_evidence_bundles,
    run_case_with_source_bundle,
    run_case_with_source_mutation_bundle,
    _evaluate_case_source_bundle,
)
from .evaluation import evaluate_benchmark
from .loader import load_case, load_json
from .models import CheckStatus
from .revision_artifacts import load_revision_artifact_bundle
from .validation_evidence import load_validation_evidence_bundle
from .store import QualityCIStore, StoreIntegrityError
from .workflow import (
    ApprovalGateError,
    CaseMutationDerivationBundle,
    NativeReplayDerivationBundle,
    preview_resolution,
    replay_with_source_assurance,
)


def _print_run(result: Any) -> None:
    print(f"case={result.case_id} run={result.run_id} overall={result.overall_status}")
    for finding in result.findings:
        print(f"{finding.rule_id} {finding.status:<14} {finding.title}: {finding.summary}")


def command_run(args: argparse.Namespace) -> int:
    case_path = getattr(args, "case", None)
    source_manifest = getattr(args, "case_source_manifest", None)
    reference_manifest = getattr(args, "reference_manifest", None)
    validation_manifest = getattr(args, "validation_manifest", None)
    mutation_path = getattr(args, "mutation", None)
    if bool(case_path) == bool(source_manifest):
        raise ValueError(
            "run requires exactly one of --case or --case-source-manifest"
        )
    if source_manifest:
        if reference_manifest:
            raise ValueError(
                "run --case-source-manifest derives A03 from the same source pack; "
                "--reference-manifest is not accepted"
            )
        return _command_run_from_source(
            args,
            source_manifest,
            mutation_path,
            validation_manifest,
        )

    if validation_manifest and not reference_manifest:
        raise ValueError(
            "run --validation-manifest requires --reference-manifest"
        )
    case = load_case(case_path, mutation_path)
    reference_bundle = (
        load_controlled_reference_bundle(reference_manifest)
        if reference_manifest
        else None
    )
    validation_bundle = (
        load_validation_evidence_bundle(validation_manifest)
        if validation_manifest
        else None
    )
    result = (
        run_case_with_evidence_bundles(case, reference_bundle, validation_bundle)
        if reference_bundle is not None and validation_bundle is not None
        else (
            run_case_with_reference_bundle(case, reference_bundle)
            if reference_bundle is not None
            else run_case(case)
        )
    )
    print("trust=EVALUATION_UNBOUND trusted=false admission=BLOCKED")
    _print_run(result)
    if getattr(args, "db", None):
        print("audit_store=NOT_WRITTEN unbound serialized Case")
    if getattr(args, "output", None):
        print("output=NOT_WRITTEN unbound serialized Case")
    # Rule PASS is still observable as evaluation, but this lane never returns
    # trusted success and never creates a DB/output artifact.
    return 1


def _require_existing_a08_store_before_raw_read(database: Path) -> None:
    if not database.exists():
        if database.is_symlink():
            raise ValueError("audit database path must not be a symlink")
        return
    if database.is_symlink() or not database.is_file():
        raise ValueError("audit database path is not a regular file")
    with QualityCIStore(database, readonly=True) as store:
        store.require_a08_schema()


def _command_run_from_source(
    args: argparse.Namespace,
    source_manifest: str | Path,
    mutation_path: str | Path | None,
    validation_manifest: str | Path | None,
) -> int:
    database_value = getattr(args, "db", None)
    database = Path(database_value) if database_value else None
    output_value = getattr(args, "output", None)
    output = Path(output_value) if output_value else None
    if database is not None and output is not None:
        database_paths = {
            Path(f"{database}{suffix}").resolve()
            for suffix in ("", "-journal", "-wal", "-shm")
        }
        if output.resolve() in database_paths:
            raise ValueError("run --db and --output paths must be distinct")
    # A legacy/partial existing Store is rejected by a pure read before any
    # non-DB raw source is opened.  A missing path is deliberately not opened.
    if database is not None:
        _require_existing_a08_store_before_raw_read(database)

    source_bundle = load_case_source_bundle(source_manifest)
    mutation_bundle = (
        load_case_mutation_bundle(mutation_path) if mutation_path else None
    )
    validation_bundle = (
        load_validation_evidence_bundle(validation_manifest)
        if validation_manifest
        else None
    )
    # Close and validate all raw material before a new SQLite path can exist.
    result = (
        run_case_with_source_bundle(source_bundle, validation_bundle)
        if mutation_bundle is None
        else run_case_with_source_mutation_bundle(
            source_bundle,
            mutation_bundle,
            validation_bundle,
        )
    )
    if result.case_source_assurance_state not in {
        CASE_SOURCE_BOUND,
        CASE_SOURCE_DERIVED,
    }:
        raise AssertionError("source-rooted CLI received an unbound RunResult")
    _print_run(result)
    if result.overall_status != CheckStatus.PASS:
        if database is not None:
            print("audit_store=NOT_WRITTEN source-rooted quality gate did not pass")
        if output is not None:
            print("output=NOT_WRITTEN source-rooted quality gate did not pass")
        return 1

    rollback_root: Path | None = None
    staged_output: Path | None = None
    output_existed = False
    output_backup: Path | None = None
    database_backups: dict[Path, Path] = {}
    database_write_started = False
    output_promotion_started = False
    try:
        if database is not None or output is not None:
            rollback_root = Path(
                tempfile.mkdtemp(prefix="qualityci-a08-entry-rollback-")
            )
        if output is not None:
            output_existed, output_backup = _snapshot_output_for_rollback(
                output,
                rollback_root,
            )
            staged_output = _stage_json_output(output, result.to_dict())
        if database is not None:
            database_backups = _snapshot_database_for_rollback(
                database,
                rollback_root,
            )
            database_write_started = True
            with QualityCIStore(database) as store:
                store.require_a08_schema()
                stored_result = store.save_source_run_from_bundles(
                    source_bundle,
                    prior_derivations=(),
                    current_mutation=mutation_bundle,
                    validation_bundle=validation_bundle,
                )
                if stored_result.to_dict() != result.to_dict():
                    raise AssertionError(
                        "stored source Run differs from preflight evaluation"
                    )
                if not store.verify_audit_chain():
                    raise AssertionError("stored source Run audit chain is invalid")
                result = stored_result
            if staged_output is not None and output is not None:
                output_promotion_started = True
                _promote_staged_output(staged_output, output)
                staged_output = None
            print(f"audit_store={database} chain_valid=True")
        elif staged_output is not None and output is not None:
            output_promotion_started = True
            _promote_staged_output(staged_output, output)
            staged_output = None
    except BaseException:
        if database is not None and database_write_started:
            _restore_database_after_failure(database, database_backups)
        if output is not None and output_promotion_started:
            _restore_output_after_failure(output, output_existed, output_backup)
        raise
    finally:
        if staged_output is not None:
            staged_output.unlink(missing_ok=True)
        if rollback_root is not None:
            shutil.rmtree(rollback_root, ignore_errors=True)
    return 0


def command_bench(args: argparse.Namespace) -> int:
    root = Path(args.benchmark)
    report = evaluate_benchmark(root)
    print(report.synthetic_data_notice)
    print(
        " ".join(
            (
                f"mutations={report.mutations_evaluated}",
                f"rule_states={report.rule_states_correct}/{report.rule_states_evaluated}",
                f"state_accuracy={report.rule_state_accuracy:.4f}",
                f"mutation_pass_rate={report.mutation_pass_rate:.4f}",
                f"finding_f1={report.finding_f1:.4f}",
                f"evidence_present_rate={report.evidence_present_rate:.4f}",
            )
        )
    )
    if args.output:
        output = Path(args.output)
        _atomic_write_json(output, report.to_dict())
        print(f"report={output}")
    return 0 if report.baseline_all_rules_pass and report.mutation_pass_rate == 1.0 else 1


_PRIOR_MUTATION_DESCRIPTOR_KEYS = frozenset(
    {"operation_kind", "mutation_path"}
)
_PRIOR_NATIVE_DESCRIPTOR_KEYS = frozenset(
    {
        "operation_kind",
        "resolution_path",
        "approval_subject_path",
        "approval_assertions_path",
        "authorization_manifest_path",
        "authorization_trust_manifest_path",
        "replacement_manifest_path",
        "source_validation_manifest_path",
        "resolved_validation_manifest_path",
    }
)


def _exact_locator(value: Any, label: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"{label} must be an exact non-empty path locator")
    if any(ord(character) < 32 for character in value):
        raise ValueError(f"{label} contains control characters")
    return value


def _descriptor_locator(root: Path, value: Any, label: str) -> Path:
    locator_text = _exact_locator(value, label)
    locator = PurePosixPath(locator_text)
    if (
        locator.is_absolute()
        or bool(PureWindowsPath(locator_text).drive)
        or "\\" in locator_text
        or locator.as_posix() != locator_text
        or any(part in {"", ".", ".."} for part in locator.parts)
    ):
        raise ValueError(f"{label} must be one canonical relative path")
    # Keep the lexical path intact.  The descriptor is only a locator; the
    # real raw-material loader must perform the one authoritative open beneath
    # this same root instead of consuming a pre-resolved path under a new root.
    return root.joinpath(*locator.parts)


def _read_exact_json_object_bytes(
    path: str | Path,
    label: str,
    *,
    root_dir: str | Path | None = None,
) -> bytes:
    """Capture one ordinary JSON carrier once without canonicalizing its bytes."""

    from .ingestion import read_source_bytes
    from .loader import MAX_JSON_FILE_BYTES, strict_json_loads

    requested = Path(path)
    _name, _relative, raw = read_source_bytes(
        requested,
        root_dir=root_dir if root_dir is not None else requested.parent,
    )
    if len(raw) > MAX_JSON_FILE_BYTES:
        raise ValueError(f"{label} exceeds the JSON byte limit")
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeError, TypeError, ValueError) as error:
        raise ValueError(f"{label} must be strict UTF-8 JSON") from error
    if type(value) is not dict:
        raise ValueError(f"{label} must be an exact JSON object")
    return bytes(raw)


def _native_replay_bundle_from_locators(
    *,
    resolution_path: str | Path,
    approval_subject_path: str | Path,
    approval_assertions_path: str | Path,
    authorization_manifest_path: str | Path,
    authorization_trust_manifest_path: str | Path,
    replacement_manifest_path: str | Path,
    source_validation_manifest_path: str | Path,
    resolved_validation_manifest_path: str | Path,
    root_dir: str | Path | None = None,
) -> NativeReplayDerivationBundle:
    return NativeReplayDerivationBundle(
        native_resolution_bytes=_read_exact_json_object_bytes(
            resolution_path,
            "native resolution",
            root_dir=root_dir,
        ),
        approval_subject_bytes=_read_exact_json_object_bytes(
            approval_subject_path,
            "approval subject",
            root_dir=root_dir,
        ),
        approval_assertions_bytes=_read_exact_json_object_bytes(
            approval_assertions_path,
            "approval assertions",
            root_dir=root_dir,
        ),
        authorization_bundle=load_authorization_record_bundle(
            authorization_manifest_path,
            root_dir=root_dir,
        ),
        authorization_trust_bundle=load_authorization_trust_snapshot_bundle(
            authorization_trust_manifest_path,
            root_dir=root_dir,
        ),
        artifact_bundle=load_revision_artifact_bundle(
            replacement_manifest_path,
            root_dir=root_dir,
        ),
        source_validation_bundle=load_validation_evidence_bundle(
            source_validation_manifest_path,
            root_dir=root_dir,
        ),
        resolved_validation_bundle=load_validation_evidence_bundle(
            resolved_validation_manifest_path,
            root_dir=root_dir,
        ),
    )


def _load_prior_derivation_descriptor(
    descriptor_path: str | Path,
) -> CaseMutationDerivationBundle | NativeReplayDerivationBundle:
    requested = Path(descriptor_path)
    raw = _read_exact_json_object_bytes(requested, "prior derivation descriptor")
    from .loader import strict_json_loads

    descriptor = strict_json_loads(raw.decode("utf-8"))
    if type(descriptor) is not dict:
        raise AssertionError("validated descriptor is not an object")
    operation_kind = descriptor.get("operation_kind")
    if operation_kind == "MUTATION":
        if set(descriptor) != _PRIOR_MUTATION_DESCRIPTOR_KEYS:
            raise ValueError(
                "MUTATION prior descriptor requires only operation_kind and "
                "mutation_path"
            )
        return CaseMutationDerivationBundle(
            load_case_mutation_bundle(
                _descriptor_locator(
                    requested.parent,
                    descriptor["mutation_path"],
                    "prior mutation_path",
                ),
                root_dir=requested.parent,
            )
        )
    if operation_kind == "NATIVE_REPLAY":
        if set(descriptor) != _PRIOR_NATIVE_DESCRIPTOR_KEYS:
            raise ValueError(
                "NATIVE_REPLAY prior descriptor has an unsupported locator shape"
            )
        paths = {
            key.removesuffix("_path"): _descriptor_locator(
                requested.parent,
                descriptor[key],
                f"prior {key}",
            )
            for key in _PRIOR_NATIVE_DESCRIPTOR_KEYS
            if key != "operation_kind"
        }
        return _native_replay_bundle_from_locators(
            resolution_path=paths["resolution"],
            approval_subject_path=paths["approval_subject"],
            approval_assertions_path=paths["approval_assertions"],
            authorization_manifest_path=paths["authorization_manifest"],
            authorization_trust_manifest_path=paths[
                "authorization_trust_manifest"
            ],
            replacement_manifest_path=paths["replacement_manifest"],
            source_validation_manifest_path=paths[
                "source_validation_manifest"
            ],
            resolved_validation_manifest_path=paths[
                "resolved_validation_manifest"
            ],
            root_dir=requested.parent,
        )
    raise ValueError(
        "prior derivation descriptor operation_kind must be MUTATION or "
        "NATIVE_REPLAY"
    )


def _required_source_replay_locator(
    args: argparse.Namespace,
    attribute: str,
    option: str,
) -> str:
    value = getattr(args, attribute, None)
    if not value:
        raise ValueError(
            f"trusted replay --case-source-manifest requires {option}"
        )
    return _exact_locator(value, option)


def _current_native_replay_bundle(args: argparse.Namespace) -> NativeReplayDerivationBundle:
    return _native_replay_bundle_from_locators(
        resolution_path=_required_source_replay_locator(
            args, "resolution", "--resolution"
        ),
        approval_subject_path=_required_source_replay_locator(
            args, "approval_subject", "--approval-subject"
        ),
        approval_assertions_path=_required_source_replay_locator(
            args, "approval_assertions", "--approval-assertions"
        ),
        authorization_manifest_path=_required_source_replay_locator(
            args, "authorization_manifest", "--authorization-manifest"
        ),
        authorization_trust_manifest_path=_required_source_replay_locator(
            args,
            "authorization_trust_manifest",
            "--authorization-trust-manifest",
        ),
        replacement_manifest_path=_required_source_replay_locator(
            args, "replacement_manifest", "--replacement-manifest"
        ),
        source_validation_manifest_path=_required_source_replay_locator(
            args,
            "source_validation_manifest",
            "--source-validation-manifest",
        ),
        resolved_validation_manifest_path=_required_source_replay_locator(
            args,
            "resolved_validation_manifest",
            "--resolved-validation-manifest",
        ),
    )


def _command_legacy_replay_evaluation(args: argparse.Namespace) -> int:
    mutation_path = getattr(args, "mutation", None)
    if not mutation_path:
        raise ValueError("legacy replay --case requires --mutation")
    case = load_case(args.case, mutation_path)
    result = run_case(case)
    print(
        "trust=EVALUATION_UNBOUND trusted=false replay_admission=BLOCKED "
        "baseline=NOT_CREATED"
    )
    _print_run(result)
    if getattr(args, "db", None):
        print("audit_store=NOT_WRITTEN unbound serialized Case replay")
    if getattr(args, "output", None):
        print("output=NOT_WRITTEN unbound serialized Case replay")
    return 1


def command_replay(args: argparse.Namespace) -> int:
    case_path = getattr(args, "case", None)
    source_manifest = getattr(args, "case_source_manifest", None)
    if bool(case_path) == bool(source_manifest):
        raise ValueError(
            "replay requires exactly one of --case or --case-source-manifest"
        )
    if case_path:
        return _command_legacy_replay_evaluation(args)
    if getattr(args, "mutation", None):
        raise ValueError(
            "trusted replay uses ordered --prior-derivation descriptors; "
            "--mutation is not accepted"
        )
    if getattr(args, "reference_manifest", None):
        raise ValueError(
            "trusted replay derives root A03 from --case-source-manifest and "
            "does not accept --reference-manifest"
        )

    database_value = getattr(args, "db", None)
    database = Path(database_value) if database_value else None
    output_value = getattr(args, "output", None)
    output = Path(output_value) if output_value else None
    if database is not None and output is not None:
        database_paths = {
            Path(f"{database}{suffix}").resolve()
            for suffix in ("", "-journal", "-wal", "-shm")
        }
        if output.resolve() in database_paths:
            raise ValueError("replay --db and --output paths must be distinct")
    if database is not None:
        _require_existing_a08_store_before_raw_read(database)

    root_bundle = load_case_source_bundle(source_manifest)
    prior_derivations = tuple(
        _load_prior_derivation_descriptor(path)
        for path in (getattr(args, "prior_derivation", None) or ())
    )
    current_replay = _current_native_replay_bundle(args)
    try:
        native_replay = replay_with_source_assurance(
            root_bundle,
            prior_derivations,
            current_replay,
        )
    except ApprovalGateError as error:
        print(f"BLOCKED {error}")
        return 2
    replay = native_replay.replay
    if replay.before.case_source_assurance_state not in {
        CASE_SOURCE_BOUND,
        CASE_SOURCE_DERIVED,
    } or replay.after.case_source_assurance_state != CASE_SOURCE_DERIVED:
        raise AssertionError("trusted CLI replay received an invalid source tuple")
    print(f"before={replay.before.overall_status} after={replay.after.overall_status}")
    print(
        "approval=native-byte-bound-source-rooted "
        f"single_use={native_replay.replay_approval.single_use_status}"
    )
    if replay.baseline is None:
        print("baseline=NOT_CREATED unresolved checks remain")
        if database is not None:
            print("audit_store=NOT_WRITTEN source-rooted replay has no baseline")
        if output is not None:
            print("output=NOT_WRITTEN source-rooted replay has no baseline")
        return 1
    print(f"baseline={replay.baseline.baseline_id} status={replay.baseline.status}")

    rollback_root: Path | None = None
    staged_output: Path | None = None
    output_existed = False
    output_backup: Path | None = None
    database_backups: dict[Path, Path] = {}
    database_write_started = False
    output_promotion_started = False
    try:
        if database is not None or output is not None:
            rollback_root = Path(
                tempfile.mkdtemp(prefix="qualityci-a08-replay-rollback-")
            )
        if output is not None:
            output_existed, output_backup = _snapshot_output_for_rollback(
                output,
                rollback_root,
            )
            staged_output = _stage_json_output(output, native_replay.to_dict())
        if database is not None:
            database_backups = _snapshot_database_for_rollback(
                database,
                rollback_root,
            )
            database_write_started = True
            with QualityCIStore(database) as store:
                store.require_a08_schema()
                stored = store.save_native_replay_from_bundles(
                    root_bundle,
                    prior_derivations,
                    current_replay,
                )
                if stored.to_dict() != native_replay.to_dict():
                    raise AssertionError(
                        "stored source replay differs from preflight evaluation"
                    )
                if not store.verify_audit_chain():
                    raise AssertionError("stored source replay audit chain is invalid")
            if staged_output is not None and output is not None:
                output_promotion_started = True
                _promote_staged_output(staged_output, output)
                staged_output = None
            print(f"audit_store={database} chain_valid=True")
        elif staged_output is not None and output is not None:
            output_promotion_started = True
            _promote_staged_output(staged_output, output)
            staged_output = None
    except BaseException:
        if database is not None and database_write_started:
            _restore_database_after_failure(database, database_backups)
        if output is not None and output_promotion_started:
            _restore_output_after_failure(output, output_existed, output_backup)
        raise
    finally:
        if staged_output is not None:
            staged_output.unlink(missing_ok=True)
        if rollback_root is not None:
            shutil.rmtree(rollback_root, ignore_errors=True)
    return 0


def command_preview_resolution(args: argparse.Namespace) -> int:
    case = load_case(args.case, args.mutation)
    resolution = load_json(args.resolution)
    preview = preview_resolution(case, resolution)
    payload = preview.to_dict()
    print("state=PROPOSED_UNATTESTED trusted=false eligible_for_baseline=false")
    print("notice=estimated rule findings are not an attested PASS or actual RunResult")
    if args.output:
        _atomic_write_json(Path(args.output), payload)
    return 0


def command_audit(args: argparse.Namespace) -> int:
    database = Path(args.db)
    if not database.is_file():
        print(json.dumps({"database": args.db, "chain_valid": False, "error": "database_not_found"}, ensure_ascii=False))
        return 2
    try:
        with QualityCIStore(database, readonly=True) as store:
            if not store.has_required_schema():
                print(
                    json.dumps(
                        {
                            "database": args.db,
                            "chain_valid": False,
                            "error": "required_audit_tables_missing",
                        },
                        ensure_ascii=False,
                    )
                )
                return 2
            valid = store.verify_audit_chain()
            counts = store.counts()
    except StoreIntegrityError as error:
        error_code = (
            "required_audit_tables_missing"
            if str(error) == "A08_SCHEMA_PARTIAL_OR_UNKNOWN"
            else "invalid_audit_database"
        )
        print(
            json.dumps(
                {"database": args.db, "chain_valid": False, "error": error_code},
                ensure_ascii=False,
            )
        )
        return 2
    except sqlite3.Error:
        print(
            json.dumps(
                {"database": args.db, "chain_valid": False, "error": "invalid_audit_database"},
                ensure_ascii=False,
            )
        )
        return 2
    print(json.dumps({"database": args.db, "chain_valid": valid, "counts": counts}, ensure_ascii=False))
    return 0 if valid else 1


def command_build_case(args: argparse.Namespace) -> int:
    if args.run:
        # The same exact raw bundle produces both the serialized Case and the
        # source-rooted v4 gate.  The private evaluation owns one rebuilt source
        # context, so this path neither reopens the pack nor falls back to the
        # old reference-only Builder helper.
        source_bundle = load_case_source_bundle(args.manifest)
        validation_manifest = getattr(args, "validation_manifest", None)
        validation_bundle = (
            load_validation_evidence_bundle(validation_manifest)
            if validation_manifest
            else None
        )
        evaluation = _evaluate_case_source_bundle(
            source_bundle,
            validation_bundle=validation_bundle,
        )
        case = evaluation.case()
        result = evaluation.run
        if result.case_source_assurance_state != CASE_SOURCE_BOUND:
            raise AssertionError("build-case --run requires a bound raw source Run")
    else:
        case = build_case_from_pack(args.manifest)
        result = None
    if result is not None:
        _print_run(result)
        if result.overall_status != CheckStatus.PASS:
            print("output=NOT_WRITTEN quality gate did not pass")
            return 1
    output = Path(args.output)
    _atomic_write_json(output, case)
    print(
        f"case={case['case_id']} documents={len(case['documents'])} "
        f"output={output}"
    )
    return 0


def _stage_json_output(output: Path, payload: Any) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.",
        suffix=".tmp",
        dir=output.parent,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        return Path(temporary_name)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _promote_staged_output(staged: Path, output: Path) -> None:
    os.replace(staged, output)


def _atomic_write_json(output: Path, payload: Any) -> None:
    staged = _stage_json_output(output, payload)
    try:
        _promote_staged_output(staged, output)
    finally:
        staged.unlink(missing_ok=True)


def _snapshot_output_for_rollback(
    output: Path,
    rollback_root: Path | None,
) -> tuple[bool, Path | None]:
    if rollback_root is None:
        raise AssertionError("output rollback root is missing")
    if output.is_symlink():
        raise ValueError("output path must not be a symlink")
    if not output.exists():
        return False, None
    if not output.is_file():
        raise ValueError("output path is not a regular file")
    backup = rollback_root / "output.before"
    shutil.copy2(output, backup)
    return True, backup


def _database_artifact_paths(database: Path) -> tuple[Path, ...]:
    return tuple(
        Path(f"{database}{suffix}")
        for suffix in ("", "-journal", "-wal", "-shm")
    )


def _snapshot_database_for_rollback(
    database: Path,
    rollback_root: Path | None,
) -> dict[Path, Path]:
    if rollback_root is None:
        raise AssertionError("database rollback root is missing")
    backups: dict[Path, Path] = {}
    for index, path in enumerate(_database_artifact_paths(database)):
        if path.is_symlink():
            raise ValueError("audit database artifacts must not be symlinks")
        if not path.exists():
            continue
        if not path.is_file():
            raise ValueError("audit database artifact is not a regular file")
        backup = rollback_root / f"database.{index}.before"
        shutil.copy2(path, backup)
        backups[path] = backup
    return backups


def _restore_database_after_failure(
    database: Path,
    backups: dict[Path, Path],
) -> None:
    for path in _database_artifact_paths(database):
        if path.exists() or path.is_symlink():
            path.unlink()
    for path, backup in backups.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup, path)


def _restore_output_after_failure(
    output: Path,
    existed: bool,
    backup: Path | None,
) -> None:
    if output.exists() or output.is_symlink():
        output.unlink()
    if existed:
        if backup is None:
            raise AssertionError("existing output rollback backup is missing")
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup, output)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="qualityci")
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser("run", help="run a quality regression")
    run_input = run_parser.add_mutually_exclusive_group(required=True)
    run_input.add_argument(
        "--case",
        help="serialized Case evaluation only; never a trusted admission lane",
    )
    run_input.add_argument(
        "--case-source-manifest",
        help="exact five-member Case source pack for A08 source assurance",
    )
    run_parser.add_argument("--mutation")
    run_parser.add_argument("--reference-manifest")
    run_parser.add_argument("--validation-manifest")
    run_parser.add_argument("--output")
    run_parser.add_argument("--db", help="optional SQLite audit store")
    run_parser.set_defaults(func=command_run)
    bench_parser = subparsers.add_parser("bench", help="run mutation truth checks")
    bench_parser.add_argument(
        "--benchmark",
        required=True,
        help="benchmark directory containing baseline_v04.json and mutations/",
    )
    bench_parser.add_argument("--output")
    bench_parser.set_defaults(func=command_bench)
    replay_parser = subparsers.add_parser(
        "replay",
        help="evaluate an unbound replay or execute a source-rooted native replay",
    )
    replay_input = replay_parser.add_mutually_exclusive_group(required=True)
    replay_input.add_argument(
        "--case",
        help="serialized Case evaluation only; never a trusted replay lane",
    )
    replay_input.add_argument(
        "--case-source-manifest",
        help="exact root source pack for a trusted source-rooted replay",
    )
    replay_parser.add_argument(
        "--prior-derivation",
        action="append",
        default=[],
        help=(
            "ordered exact locator descriptor for one prior MUTATION or "
            "NATIVE_REPLAY; repeat in parent order"
        ),
    )
    replay_parser.add_argument("--mutation")
    replay_parser.add_argument("--resolution")
    replay_parser.add_argument("--approval-subject")
    replay_parser.add_argument("--approval-assertions")
    replay_parser.add_argument("--authorization-manifest")
    replay_parser.add_argument("--authorization-trust-manifest")
    replay_parser.add_argument("--replacement-manifest")
    replay_parser.add_argument("--reference-manifest")
    replay_parser.add_argument("--source-validation-manifest")
    replay_parser.add_argument("--resolved-validation-manifest")
    replay_parser.add_argument("--output")
    replay_parser.add_argument("--db", help="optional SQLite audit store")
    replay_parser.set_defaults(func=command_replay)
    preview_parser = subparsers.add_parser(
        "preview-resolution",
        help="preview an unattested structured patch without creating an actual run",
    )
    preview_parser.add_argument("--case", required=True)
    preview_parser.add_argument("--mutation", required=True)
    preview_parser.add_argument("--resolution", required=True)
    preview_parser.add_argument("--output")
    preview_parser.set_defaults(func=command_preview_resolution)
    audit_parser = subparsers.add_parser("audit", help="verify the local audit hash chain")
    audit_parser.add_argument("--db", required=True)
    audit_parser.set_defaults(func=command_audit)
    build_case_parser = subparsers.add_parser(
        "build-case",
        help="build a synthetic Case JSON from an explicit five-table manifest",
    )
    build_case_parser.add_argument("--manifest", required=True)
    build_case_parser.add_argument("--output", required=True)
    build_case_parser.add_argument("--validation-manifest")
    build_case_parser.add_argument(
        "--run",
        action="store_true",
        help="run the deterministic quality gate after building the case",
    )
    build_case_parser.set_defaults(func=command_build_case)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except (
        json.JSONDecodeError,
        UnicodeError,
        OSError,
        sqlite3.Error,
        KeyError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
    ) as error:
        print(f"ERROR invalid input: {error}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
