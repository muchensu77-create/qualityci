from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

import qualityci.cli as cli_module
from qualityci.case_builder import build_case_from_pack
from qualityci.case_source_assurance import load_case_source_bundle
from qualityci.engine import run_case_with_source_bundle
from qualityci.store import QualityCIStore
from qualityci.validation_evidence import load_validation_evidence_bundle
from validation_support import validation_bundle


ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "datasets/qualityci-bench/tacoma_24v152"
CASE_PATH = BENCH / "baseline_v04.json"
REFERENCE_MANIFEST = BENCH / "reference_sources/manifest.json"
VALIDATION_MANIFEST = BENCH / "validation_sources/BASELINE/source/manifest.json"
SOURCE_MANIFEST = ROOT / "tests/fixtures/case_builder/manifest.json"
A08_TABLES = (
    "run_case_source_sets",
    "case_lineage_bindings",
    "case_source_members",
    "case_source_sets",
)


def _run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "qualityci.cli", *arguments],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validation_manifest(tmp_path: Path) -> Path:
    case = build_case_from_pack(SOURCE_MANIFEST)
    validation = validation_bundle(case, "SOURCE")
    validation_root = tmp_path / "validation"
    validation_root.mkdir()
    manifest = validation_root / "manifest.json"
    manifest.write_bytes(validation.canonical_manifest_bytes)
    for member in validation.members:
        (validation_root / member.filename).write_bytes(member.raw_bytes)
    return manifest


def test_direct_pass_is_evaluation_only_and_writes_no_output_or_database(
    tmp_path: Path,
) -> None:
    output = tmp_path / "existing-output.json"
    database = tmp_path / "existing-database.sqlite"
    output_bytes = b'{"sentinel":"output","generation":8}\n'
    database_bytes = b"not-a-database-but-direct-must-not-open-it\n"
    output.write_bytes(output_bytes)
    database.write_bytes(database_bytes)

    completed = _run_cli(
        "run",
        "--case",
        str(CASE_PATH),
        "--reference-manifest",
        str(REFERENCE_MANIFEST),
        "--validation-manifest",
        str(VALIDATION_MANIFEST),
        "--output",
        str(output),
        "--db",
        str(database),
    )

    assert completed.returncode == 1
    assert completed.stderr == ""
    assert "overall=PASS" in completed.stdout
    assert "trust=EVALUATION_UNBOUND trusted=false admission=BLOCKED" in completed.stdout
    assert "audit_store=NOT_WRITTEN" in completed.stdout
    assert "output=NOT_WRITTEN" in completed.stdout
    assert output.read_bytes() == output_bytes
    assert database.read_bytes() == database_bytes


def test_source_manifest_emits_bound_current_result_without_duplicate_reference(
    tmp_path: Path,
) -> None:
    output = tmp_path / "source-run.json"

    completed = _run_cli(
        "run",
        "--case-source-manifest",
        str(SOURCE_MANIFEST),
        "--output",
        str(output),
    )

    assert completed.returncode == 1  # R006 has no raw validation bundle here.
    assert completed.stderr == ""
    assert "output=NOT_WRITTEN" in completed.stdout
    assert not output.exists()

    result = run_case_with_source_bundle(load_case_source_bundle(SOURCE_MANIFEST))
    payload = result.to_dict()
    assert len(payload) == 22
    assert payload["run_result_contract_version"] == "qualityci-run-result-0.2"
    assert payload["run_identity_version"] == "qualityci-run-identity-v4"
    assert payload["case_source_assurance_state"] == "BOUND_RAW_SOURCE_CASE"
    assert payload["case_source_lineage_hash"] is None
    assert payload["reference_assurance_state"] == "ATTESTED_REFERENCE_SET"
    assert payload["validation_assurance_state"] == "UNATTESTED_VALIDATION_JSON"


def test_source_manifest_with_raw_validation_can_return_trusted_success(
    tmp_path: Path,
) -> None:
    validation_manifest = _validation_manifest(tmp_path)
    output = tmp_path / "source-pass.json"

    completed = _run_cli(
        "run",
        "--case-source-manifest",
        str(SOURCE_MANIFEST),
        "--validation-manifest",
        str(validation_manifest),
        "--output",
        str(output),
    )

    assert completed.returncode == 0
    assert completed.stderr == ""
    payload = json.loads(output.read_text("utf-8"))
    assert payload["overall_status"] == "PASS"
    assert payload["case_source_assurance_state"] == "BOUND_RAW_SOURCE_CASE"
    assert payload["reference_assurance_state"] == "ATTESTED_REFERENCE_SET"
    assert payload["validation_assurance_state"] == "ATTESTED_VALIDATION_SET"


def test_source_mutation_is_captured_as_derived_lineage(tmp_path: Path) -> None:
    mutation = tmp_path / "mutation.json"
    mutation.write_text(
        json.dumps(
            {
                "mutation_id": "A08-ENTRY-TITLE",
                "operations": [
                    {
                        "op": "set",
                        "target": "case",
                        "path": "title",
                        "value": "A08 source-rooted derived title",
                    }
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    output = tmp_path / "must-not-exist.json"
    derived = _run_cli(
        "run",
        "--case-source-manifest",
        str(SOURCE_MANIFEST),
        "--mutation",
        str(mutation),
        "--output",
        str(output),
    )

    assert derived.returncode == 1
    assert "overall=UNVERIFIABLE" in derived.stdout
    assert "output=NOT_WRITTEN" in derived.stdout
    assert not output.exists()

    from qualityci.case_source_assurance import load_case_mutation_bundle
    from qualityci.engine import run_case_with_source_mutation_bundle

    root_result = run_case_with_source_bundle(load_case_source_bundle(SOURCE_MANIFEST))
    derived_result = run_case_with_source_mutation_bundle(
        load_case_source_bundle(SOURCE_MANIFEST),
        load_case_mutation_bundle(mutation),
    )
    root_payload = root_result.to_dict()
    derived_payload = derived_result.to_dict()
    assert derived_payload["case_source_assurance_state"] == (
        "SOURCE_ROOTED_DERIVATION"
    )
    assert derived_payload["case_source_lineage_contract_version"] == (
        "qualityci-case-source-lineage-0.1"
    )
    assert len(derived_payload["case_source_lineage_hash"]) == 64
    assert derived_payload["case_source_set_hash"] == root_payload["case_source_set_hash"]
    assert derived_payload["case_source_binding_hash"] == (
        root_payload["case_source_binding_hash"]
    )
    assert derived_payload["case_hash"] != root_payload["case_hash"]


def test_existing_legacy_store_rejects_before_any_raw_source_read(
    tmp_path: Path,
) -> None:
    database = tmp_path / "legacy.sqlite"
    with QualityCIStore(database):
        pass
    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA foreign_keys = OFF")
        for table in A08_TABLES:
            connection.execute(f"DROP TABLE {table}")
        connection.commit()
    finally:
        connection.close()
    before = _sha(database)
    output = tmp_path / "must-not-exist.json"

    completed = _run_cli(
        "run",
        "--case-source-manifest",
        str(tmp_path / "missing-source-manifest.json"),
        "--db",
        str(database),
        "--output",
        str(output),
    )

    assert completed.returncode == 2
    assert completed.stderr == ""
    assert "A08_SCHEMA_MIGRATION_REQUIRED" in completed.stdout
    assert "cannot be resolved" not in completed.stdout
    assert _sha(database) == before
    assert not output.exists()


def test_bad_source_material_does_not_create_new_database_or_output(
    tmp_path: Path,
) -> None:
    database = tmp_path / "must-not-exist.sqlite"
    output = tmp_path / "must-not-exist.json"

    completed = _run_cli(
        "run",
        "--case-source-manifest",
        str(tmp_path / "missing-source-manifest.json"),
        "--db",
        str(database),
        "--output",
        str(output),
    )

    assert completed.returncode == 2
    assert completed.stderr == ""
    assert not database.exists()
    assert not output.exists()


def test_source_nonpass_preserves_existing_database_and_output_bytes(
    tmp_path: Path,
) -> None:
    database = tmp_path / "current.sqlite"
    output = tmp_path / "current.json"
    output_bytes = b'{"sentinel":"nonpass-output","generation":14}\n'
    output.write_bytes(output_bytes)
    with QualityCIStore(database):
        pass
    database_before = _sha(database)

    completed = _run_cli(
        "run",
        "--case-source-manifest",
        str(SOURCE_MANIFEST),
        "--db",
        str(database),
        "--output",
        str(output),
    )

    assert completed.returncode == 1
    assert "overall=UNVERIFIABLE" in completed.stdout
    assert "audit_store=NOT_WRITTEN" in completed.stdout
    assert "output=NOT_WRITTEN" in completed.stdout
    assert _sha(database) == database_before
    assert output.read_bytes() == output_bytes


def test_source_db_and_output_success_is_one_cli_boundary(tmp_path: Path) -> None:
    validation_manifest = _validation_manifest(tmp_path)
    database = tmp_path / "source.sqlite"
    output = tmp_path / "source.json"

    completed = _run_cli(
        "run",
        "--case-source-manifest",
        str(SOURCE_MANIFEST),
        "--validation-manifest",
        str(validation_manifest),
        "--db",
        str(database),
        "--output",
        str(output),
    )

    assert completed.returncode == 0
    assert completed.stderr == ""
    payload = json.loads(output.read_text("utf-8"))
    assert payload["overall_status"] == "PASS"
    with QualityCIStore(database, readonly=True) as store:
        assert store.require_a08_schema() is None
        assert store.verify_audit_chain() is True
        assert store.counts()["runs"] == 1


def test_store_fault_preserves_existing_database_and_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validation_manifest = _validation_manifest(tmp_path)
    database = tmp_path / "source.sqlite"
    output = tmp_path / "source.json"
    output_bytes = b'{"sentinel":"store-fault-output","generation":21}\n'
    output.write_bytes(output_bytes)
    with QualityCIStore(database):
        pass
    database_before = _sha(database)
    original_fault = QualityCIStore._fault_point

    def fail(store: QualityCIStore, stage: str) -> None:
        if stage == "a08_source_run_before_final_preflight":
            raise RuntimeError("injected Store business fault")
        original_fault(store, stage)

    monkeypatch.setattr(QualityCIStore, "_fault_point", fail)
    arguments = cli_module.build_parser().parse_args(
        [
            "run",
            "--case-source-manifest",
            str(SOURCE_MANIFEST),
            "--validation-manifest",
            str(validation_manifest),
            "--db",
            str(database),
            "--output",
            str(output),
        ]
    )
    with pytest.raises(RuntimeError, match="injected Store business fault"):
        cli_module.command_run(arguments)

    assert _sha(database) == database_before
    assert output.read_bytes() == output_bytes


def test_output_promotion_fault_rolls_back_committed_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validation_manifest = _validation_manifest(tmp_path)
    database = tmp_path / "source.sqlite"
    output = tmp_path / "source.json"
    output_bytes = b'{"sentinel":"replace-fault-output","generation":22}\n'
    output.write_bytes(output_bytes)
    with QualityCIStore(database):
        pass
    database_before = _sha(database)

    def fail_promotion(_staged: Path, _output: Path) -> None:
        raise OSError("injected output promotion fault")

    monkeypatch.setattr(cli_module, "_promote_staged_output", fail_promotion)
    arguments = cli_module.build_parser().parse_args(
        [
            "run",
            "--case-source-manifest",
            str(SOURCE_MANIFEST),
            "--validation-manifest",
            str(validation_manifest),
            "--db",
            str(database),
            "--output",
            str(output),
        ]
    )
    with pytest.raises(OSError, match="injected output promotion fault"):
        cli_module.command_run(arguments)

    assert _sha(database) == database_before
    assert output.read_bytes() == output_bytes


def test_case_and_source_manifest_are_mutually_exclusive(tmp_path: Path) -> None:
    output = tmp_path / "must-not-exist.json"
    completed = _run_cli(
        "run",
        "--case",
        str(CASE_PATH),
        "--case-source-manifest",
        str(SOURCE_MANIFEST),
        "--output",
        str(output),
    )

    assert completed.returncode == 2
    assert not output.exists()
