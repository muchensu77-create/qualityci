import argparse
from pathlib import Path
import json
import os
import subprocess
import sys

import pytest

from qualityci.engine import run_case
from qualityci.loader import MAX_JSON_FILE_BYTES, load_case


ROOT = Path(__file__).parents[1]
BASE = ROOT / "datasets/qualityci-bench/tacoma_24v152"
NATIVE_CASE = BASE / "baseline_v04.json"
CASE_BUILDER_PACK = ROOT / "tests/fixtures/case_builder"
REFERENCE_MANIFEST = BASE / "reference_sources/manifest.json"
BASELINE_VALIDATION_MANIFEST = BASE / "validation_sources/BASELINE/source/manifest.json"
R001_SOURCE_VALIDATION_MANIFEST = BASE / "validation_sources/R001/source/manifest.json"
R001_RESOLVED_VALIDATION_MANIFEST = BASE / "validation_sources/R001/resolved/manifest.json"
BUILDER_VALIDATION_MANIFEST = CASE_BUILDER_PACK / "validation_manifest.json"
NATIVE_RESOLUTION = BASE / "resolutions/R001_resolve_stale_sop_native.json"
APPROVAL_SOURCE = BASE / "approval_sources/R001"


def _native_approval_arguments() -> tuple[str, ...]:
    return (
        "--resolution", str(NATIVE_RESOLUTION),
        "--approval-subject", str(APPROVAL_SOURCE / "approval_subject.json"),
        "--approval-assertions", str(APPROVAL_SOURCE / "approval_assertions.json"),
        "--authorization-manifest", str(APPROVAL_SOURCE / "authorization_a06/manifest.json"),
        "--authorization-trust-manifest",
        str(APPROVAL_SOURCE / "authorization_trust/snapshot.json"),
    )


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "qualityci.cli", *arguments],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_run_persists_and_audits(tmp_path):
    database = tmp_path / "audit.db"
    output = tmp_path / "run.json"
    run = _run(
        "run",
        "--case-source-manifest",
        str(CASE_BUILDER_PACK / "manifest.json"),
        "--validation-manifest",
        str(BUILDER_VALIDATION_MANIFEST),
        "--db",
        str(database),
        "--output",
        str(output),
    )
    assert run.returncode == 0, run.stderr
    assert "overall=PASS" in run.stdout
    assert "chain_valid=True" in run.stdout
    audit = _run("audit", "--db", str(database))
    assert audit.returncode == 0
    assert '"chain_valid": true' in audit.stdout
    assert '"runs": 1' in audit.stdout
    payload = json.loads(output.read_text("utf-8"))
    assert payload["case_source_assurance_state"] == "BOUND_RAW_SOURCE_CASE"
    assert len(payload["case_source_set_hash"]) == 64
    assert len(payload["case_source_binding_hash"]) == 64
    assert payload["case_source_lineage_hash"] is None
    assert payload["reference_assurance_state"] == "ATTESTED_REFERENCE_SET"
    assert len(payload["reference_set_hash"]) == 64
    assert payload["reference_contract_version"] == "qualityci-controlled-reference-0.1"


def test_cli_legacy_replay_is_evaluation_only_despite_native_flags(tmp_path):
    database = tmp_path / "replay.db"
    output = tmp_path / "replay.json"
    replay = _run(
        "replay",
        "--case", str(NATIVE_CASE),
        "--mutation", str(BASE / "mutations/M001_stale_sop_conflict.json"),
        *_native_approval_arguments(),
        "--replacement-manifest", str(BASE / "replacement_artifacts/R001/manifest.json"),
        "--reference-manifest", str(REFERENCE_MANIFEST),
        "--source-validation-manifest", str(R001_SOURCE_VALIDATION_MANIFEST),
        "--resolved-validation-manifest", str(R001_RESOLVED_VALIDATION_MANIFEST),
        "--db", str(database),
        "--output", str(output),
    )
    assert replay.returncode == 1
    assert replay.stderr == ""
    assert "trust=EVALUATION_UNBOUND trusted=false" in replay.stdout
    assert "replay_admission=BLOCKED baseline=NOT_CREATED" in replay.stdout
    assert "overall=CONTRADICTED" in replay.stdout
    assert "audit_store=NOT_WRITTEN" in replay.stdout
    assert "output=NOT_WRITTEN" in replay.stdout
    assert not database.exists()
    assert not output.exists()


def test_cli_legacy_replay_does_not_require_replacement_manifest():
    replay = _run(
        "replay",
        "--case", str(NATIVE_CASE),
        "--mutation", str(BASE / "mutations/M001_stale_sop_conflict.json"),
        *_native_approval_arguments(),
    )

    assert replay.returncode == 1
    assert replay.stderr == ""
    assert "trust=EVALUATION_UNBOUND trusted=false" in replay.stdout
    assert "replay_admission=BLOCKED baseline=NOT_CREATED" in replay.stdout
    assert "--replacement-manifest" not in replay.stderr
    assert "before=" not in replay.stdout


def test_cli_preview_is_explicitly_untrusted_and_not_an_actual_result(tmp_path):
    output = tmp_path / "proposal-preview.json"
    preview = _run(
        "preview-resolution",
        "--case", str(NATIVE_CASE),
        "--mutation", str(BASE / "mutations/M001_stale_sop_conflict.json"),
        "--resolution", str(BASE / "resolutions/R001_resolve_stale_sop.json"),
        "--output", str(output),
    )

    assert preview.returncode == 0, preview.stderr
    assert "state=PROPOSED_UNATTESTED trusted=false eligible_for_baseline=false" in preview.stdout
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["state"] == "PROPOSED_UNATTESTED"
    assert payload["trusted"] is False
    assert payload["eligible_for_baseline"] is False
    assert not ({"overall_status", "run_id", "case_hash", "baseline"} & set(payload))


def test_cli_legacy_replay_never_opens_store_or_replaces_output(tmp_path):
    output = tmp_path / "existing-replay.json"
    output_bytes = b'{"status":"KNOWN_GOOD","generation":8}\n'
    output.write_bytes(output_bytes)
    invalid_database = tmp_path / "database-is-a-directory"
    invalid_database.mkdir()
    before_database = invalid_database.stat()

    replay = _run(
        "replay",
        "--case", str(NATIVE_CASE),
        "--mutation", str(BASE / "mutations/M001_stale_sop_conflict.json"),
        *_native_approval_arguments(),
        "--replacement-manifest", str(BASE / "replacement_artifacts/R001/manifest.json"),
        "--reference-manifest", str(REFERENCE_MANIFEST),
        "--source-validation-manifest", str(R001_SOURCE_VALIDATION_MANIFEST),
        "--resolved-validation-manifest", str(R001_RESOLVED_VALIDATION_MANIFEST),
        "--db", str(invalid_database),
        "--output", str(output),
    )

    after_database = invalid_database.stat()
    assert replay.returncode == 1
    assert replay.stderr == ""
    assert "audit_store=NOT_WRITTEN" in replay.stdout
    assert "output=NOT_WRITTEN" in replay.stdout
    assert output.read_bytes() == output_bytes
    assert (after_database.st_size, after_database.st_mtime_ns) == (
        before_database.st_size,
        before_database.st_mtime_ns,
    )


def test_cli_bench_writes_full_synthetic_report(tmp_path):
    output = tmp_path / "bench.json"
    bench = _run("bench", "--benchmark", str(BASE), "--output", str(output))
    assert bench.returncode == 0, bench.stderr
    assert "mutations=30" in bench.stdout
    assert "not evidence of real-factory quality improvement" in bench.stdout
    assert '"rule_states_evaluated": 210' in output.read_text("utf-8")


def test_cli_build_case_creates_runnable_five_document_case(tmp_path):
    output = tmp_path / "built-case.json"

    built = _run(
        "build-case",
        "--manifest",
        str(CASE_BUILDER_PACK / "manifest.json"),
        "--validation-manifest",
        str(BUILDER_VALIDATION_MANIFEST),
        "--output",
        str(output),
        "--run",
    )

    assert built.returncode == 0, built.stderr
    assert "documents=5" in built.stdout
    assert "overall=PASS" in built.stdout
    rerun = _run("run", "--case", str(output))
    assert rerun.returncode == 1, rerun.stderr
    assert "overall=UNVERIFIABLE" in rerun.stdout


def test_cli_build_case_run_uses_one_raw_snapshot(tmp_path, monkeypatch):
    import qualityci.cli as cli_module

    original_loader = cli_module.load_case_source_bundle
    original_evaluate = cli_module._evaluate_case_source_bundle
    load_calls = 0
    evaluations = []

    def counted_loader(manifest):
        nonlocal load_calls
        load_calls += 1
        return original_loader(manifest)

    def counted_evaluate(source_bundle, *, validation_bundle=None):
        evaluation = original_evaluate(
            source_bundle,
            validation_bundle=validation_bundle,
        )
        evaluations.append(evaluation)
        return evaluation

    monkeypatch.setattr(
        cli_module, "load_case_source_bundle", counted_loader
    )
    monkeypatch.setattr(
        cli_module, "_evaluate_case_source_bundle", counted_evaluate
    )
    monkeypatch.setattr(
        cli_module,
        "build_case_from_pack",
        lambda _manifest: pytest.fail("build-case --run reopened the raw pack"),
    )
    output = tmp_path / "single-snapshot.json"
    result = cli_module.command_build_case(
        argparse.Namespace(
            manifest=str(CASE_BUILDER_PACK / "manifest.json"),
            output=str(output),
            run=True,
            validation_manifest=str(BUILDER_VALIDATION_MANIFEST),
        )
    )

    assert result == 0
    assert load_calls == 1
    assert len(evaluations) == 1
    assert evaluations[0].run.case_source_assurance_state == "BOUND_RAW_SOURCE_CASE"
    reopened = run_case(load_case(output))
    assert reopened.case_source_assurance_state == "UNBOUND_SERIALIZED_CASE"
    assert reopened.case_source_set_hash is None
    assert reopened.case_source_binding_hash is None
    assert reopened.case_source_lineage_hash is None


def test_cli_build_case_does_not_replace_output_when_gate_fails(tmp_path):
    pack = tmp_path / "case-builder-pack"
    import shutil

    shutil.copytree(CASE_BUILDER_PACK, pack)
    sop = pack / "sop.csv"
    sop.write_text(
        sop.read_text(encoding="utf-8").replace(",0,0,0,", ",0,0,1,"),
        encoding="utf-8",
    )
    output = tmp_path / "existing.json"
    sentinel = {"known_good": True}
    output.write_text(json.dumps(sentinel), encoding="utf-8")

    built = _run(
        "build-case",
        "--manifest",
        str(pack / "manifest.json"),
        "--output",
        str(output),
        "--run",
    )

    assert built.returncode == 1
    assert "output=NOT_WRITTEN" in built.stdout
    assert json.loads(output.read_text(encoding="utf-8")) == sentinel


def test_cli_run_returns_nonzero_for_non_pass_result():
    run = _run(
        "run",
        "--case", str(BASE / "baseline.json"),
        "--mutation", str(BASE / "mutations/M001_stale_sop_conflict.json"),
    )
    assert run.returncode == 1
    assert "overall=CONTRADICTED" in run.stdout


def test_cli_audit_does_not_create_or_accept_missing_database(tmp_path):
    missing = tmp_path / "does-not-exist.db"
    audit = _run("audit", "--db", str(missing))
    assert audit.returncode == 2
    assert '"chain_valid": false' in audit.stdout
    assert '"error": "database_not_found"' in audit.stdout
    assert not missing.exists()


def test_cli_audit_rejects_empty_database(tmp_path):
    empty = tmp_path / "empty.db"
    empty.touch()
    before = empty.stat()
    audit = _run("audit", "--db", str(empty))
    after = empty.stat()
    assert audit.returncode == 2
    assert '"chain_valid": false' in audit.stdout
    assert '"error": "required_audit_tables_missing"' in audit.stdout
    assert (after.st_size, after.st_mtime_ns) == (before.st_size, before.st_mtime_ns)


def test_cli_audit_opens_existing_database_read_only(tmp_path):
    database = tmp_path / "audit.db"
    assert _run(
        "run",
        "--case-source-manifest",
        str(CASE_BUILDER_PACK / "manifest.json"),
        "--validation-manifest",
        str(BUILDER_VALIDATION_MANIFEST),
        "--db",
        str(database),
    ).returncode == 0
    before = database.stat()
    audit = _run("audit", "--db", str(database))
    after = database.stat()
    assert audit.returncode == 0
    assert '"chain_valid": true' in audit.stdout
    assert (after.st_size, after.st_mtime_ns) == (before.st_size, before.st_mtime_ns)


def test_cli_malformed_json_is_concise_input_error(tmp_path):
    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"case_id":', encoding="utf-8")
    run = _run("run", "--case", str(malformed))
    assert run.returncode == 2
    assert "ERROR invalid input:" in run.stdout
    assert "Traceback" not in run.stdout
    assert "Traceback" not in run.stderr


def test_cli_oversized_json_is_concise_input_error(tmp_path):
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (MAX_JSON_FILE_BYTES + 1))

    run = _run("run", "--case", str(oversized))

    assert run.returncode == 2
    assert "ERROR invalid input:" in run.stdout
    assert "byte input limit" in run.stdout
    assert "Traceback" not in run.stdout + run.stderr


def test_cli_rejects_duplicate_json_keys_and_nan_without_traceback(tmp_path):
    for index, payload in enumerate(
        (
            '{"case_id":"one","case_id":"two"}',
            '{"case_id":"one","value":NaN}',
            '{"case_id":"one","value":1e999}',
        )
    ):
        source = tmp_path / f"ambiguous-{index}.json"
        source.write_text(payload, encoding="utf-8")
        run = _run("run", "--case", str(source))
        assert run.returncode == 2
        assert "ERROR invalid input:" in run.stdout
        assert "Traceback" not in run.stdout + run.stderr


def test_cli_rejects_excessively_nested_json_without_traceback(tmp_path):
    source = tmp_path / "too-deep.json"
    source.write_text("[" * 2000 + "0" + "]" * 2000, encoding="utf-8")
    run = _run("run", "--case", str(source))
    assert run.returncode == 2
    assert "ERROR invalid input:" in run.stdout
    assert "Traceback" not in run.stdout + run.stderr
