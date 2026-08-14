from __future__ import annotations

from dataclasses import replace
from enum import StrEnum
import hashlib
import json
from pathlib import Path

import pytest

import qualityci.case_builder as case_builder
import qualityci.case_source_assurance as source_assurance
from qualityci.case_builder import _build_case_and_reference_context_from_pack
from qualityci.case_source_assurance import (
    CASE_SOURCE_BOUND,
    CASE_SOURCE_DERIVED,
    CASE_SOURCE_UNBOUND,
    CASE_SOURCE_PACK_CONTRACT_VERSION,
    CASE_SOURCE_SET_CONTRACT_VERSION,
    RUN_IDENTITY_VERSION,
    RUN_RESULT_CONTRACT_VERSION,
    CaseSourceBundle,
    CaseSourceCapture,
    CaseSourceError,
    CaseSourceMember,
    CaseMutationBundle,
    CaseSourceSnapshot,
    _prepare_case_source_context,
    _derive_case_source_mutation,
    load_case_source_bundle,
    validate_case_source_assurance_payload,
)
from qualityci.engine import (
    legacy_run_result_projection,
    run_case,
    run_case_with_source_bundle,
    run_case_with_source_mutation_bundle,
)
from qualityci.loader import canonical_hash, load_case, prepare_case
from qualityci.validation_evidence import load_validation_evidence_bundle
from qualityci.validation_evidence import _prepare_validation_evidence_context
from qualityci.engine import _evaluate_source_rooted_case


ROOT = Path(__file__).parents[1]
MANIFEST = ROOT / "tests/fixtures/case_builder/manifest.json"
BENCH = ROOT / "datasets/qualityci-bench/tacoma_24v152"


def _bundle_with_manifest(bundle: CaseSourceBundle, raw: bytes) -> CaseSourceBundle:
    captures = tuple(
        replace(
            item,
            size_bytes=len(raw) if item.source_kind == "JSON" else item.size_bytes,
            filesystem_safe=False,
        )
        for item in bundle.snapshot.captures
    )
    return replace(
        bundle,
        manifest_bytes=raw,
        snapshot=CaseSourceSnapshot(
            source_kind="IN_MEMORY_BUNDLE",
            captures=captures,
        ),
    )


def test_source_bundle_captures_exact_manifest_plus_five_canonical_members() -> None:
    bundle = load_case_source_bundle(MANIFEST)

    assert bundle.contract_version == CASE_SOURCE_PACK_CONTRACT_VERSION
    assert type(bundle.manifest_bytes) is bytes
    assert tuple(member.document_type for member in bundle.members) == (
        "PROCESS_FLOW",
        "PFMEA",
        "CONTROL_PLAN",
        "SOP",
        "INSPECTION_RECORD",
    )
    assert len(bundle.members) == 5
    assert len(bundle.snapshot.captures) == 6
    assert bundle.snapshot.source_kind == "FILESYSTEM_SINGLE_SNAPSHOT"
    assert all(type(member) is CaseSourceMember for member in bundle.members)
    assert all(type(item) is CaseSourceCapture for item in bundle.snapshot.captures)
    assert all(item.filesystem_safe is True for item in bundle.snapshot.captures)


def test_source_context_rebuilds_the_existing_case_and_same_snapshot_a03() -> None:
    expected_case, expected_reference = _build_case_and_reference_context_from_pack(
        MANIFEST
    )
    context = _prepare_case_source_context(load_case_source_bundle(MANIFEST))

    assert context.case() == expected_case
    assert context.case() is not context.case()
    assert context.root_case_hash == canonical_hash(expected_case)
    assert context._reference_context.reference_set_hash == (
        expected_reference.reference_set_hash
    )
    assert context._reference_context.contract_version == (
        expected_reference.contract_version
    )
    assert context.case_source_set.source_set_contract_version == (
        CASE_SOURCE_SET_CONTRACT_VERSION
    )
    assert context.case_source_set.to_dict()["source_set_hash"] == (
        context.case_source_set.source_set_hash
    )


def test_source_set_and_binding_are_deterministic_and_raw_format_sensitive() -> None:
    bundle = load_case_source_bundle(MANIFEST)
    first = _prepare_case_source_context(bundle)
    second = _prepare_case_source_context(load_case_source_bundle(MANIFEST))
    reformatted = _prepare_case_source_context(
        _bundle_with_manifest(bundle, bundle.manifest_bytes + b" \n")
    )

    assert first.case_source_set.to_dict() == second.case_source_set.to_dict()
    assert first.case_source_binding_hash == second.case_source_binding_hash
    assert first.root_case_hash == second.root_case_hash
    assert reformatted.root_case_hash == first.root_case_hash
    assert reformatted.case() == first.case()
    assert reformatted.case_source_set.source_set_hash != (
        first.case_source_set.source_set_hash
    )
    assert reformatted.case_source_binding_hash != first.case_source_binding_hash


def test_preparation_consumes_owned_bytes_without_reopening_the_pack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = load_case_source_bundle(MANIFEST)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("source pack was reopened after capture")

    monkeypatch.setattr(source_assurance, "_capture_filesystem_bytes", forbidden)
    monkeypatch.setattr(case_builder, "read_source_bytes", forbidden)
    context = _prepare_case_source_context(bundle)

    assert context.case()["case_id"] == "QCI-BUILDER-SYN-001"
    assert context._reference_context.reference_set_hash


def test_exact_carriers_reject_mutable_wrong_and_colliding_material() -> None:
    bundle = load_case_source_bundle(MANIFEST)

    with pytest.raises(CaseSourceError, match="manifest_bytes"):
        CaseSourceBundle(  # type: ignore[arg-type]
            manifest_bytes=bytearray(bundle.manifest_bytes),
            members=bundle.members,
            snapshot=bundle.snapshot,
        )
    with pytest.raises(CaseSourceError, match="exactly five"):
        replace(bundle, members=bundle.members[:-1])
    with pytest.raises(CaseSourceError, match="exact member type"):
        replace(bundle, members=tuple({} for _index in range(5)))  # type: ignore[arg-type]
    with pytest.raises(CaseSourceError, match="raw member bytes collision"):
        replace(
            bundle,
            members=(
                bundle.members[0],
                replace(bundle.members[1], raw_bytes=bundle.members[0].raw_bytes),
                *bundle.members[2:],
            ),
        )


def test_member_manifest_identity_and_snapshot_shape_are_rechecked() -> None:
    bundle = load_case_source_bundle(MANIFEST)
    with pytest.raises(CaseSourceError, match="canonical role order"):
        replace(bundle, members=tuple(reversed(bundle.members)))
    attacked = replace(
        bundle,
        members=(
            replace(bundle.members[0], source_id="different-source"),
            *bundle.members[1:],
        ),
    )
    with pytest.raises(CaseSourceError, match="member differs from manifest"):
        _prepare_case_source_context(attacked)

    with pytest.raises(CaseSourceError, match="six captures"):
        CaseSourceSnapshot(
            source_kind="IN_MEMORY_BUNDLE",
            captures=bundle.snapshot.captures[:-1],
        )
    with pytest.raises(CaseSourceError, match="filesystem loader"):
        CaseSourceSnapshot(
            source_kind="FILESYSTEM_SINGLE_SNAPSHOT",
            captures=bundle.snapshot.captures,
        )
    with pytest.raises(CaseSourceError, match="filesystem loader"):
        replace(bundle.snapshot, captures=bundle.snapshot.captures)
    with pytest.raises(CaseSourceError, match="cannot assert filesystem safety"):
        CaseSourceSnapshot(
            source_kind="IN_MEMORY_BUNDLE",
            captures=bundle.snapshot.captures,
        )
    in_memory = CaseSourceSnapshot(
        source_kind="IN_MEMORY_BUNDLE",
        captures=tuple(
            replace(item, filesystem_safe=False)
            for item in bundle.snapshot.captures
        ),
    )
    assert all(item.filesystem_safe is False for item in in_memory.captures)


def test_assurance_output_validator_rejects_string_subclass_state() -> None:
    class LookalikeState(StrEnum):
        BOUND = CASE_SOURCE_BOUND

    context = _prepare_case_source_context(load_case_source_bundle(MANIFEST))
    payload = context.assurance().to_dict()
    payload["case_source_assurance_state"] = LookalikeState.BOUND

    with pytest.raises(CaseSourceError, match="state is unsupported"):
        validate_case_source_assurance_payload(payload)


@pytest.mark.parametrize(
    ("path", "value", "message"),
    (
        (("case", "title"), 7, "case.title must be a string"),
        (("case", "source_provenance"), {}, "list of objects"),
        (("event", "provenance"), [], "event.provenance must be an object"),
    ),
)
def test_builder_manifest_schema_expressible_optional_shapes_reject_in_runtime(
    path: tuple[str, str],
    value: object,
    message: str,
) -> None:
    bundle = load_case_source_bundle(MANIFEST)
    manifest = json.loads(bundle.manifest_bytes)
    manifest[path[0]][path[1]] = value
    attacked = _bundle_with_manifest(
        bundle,
        json.dumps(manifest, ensure_ascii=False).encode("utf-8"),
    )

    with pytest.raises(CaseSourceError, match=message):
        _prepare_case_source_context(attacked)


def test_current_run_identity_distinguishes_unbound_and_raw_bound_sources() -> None:
    direct = run_case(load_case(BENCH / "baseline_v04.json"))
    validation = load_validation_evidence_bundle(
        MANIFEST.parent / "validation_manifest.json"
    )
    bound = run_case_with_source_bundle(
        load_case_source_bundle(MANIFEST), validation
    )

    assert direct.run_result_contract_version == RUN_RESULT_CONTRACT_VERSION
    assert direct.run_identity_version == RUN_IDENTITY_VERSION
    assert direct.case_source_assurance_state == CASE_SOURCE_UNBOUND
    assert direct.case_source_set_hash is None
    assert len(direct.to_dict()) == 22
    assert bound.run_result_contract_version == RUN_RESULT_CONTRACT_VERSION
    assert bound.run_identity_version == RUN_IDENTITY_VERSION
    assert bound.case_source_assurance_state == CASE_SOURCE_BOUND
    assert bound.case_source_set_hash
    assert bound.case_source_binding_hash
    assert bound.case_source_lineage_hash is None
    assert bound.overall_status.value == "PASS"
    assert direct.run_id != legacy_run_result_projection(direct)["run_id"]
    assert len(legacy_run_result_projection(direct)) == 13
    with pytest.raises(ValueError, match="source-rooted"):
        legacy_run_result_projection(bound)

    identity = {
        key: bound.to_dict()[key]
        for key in (
            "run_result_contract_version",
            "run_identity_version",
            "case_hash",
            "ruleset_version",
            "case_source_assurance_state",
            "case_source_pack_contract_version",
            "case_source_set_contract_version",
            "case_source_set_hash",
            "case_source_binding_hash",
            "case_source_lineage_contract_version",
            "case_source_lineage_hash",
            "reference_assurance_state",
            "reference_set_hash",
            "reference_contract_version",
            "validation_assurance_state",
            "validation_evidence_set_hash",
            "validation_evidence_contract_version",
        )
    }
    canonical_identity = json.dumps(
        identity,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    assert bound.run_id == hashlib.sha256(
        b"QualityCI/run-identity/v4\0" + canonical_identity
    ).hexdigest()[:16]


@pytest.mark.parametrize(
    ("changes", "message"),
    (
        (
            {"run_result_contract_version": "qualityci-run-result-9.9"},
            "contract version",
        ),
        (
            {"run_identity_version": "qualityci-run-identity-v3"},
            "identity version",
        ),
        (
            {
                "case_source_assurance_state": CASE_SOURCE_BOUND,
                "case_source_pack_contract_version": None,
                "case_source_set_contract_version": None,
                "case_source_set_hash": None,
                "case_source_binding_hash": None,
            },
            "inconsistent versions",
        ),
        ({"run_id": "0" * 16}, "differs from its v4 identity"),
    ),
)
def test_run_result_value_rejects_mixed_or_unrecomputed_profiles(
    changes: dict[str, object],
    message: str,
) -> None:
    run = run_case(load_case(BENCH / "baseline_v04.json"))
    with pytest.raises(ValueError, match=message):
        replace(run, **changes)


def test_mutation_bytes_create_one_closed_source_rooted_lineage() -> None:
    bundle = load_case_source_bundle(MANIFEST)
    raw = json.dumps(
        {
            "mutation_id": "A08-TITLE-CHANGE",
            "operations": [
                {
                    "op": "set",
                    "target": "case",
                    "path": "title",
                    "value": "A08 derived synthetic title",
                }
            ],
        },
        ensure_ascii=False,
        indent=2,
    ).encode("utf-8")
    mutation = CaseMutationBundle(raw)
    root = _prepare_case_source_context(bundle)
    derived = _derive_case_source_mutation(root, mutation)
    run = run_case_with_source_mutation_bundle(bundle, mutation)

    assert len(derived.lineages) == 1
    lineage = derived.lineages[0]
    assert lineage.parent_lineage_hash is None
    assert lineage.root_binding_hash == root.case_source_binding_hash
    assert lineage.input_case_hash == root.root_case_hash
    assert lineage.output_case_hash == canonical_hash(derived.case())
    assert lineage.operation_kind == "MUTATION"
    assert lineage.operation_material()["mutation_id"] == "A08-TITLE-CHANGE"
    assert lineage.operation_material()["applied_operations"][0] == {
        "sequence": 0,
        "op": "set",
        "target": "case",
        "document_id": None,
        "path": "title",
        "value": {"present": True, "json": "A08 derived synthetic title"},
    }
    assert derived.assurance().case_source_assurance_state == CASE_SOURCE_DERIVED
    assert derived.assurance().case_source_lineage_hash == lineage.lineage_hash
    assert run.case_source_assurance_state == CASE_SOURCE_DERIVED
    assert run.case_source_lineage_hash == lineage.lineage_hash
    assert run.case_hash == lineage.output_case_hash


def test_source_evaluator_rejects_validation_context_for_pre_mutation_case() -> None:
    root = _prepare_case_source_context(load_case_source_bundle(MANIFEST))
    validation = load_validation_evidence_bundle(
        MANIFEST.parent / "validation_manifest.json"
    )
    stale = _prepare_validation_evidence_context(
        validation,
        root.case(),
        expected_phase="SOURCE",
    )
    derived = _derive_case_source_mutation(
        root,
        CaseMutationBundle(
            b'{"mutation_id":"A08-VALIDATION-STALE","operations":['
            b'{"op":"set","target":"case","path":"title",'
            b'"value":"changed validation subject"}]}'
        ),
    )

    with pytest.raises(TypeError, match="validation context differs"):
        _evaluate_source_rooted_case(
            derived.case(),
            derived._reference_context,
            stale,
            derived,
        )


def test_mutation_lineage_is_ordered_and_raw_format_sensitive() -> None:
    root = _prepare_case_source_context(load_case_source_bundle(MANIFEST))
    value = {
        "mutation_id": "A08-TITLE-CHANGE",
        "operations": [
            {"op": "set", "target": "case", "path": "title", "value": "same"}
        ],
    }
    compact = CaseMutationBundle(
        json.dumps(value, separators=(",", ":")).encode("utf-8")
    )
    pretty = CaseMutationBundle(json.dumps(value, indent=2).encode("utf-8"))
    first = _derive_case_source_mutation(root, compact)
    same_output = _derive_case_source_mutation(root, pretty)
    second = _derive_case_source_mutation(
        first,
        CaseMutationBundle(
            b'{"mutation_id":"A08-EVENT-CHANGE","operations":['
            b'{"op":"set","target":"event","path":"change_summary",'
            b'"value":"second"}]}'
        ),
    )

    assert first.case() == same_output.case()
    assert first.lineages[-1].operation_material_hash != (
        same_output.lineages[-1].operation_material_hash
    )
    assert first.lineages[-1].lineage_hash != same_output.lineages[-1].lineage_hash
    assert len(second.lineages) == 2
    assert second.lineages[-1].parent_lineage_hash == first.lineages[-1].lineage_hash
    assert second.lineages[-1].input_case_hash == first.lineages[-1].output_case_hash

    attacked = CaseMutationBundle(
        b'{"mutation_id":"A08-BAD","operations":['
        b'{"op":"set","target":"case","path":"title","value":"x",'
        b'"caller_trusted":true}]}'
    )
    with pytest.raises(CaseSourceError, match="unknown or inconsistent fields"):
        _derive_case_source_mutation(root, attacked)


def test_native_replay_material_is_rebuilt_from_raw_resolution() -> None:
    root = _prepare_case_source_context(load_case_source_bundle(MANIFEST))
    resolution = {
        "resolution_id": "A08-NATIVE-TITLE",
        "description": "exact source-rooted native operation",
        "replacement_set_id": "A08-REPLACEMENT-SET",
        "operations": [
            {
                "op": "set",
                "document_id": root.case()["documents"][0]["document_id"],
                "path": "revision",
                "value": "B2",
            }
        ],
    }
    raw = json.dumps(resolution, ensure_ascii=False, indent=2).encode("utf-8")
    material = {
        **source_assurance._NATIVE_REPLAY_CONSTANT_FIELDS,
        "native_resolution_blob": {
            "source_hash": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
        },
        "resolution_id": resolution["resolution_id"],
        "applied_operations": [
            {
                "sequence": 0,
                "op": "set",
                "target": "document",
                "document_id": resolution["operations"][0]["document_id"],
                "path": "revision",
                "value": {"present": True, "json": "B2"},
            }
        ],
        **{
            key: character * 64
            for key, character in zip(
                sorted(source_assurance._NATIVE_REPLAY_HASH_FIELDS),
                "123456789ab",
                strict=True,
            )
        },
    }
    material["controlled_reference_set_hash"] = (
        root._reference_context.reference_set_hash
    )
    assert source_assurance._validate_native_replay_material(material, raw) == material

    attacked = json.loads(json.dumps(material))
    attacked["applied_operations"][0]["sequence"] = 1
    with pytest.raises(CaseSourceError, match="operations differ from raw bytes"):
        source_assurance._validate_native_replay_material(attacked, raw)
