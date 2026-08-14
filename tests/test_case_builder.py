from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from qualityci import case_builder as case_builder_module
from qualityci.case_builder import (
    AmbiguousMappingError,
    CaseBuilderError,
    DuplicateIdentifierError,
    ManifestError,
    MissingColumnError,
    build_case_from_csv_pack,
    _build_case_and_reference_context_from_pack,
)
from qualityci.engine import run_case, run_case_from_pack, _run_case_with_reference_context
from qualityci.loader import validate_case
from qualityci.models import CheckStatus
from qualityci.validation_evidence import _prepare_validation_evidence_context

from validation_support import validation_bundle


PACK = Path(__file__).parent / "fixtures" / "case_builder"


def _copy_pack(tmp_path: Path) -> Path:
    target = tmp_path / "case-builder-pack"
    shutil.copytree(PACK, target)
    return target


def test_complete_five_file_pack_builds_valid_passing_case() -> None:
    case = build_case_from_csv_pack(PACK / "manifest.json")

    validate_case(case)
    assert run_case(case).overall_status == CheckStatus.UNVERIFIABLE
    result = run_case_from_pack(
        PACK / "manifest.json",
        validation_manifest_path=PACK / "validation_manifest.json",
    )
    assert result.overall_status == CheckStatus.PASS
    assert all(finding.status == CheckStatus.PASS for finding in result.findings)
    assert {document["document_type"] for document in case["documents"]} == {
        "PROCESS_FLOW",
        "PFMEA",
        "CONTROL_PLAN",
        "SOP",
        "INSPECTION_RECORD",
    }

    process_flow = next(
        document
        for document in case["documents"]
        if document["document_type"] == "PROCESS_FLOW"
    )
    first_mapping = process_flow["mapping_provenance"][0]
    assert first_mapping == {
        "mapping_kind": "DIRECT_CELL_VALUE",
        "conversion_contract": "qualityci-mapping-value-conversion-0.1",
        "target": "fields.process_steps[0]",
        "value": "WELD-10",
        "source": {
            "source_id": "process-flow-table",
            "document_id": "PF-BUILDER-SYN",
            "source_hash": process_flow["source_hash"],
            "locator": "CSV#row-2.cell-A",
            "kind": "CELL",
            "coordinates": {"row": 2, "column": 1},
            "column": "process_step_id",
            "raw_value": "WELD-10",
        },
    }
    for document in case["documents"]:
        assert document["mapping_provenance"]
        assert all(
            mapping["source"]["locator"]
            and mapping["source"]["source_hash"] == document["source_hash"]
            for mapping in document["mapping_provenance"]
            if mapping["mapping_kind"] in {"DIRECT_CELL_VALUE", "DERIVED_LOCATOR"}
        )
    builder_sources = case["builder_provenance"]["sources"]
    fingerprints = {
        source["logical_table_fingerprint"] for source in builder_sources
    }
    assert len(fingerprints) == 5
    assert all(
        fingerprint.startswith("sha256:") and len(fingerprint) == 71
        for fingerprint in fingerprints
    )
    assert {source["canonical_table_selector"]["format"] for source in builder_sources} == {
        "CSV"
    }


def test_all_builder_mapping_values_are_exact_immutable_json_scalars() -> None:
    case = build_case_from_csv_pack(PACK / "manifest.json")

    values = [
        mapping["value"]
        for document in case["documents"]
        for mapping in document["mapping_provenance"]
    ]
    assert values
    assert all(type(value) in {str, int, float, bool} for value in values)
    assert {type(value) for value in values} >= {str, int, bool}

    with pytest.raises(CaseBuilderError, match="immutable JSON scalars"):
        case_builder_module._immutable_mapping_value({"mutable": True})
    for nonfinite in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(CaseBuilderError, match="finite JSON scalars"):
            case_builder_module._mapping_value_key(nonfinite)

    key = case_builder_module._mapping_value_key
    assert key(True) != key(1)
    assert key(1) != key(1.0)
    assert key(-0.0) != key(0.0)
    assert key("\u00e9") != key("e\u0301")


def test_missing_manifest_column_fails_closed(tmp_path: Path) -> None:
    pack = _copy_pack(tmp_path)
    sop = pack / "sop.csv"
    sop.write_text(
        sop.read_text(encoding="utf-8").replace(",unit\n", ",units\n"),
        encoding="utf-8",
    )

    with pytest.raises(MissingColumnError, match="missing manifest column 'unit'"):
        build_case_from_csv_pack(pack / "manifest.json")


def test_duplicate_entity_identifier_fails_closed(tmp_path: Path) -> None:
    pack = _copy_pack(tmp_path)
    pfmea = pack / "pfmea.csv"
    pfmea.write_text(
        pfmea.read_text(encoding="utf-8").replace(
            "FM-MISSED-SPATTER", "FM-SPATTER-SEAT"
        ),
        encoding="utf-8",
    )

    with pytest.raises(DuplicateIdentifierError, match="duplicate failure_mode_id"):
        build_case_from_csv_pack(pack / "manifest.json")


def test_normalized_duplicate_headers_fail_as_ambiguous(tmp_path: Path) -> None:
    pack = _copy_pack(tmp_path)
    (pack / "process_flow.csv").write_text(
        "process_step_id,PROCESS_STEP_ID\n"
        "WELD-10,WELD-ALT\n"
        "INSPECT-40,INSPECT-ALT\n",
        encoding="utf-8",
    )

    with pytest.raises(AmbiguousMappingError, match="normalized duplicate headers"):
        build_case_from_csv_pack(pack / "manifest.json")


def test_same_source_path_cannot_impersonate_multiple_documents(tmp_path: Path) -> None:
    pack = _copy_pack(tmp_path)
    manifest_path = pack / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["documents"][1]["source_path"] = manifest["documents"][0]["source_path"]
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")

    with pytest.raises(DuplicateIdentifierError, match="source_path"):
        build_case_from_csv_pack(manifest_path)


def test_csv_rejects_even_empty_table_selector(tmp_path: Path) -> None:
    pack = _copy_pack(tmp_path)
    manifest_path = pack / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["documents"][0]["table_selector"] = {}
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")

    with pytest.raises(ManifestError, match="CSV sources do not accept table_selector"):
        build_case_from_csv_pack(manifest_path)


@pytest.mark.parametrize(
    ("source_format", "evidence", "explicit_selector"),
    [
        (
            "XLSX",
            [
                {
                    "kind": "CELL",
                    "coordinates": {"sheet": "Data", "row": 1, "column": 1},
                    "text": "header",
                }
            ],
            {"sheet": "Data"},
        ),
        (
            "DOCX",
            [
                {
                    "kind": "TABLE_CELL",
                    "coordinates": {"table": 1, "row": 1, "column": 1},
                    "text": "header",
                }
            ],
            {"table": 1},
        ),
    ],
)
def test_canonical_selector_uses_resolved_table_identity(
    source_format: str,
    evidence: list[dict[str, object]],
    explicit_selector: dict[str, object],
) -> None:
    implicit = case_builder_module._select_table_cells(
        source_format, evidence, None, "source", 1
    )
    explicit = case_builder_module._select_table_cells(
        source_format, evidence, explicit_selector, "source", 1
    )

    assert implicit.canonical_selector == explicit.canonical_selector


def test_same_logical_csv_table_with_different_serialization_is_rejected(
    tmp_path: Path,
) -> None:
    pack = _copy_pack(tmp_path)
    universal_table = (
        "process_step_id,control_id,characteristic_id,target,minimum,maximum,unit,"
        "control_method,frequency,reaction_plan\n"
        "WELD-10,CTRL-SPATTER-SEAT,CTQ-NUT-SEAT-SPATTER,0,0,0,visible_particle,"
        "100% visual inspection,every part,stop and isolate"
    )
    (pack / "control_plan.csv").write_text(universal_table, encoding="utf-8")
    (pack / "sop.csv").write_bytes(
        b"\xef\xbb\xbf\r\n"
        + universal_table.replace("\n", "\r\n").encode("utf-8")
    )
    manifest_path = pack / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["documents"][3]["header_row"] = 2
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")

    with pytest.raises(AmbiguousMappingError, match="normalized table content"):
        build_case_from_csv_pack(manifest_path)


def test_formula_like_source_cell_is_never_mapped_as_fact(tmp_path: Path) -> None:
    pack = _copy_pack(tmp_path)
    control_plan = pack / "control_plan.csv"
    control_plan.write_text(
        control_plan.read_text(encoding="utf-8").replace(",0,0,0,", ",=0,0,0,"),
        encoding="utf-8",
    )

    with pytest.raises(CaseBuilderError, match="formula cache values are not evidence"):
        build_case_from_csv_pack(pack / "manifest.json")


def test_xlsx_formula_cache_remains_rejected() -> None:
    source_hash = "a" * 64
    cells = (
        {
            "kind": "CELL",
            "coordinates": {"sheet": "Data", "row": 1, "column": 1},
            "locator": "'Data'!A1",
            "text": "process_step_id",
            "source_hash": source_hash,
        },
        {
            "kind": "CELL",
            "coordinates": {"sheet": "Data", "row": 2, "column": 1},
            "locator": "'Data'!A2",
            "text": "110",
            "source_hash": source_hash,
            "formula": "A3*2",
            "value_is_cached": True,
        },
    )
    selected = case_builder_module._SelectedTable(
        cells=cells,
        canonical_selector=("XLSX", "Data"),
        logical_fingerprint="unused",
    )
    spec = {
        "source_id": "source",
        "header_row": 1,
        "columns": {"process_step_id": "process_step_id"},
    }
    source = {
        "source_hash": source_hash,
        "fields": {"structure": {"format": "XLSX"}},
    }

    with pytest.raises(CaseBuilderError, match="formula cache values are not evidence"):
        case_builder_module._map_table(spec, source, selected)


def test_finite_negative_csv_numbers_are_not_misclassified_as_formulas(
    tmp_path: Path,
) -> None:
    pack = _copy_pack(tmp_path)
    for filename in ("control_plan.csv", "sop.csv", "inspection_record.csv"):
        path = pack / filename
        path.write_text(
            path.read_text(encoding="utf-8").replace(",0,0,0,", ",-1,-2,0,"),
            encoding="utf-8",
        )

    case = build_case_from_csv_pack(pack / "manifest.json")

    native_case, reference_context = _build_case_and_reference_context_from_pack(
        pack / "manifest.json"
    )
    validation_context = _prepare_validation_evidence_context(
        validation_bundle(native_case, "SOURCE"),
        native_case,
        expected_phase="SOURCE",
    )
    assert (
        _run_case_with_reference_context(
            native_case, reference_context, validation_context
        ).overall_status
        == CheckStatus.PASS
    )
    control_plan = next(
        document
        for document in case["documents"]
        if document["document_type"] == "CONTROL_PLAN"
    )
    specification = control_plan["fields"]["characteristics"][0]["specification"]
    assert specification == {
        "target": -1,
        "minimum": -2,
        "maximum": 0,
        "unit": "visible_particle",
    }
