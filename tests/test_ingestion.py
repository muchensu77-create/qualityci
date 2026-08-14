from __future__ import annotations

import math
import os
import subprocess
import zipfile
from pathlib import Path

import pytest
import qualityci.ingestion as ingestion

from qualityci.ingestion import (
    ArchiveSafetyError,
    IngestionError,
    IngestionLimits,
    LimitExceededError,
    ScannedPdfError,
    UnsafePathError,
    UnsupportedFormatError,
    ingest_document,
)


ROOT = Path(__file__).parent
FIXTURES = ROOT / "fixtures"


def _ingest(path: Path, **kwargs):
    return ingest_document(
        path,
        document_id="DOC-001",
        document_type="CONTROL_PLAN",
        revision="B",
        owner="QUALITY_ENGINEERING",
        root_dir=path.parent,
        **kwargs,
    )


def _write_zip(path: Path, members: dict[str, str | bytes], *, compression=zipfile.ZIP_DEFLATED):
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        for name, content in members.items():
            archive.writestr(name, content)


def _create_windows_junction(junction: Path, target: Path) -> None:
    created = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(target)],
        check=False,
        capture_output=True,
        text=True,
    )
    if created.returncode != 0:
        detail = (created.stderr or created.stdout).strip()
        pytest.skip(f"junction creation unavailable: {detail}")


def _xlsx_members(*, formula: str = "A2*2") -> dict[str, str]:
    return {
        "[Content_Types].xml": """<?xml version="1.0"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
 <Override PartName="/xl/workbook.xml"
  ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
</Types>""",
        "xl/workbook.xml": """<?xml version="1.0"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
 xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
 <sheets><sheet name="Risk Log" sheetId="1" r:id="rId1"/></sheets>
</workbook>""",
        "xl/_rels/workbook.xml.rels": """<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
 <Relationship Id="rId1"
  Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"
  Target="worksheets/sheet1.xml"/>
</Relationships>""",
        "xl/sharedStrings.xml": """<?xml version="1.0"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
 <si><t>characteristic_id</t></si><si><t>CTQ-TORQUE</t></si>
</sst>""",
        "xl/worksheets/sheet1.xml": f"""<?xml version="1.0"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
 <sheetData>
  <row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="inlineStr"><is><t>target</t></is></c></row>
  <row r="2"><c r="A2" t="s"><v>1</v></c><c r="B2"><v>55</v></c>
   <c r="C2"><f>{formula}</f><v>110</v></c></row>
 </sheetData>
</worksheet>""",
    }


def _docx_members(document_xml: str | None = None) -> dict[str, str]:
    return {
        "[Content_Types].xml": """<?xml version="1.0"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
 <Override PartName="/word/document.xml"
  ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>""",
        "word/document.xml": document_xml
        or """<?xml version="1.0"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
 <w:body>
  <w:p><w:r><w:t>Revision B approved</w:t></w:r></w:p>
  <w:tbl>
   <w:tr><w:tc><w:p><w:r><w:t>Characteristic</w:t></w:r></w:p></w:tc>
    <w:tc><w:p><w:r><w:t>CTQ-TORQUE</w:t></w:r></w:p></w:tc></w:tr>
   <w:tr><w:tc><w:p><w:r><w:t>Target</w:t></w:r></w:p></w:tc>
    <w:tc><w:p><w:r><w:t>55 N·m</w:t></w:r></w:p></w:tc></w:tr>
  </w:tbl>
 </w:body>
</w:document>""",
    }


def _minimal_pdf(extra: bytes = b"") -> bytes:
    return b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n" + extra + b"\n%%EOF\n"


def test_csv_produces_document_revision_and_cell_anchors():
    result = ingest_document(
        FIXTURES / "sample.csv",
        document_id="CP-001",
        document_type="CONTROL_PLAN",
        revision="B",
        root_dir=FIXTURES,
    )

    assert result["document_id"] == "CP-001"
    assert result["revision"] == "B"
    assert len(result["source_hash"]) == 64
    assert result["source"]["relative_path"] == "sample.csv"
    assert result["source"]["content_executed"] is False
    evidence = result["fields"]["evidence"]
    assert evidence[0]["locator"] == "CSV#row-1.cell-A"
    assert evidence[4]["locator"] == "CSV#row-2.cell-B"
    assert evidence[4]["text"] == "55 N·m"
    assert all(item["source_hash"] == result["source_hash"] for item in evidence)


def test_path_must_stay_inside_allowed_root(tmp_path: Path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside.csv"
    outside.write_text("a,b\n1,2\n", encoding="utf-8")

    with pytest.raises(UnsafePathError, match="escapes"):
        ingest_document(
            outside,
            document_id="DOC",
            document_type="CONTROL_PLAN",
            root_dir=allowed,
        )


def test_parent_traversal_is_rejected_even_when_it_normalizes_inside_root(
    tmp_path: Path,
):
    allowed = tmp_path / "allowed"
    nested = allowed / "nested"
    nested.mkdir(parents=True)
    source = allowed / "source.csv"
    source.write_text("a,b\n1,2\n", encoding="utf-8")

    with pytest.raises(UnsafePathError, match="traversal"):
        ingest_document(
            nested / ".." / "source.csv",
            document_id="DOC",
            document_type="CONTROL_PLAN",
            root_dir=allowed,
        )


def test_symlink_source_is_rejected(tmp_path: Path):
    target = tmp_path / "target.csv"
    target.write_text("a\n1\n", encoding="utf-8")
    link = tmp_path / "link.csv"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks are not available on this filesystem")

    with pytest.raises(UnsafePathError, match="symlink"):
        _ingest(link)


def test_symlink_directory_component_is_rejected(tmp_path: Path):
    real_directory = tmp_path / "real"
    real_directory.mkdir()
    source = real_directory / "source.csv"
    source.write_text("a\n1\n", encoding="utf-8")
    linked_directory = tmp_path / "linked"
    try:
        linked_directory.symlink_to(real_directory, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are not available on this filesystem")

    with pytest.raises(UnsafePathError, match="safely|reparse"):
        ingest_document(
            linked_directory / "source.csv",
            document_id="DOC",
            document_type="CONTROL_PLAN",
            root_dir=tmp_path,
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows junction behavior")
def test_windows_junction_directory_component_is_rejected(tmp_path: Path):
    real_directory = tmp_path / "real-junction-target"
    real_directory.mkdir()
    (real_directory / "source.csv").write_text("a\n1\n", encoding="utf-8")
    junction = tmp_path / "junction"
    _create_windows_junction(junction, real_directory)

    try:
        with pytest.raises(UnsafePathError, match="reparse"):
            ingest_document(
                junction / "source.csv",
                document_id="DOC",
                document_type="CONTROL_PLAN",
                root_dir=tmp_path,
            )
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows junction behavior")
def test_windows_junction_swap_after_resolution_is_rejected(tmp_path: Path):
    allowed = tmp_path / "allowed"
    component = allowed / "component"
    component.mkdir(parents=True)
    source = component / "source.csv"
    source.write_text("trusted\n1\n", encoding="utf-8")
    location = ingestion._resolve_source(source, allowed)

    displaced = allowed / "component-before-swap"
    component.rename(displaced)
    attacker = allowed / "attacker"
    attacker.mkdir()
    (attacker / "source.csv").write_text("attacker\n1\n", encoding="utf-8")
    _create_windows_junction(component, attacker)

    try:
        with pytest.raises(UnsafePathError, match="reparse"):
            ingestion._read_source(location, ingestion.DEFAULT_LIMITS)
    finally:
        component.rmdir()
        displaced.rename(component)


@pytest.mark.skipif(os.name != "nt", reason="Windows native file identity")
def test_windows_root_replacement_is_rejected_by_file_id(tmp_path: Path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    source = allowed / "source.csv"
    source.write_text("trusted\n1\n", encoding="utf-8")
    location = ingestion._resolve_source(source, allowed)

    original_root = tmp_path / "allowed-before-swap"
    allowed.rename(original_root)
    allowed.mkdir()
    replacement_source = allowed / "source.csv"
    replacement_source.write_text("replacement\n1\n", encoding="utf-8")

    try:
        with pytest.raises(UnsafePathError, match="root_dir changed"):
            ingestion._read_source(location, ingestion.DEFAULT_LIMITS)
    finally:
        replacement_source.unlink()
        allowed.rmdir()
        original_root.rename(allowed)


@pytest.mark.skipif(os.name != "nt", reason="Windows binary descriptor mode")
def test_windows_rootless_open_uses_binary_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "source.csv"
    source.write_bytes(b"a,b\r\n1,2\r\n")
    observed_flags: list[int] = []
    native_open = ingestion.os.open

    def tracked_open(path, flags, *args, **kwargs):
        observed_flags.append(flags)
        return native_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(ingestion.os, "open", tracked_open)
    result = ingest_document(
        source,
        document_id="DOC",
        document_type="CONTROL_PLAN",
        root_dir=None,
    )

    assert result["source"]["size_bytes"] == len(source.read_bytes())
    assert observed_flags
    assert observed_flags[0] & os.O_BINARY


def test_file_size_limit_is_enforced_before_parsing(tmp_path: Path):
    path = tmp_path / "large.csv"
    path.write_text("header\n" + "x" * 100, encoding="utf-8")
    limits = IngestionLimits(max_file_bytes=16)

    with pytest.raises(LimitExceededError, match="source file"):
        _ingest(path, limits=limits)


def test_extension_and_content_mismatch_is_rejected(tmp_path: Path):
    path = tmp_path / "fake.xlsx"
    path.write_text("not a zip", encoding="utf-8")

    with pytest.raises(UnsupportedFormatError, match="ZIP/OOXML"):
        _ingest(path)


def test_csv_formula_like_text_is_flagged_but_never_executed(tmp_path: Path):
    path = tmp_path / "formula.csv"
    path.write_text("value\n=2+2\n", encoding="utf-8")

    result = _ingest(path)
    formula_cell = result["fields"]["evidence"][1]
    assert formula_cell["text"] == "=2+2"
    assert formula_cell["potential_spreadsheet_formula"] is True
    assert formula_cell["formula_executed"] is False


def test_xlsx_preserves_sheet_cell_value_and_unexecuted_formula(tmp_path: Path):
    path = tmp_path / "quality.xlsx"
    _write_zip(path, _xlsx_members())

    result = _ingest(path)
    by_locator = {item["locator"]: item for item in result["fields"]["evidence"]}
    assert by_locator["'Risk Log'!A2"]["text"] == "CTQ-TORQUE"
    assert by_locator["'Risk Log'!B2"]["value"] == 55
    assert by_locator["'Risk Log'!C2"]["formula"] == "A2*2"
    assert by_locator["'Risk Log'!C2"]["formula_executed"] is False
    assert by_locator["'Risk Log'!C2"]["value_is_cached"] is True
    assert result["fields"]["structure"]["sheets"][0]["cell_count"] == 5


def test_ooxml_macro_or_embedded_object_is_rejected(tmp_path: Path):
    path = tmp_path / "macro.xlsx"
    members = _xlsx_members()
    members["xl/vbaProject.bin"] = b"untrusted macro"
    _write_zip(path, members)

    with pytest.raises(ArchiveSafetyError, match="macro"):
        _ingest(path)


def test_ooxml_archive_path_traversal_is_rejected(tmp_path: Path):
    path = tmp_path / "traversal.docx"
    members = _docx_members()
    members["../outside.xml"] = "payload"
    _write_zip(path, members)

    with pytest.raises(ArchiveSafetyError, match="path traversal"):
        _ingest(path)


def test_ooxml_normalizable_parent_segment_is_still_rejected(tmp_path: Path):
    path = tmp_path / "traversal.docx"
    members = _docx_members()
    members["word/../disguised.xml"] = "payload"
    _write_zip(path, members)

    with pytest.raises(ArchiveSafetyError, match="path traversal"):
        _ingest(path)


def test_ooxml_zip_bomb_ratio_is_rejected(tmp_path: Path):
    path = tmp_path / "bomb.docx"
    members = _docx_members()
    members["word/huge.xml"] = "A" * 100_000
    _write_zip(path, members)
    limits = IngestionLimits(max_compression_ratio=5.0)

    with pytest.raises(ArchiveSafetyError, match="compression ratio"):
        _ingest(path, limits=limits)


def test_ooxml_member_count_is_bounded_before_parsing(tmp_path: Path):
    path = tmp_path / "many-members.xlsx"
    _write_zip(path, _xlsx_members())
    limits = IngestionLimits(max_archive_members=4)

    with pytest.raises(ArchiveSafetyError, match="member count"):
        _ingest(path, limits=limits)


def test_macro_enabled_content_type_is_rejected_even_without_obvious_filename(tmp_path: Path):
    path = tmp_path / "disguised.xlsx"
    members = _xlsx_members()
    members["[Content_Types].xml"] = """<?xml version="1.0"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
 <Override PartName="/xl/workbook.xml"
  ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/>
</Types>"""
    _write_zip(path, members)

    with pytest.raises(ArchiveSafetyError, match="content types"):
        _ingest(path)


def test_docx_preserves_paragraph_and_table_cell_anchors(tmp_path: Path):
    path = tmp_path / "sop.docx"
    _write_zip(path, _docx_members())

    result = _ingest(path)
    by_locator = {item["locator"]: item for item in result["fields"]["evidence"]}
    assert by_locator["DOCX#paragraph-1"]["text"] == "Revision B approved"
    assert by_locator["DOCX#table-1.row-1.cell-B"]["text"] == "CTQ-TORQUE"
    assert by_locator["DOCX#table-1.row-2.cell-B"]["text"] == "55 N·m"
    assert result["fields"]["structure"]["page_coordinates_available"] is False


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig"])
def test_ooxml_dtd_or_entity_declarations_are_rejected(
    tmp_path: Path, encoding: str
):
    path = tmp_path / "entity.docx"
    dangerous_xml = """<?xml version="1.0"?>
<!DOCTYPE x [<!ENTITY boom "expanded">]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
 <w:body><w:p><w:r><w:t>&boom;</w:t></w:r></w:p></w:body>
</w:document>"""
    members = _docx_members()
    members["word/document.xml"] = dangerous_xml.encode(encoding)
    _write_zip(path, members)

    with pytest.raises(ArchiveSafetyError, match="DTD/entity"):
        _ingest(path)


@pytest.mark.parametrize("encoding", ["utf-16", "utf-32"])
@pytest.mark.parametrize(
    ("suffix", "member_name", "dangerous_xml"),
    [
        (
            "docx",
            "word/document.xml",
            """<?xml version="1.0"?>
<!DOCTYPE x [<!ENTITY boom "expanded">]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
 <w:body><w:p><w:r><w:t>&boom;</w:t></w:r></w:p></w:body>
</w:document>""",
        ),
        (
            "xlsx",
            "xl/workbook.xml",
            """<?xml version="1.0"?>
<!DOCTYPE x [<!ENTITY boom "expanded">]>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
 xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
 <sheets><sheet name="&boom;" sheetId="1" r:id="rId1"/></sheets>
</workbook>""",
        ),
    ],
)
def test_utf16_and_utf32_ooxml_dtd_bypass_is_rejected_before_parser(
    tmp_path: Path, encoding: str, suffix: str, member_name: str, dangerous_xml: str
):
    path = tmp_path / f"entity.{suffix}"
    members = _docx_members() if suffix == "docx" else _xlsx_members()
    members[member_name] = dangerous_xml.encode(encoding)
    _write_zip(path, members)

    with pytest.raises(ArchiveSafetyError, match="UTF-8"):
        _ingest(path)


def test_pdf_without_explicit_adapter_is_rejected(tmp_path: Path):
    path = tmp_path / "report.pdf"
    path.write_bytes(_minimal_pdf())

    with pytest.raises(UnsupportedFormatError, match="explicit pdf_page_extractor"):
        _ingest(path)


def test_pdf_adapter_preserves_physical_page_anchors(tmp_path: Path):
    path = tmp_path / "report.pdf"
    path.write_bytes(_minimal_pdf())

    result = _ingest(
        path,
        pdf_page_extractor=lambda _: ["Page one", "", "Page three"],
        trusted_pdf_adapter=True,
    )
    evidence = result["fields"]["evidence"]
    assert [item["locator"] for item in evidence] == [
        "PDF#page-1",
        "PDF#page-2",
        "PDF#page-3",
    ]
    assert evidence[1]["extractable_text"] is False
    assert result["fields"]["structure"]["extractable_page_count"] == 2


def test_image_only_pdf_is_not_reported_as_success(tmp_path: Path):
    path = tmp_path / "scan.pdf"
    path.write_bytes(_minimal_pdf())

    with pytest.raises(ScannedPdfError, match="no extractable text"):
        _ingest(
            path,
            pdf_page_extractor=lambda _: ["", "  "],
            trusted_pdf_adapter=True,
        )


def test_pdf_active_content_is_rejected_before_adapter(tmp_path: Path):
    path = tmp_path / "active.pdf"
    path.write_bytes(_minimal_pdf(b"2 0 obj<</JavaScript 3 0 R>>endobj"))
    called = False

    def extractor(_):
        nonlocal called
        called = True
        return ["should not run"]

    with pytest.raises(UnsupportedFormatError, match="active"):
        _ingest(path, pdf_page_extractor=extractor, trusted_pdf_adapter=True)
    assert called is False


def test_metadata_control_characters_are_rejected_before_file_read():
    with pytest.raises(IngestionError, match="control characters"):
        ingest_document(
            FIXTURES / "sample.csv",
            document_id="DOC\x00BAD",
            document_type="CONTROL_PLAN",
            root_dir=FIXTURES,
        )


def test_pdf_adapter_requires_explicit_trust_decision(tmp_path: Path):
    path = tmp_path / "report.pdf"
    path.write_bytes(_minimal_pdf())
    called = False

    def extractor(_):
        nonlocal called
        called = True
        return ["text"]

    with pytest.raises(UnsupportedFormatError, match="disabled by default"):
        _ingest(path, pdf_page_extractor=extractor)
    assert called is False


def test_pdf_trust_decision_requires_literal_true(tmp_path: Path):
    path = tmp_path / "report.pdf"
    path.write_bytes(_minimal_pdf())

    with pytest.raises(UnsupportedFormatError, match="disabled by default"):
        _ingest(
            path,
            pdf_page_extractor=lambda _: ["text"],
            trusted_pdf_adapter="yes",
        )


def test_pdf_name_escape_cannot_hide_active_content(tmp_path: Path):
    path = tmp_path / "active.pdf"
    path.write_bytes(_minimal_pdf(b"2 0 obj<</Java#53cript 3 0 R>>endobj"))
    called = False

    def extractor(_):
        nonlocal called
        called = True
        return ["text"]

    with pytest.raises(UnsupportedFormatError, match="javascript"):
        _ingest(path, pdf_page_extractor=extractor, trusted_pdf_adapter=True)
    assert called is False


def test_pdf_opaque_object_stream_is_conservatively_rejected(tmp_path: Path):
    path = tmp_path / "opaque.pdf"
    path.write_bytes(_minimal_pdf(b"2 0 obj<</Type/ObjStm>>stream\nopaque\nendstream"))

    with pytest.raises(UnsupportedFormatError, match="objstm"):
        _ingest(
            path,
            pdf_page_extractor=lambda _: ["text"],
            trusted_pdf_adapter=True,
        )


def test_encoded_macro_content_type_is_rejected_after_xml_decoding(tmp_path: Path):
    path = tmp_path / "encoded-macro.xlsx"
    members = _xlsx_members()
    members["[Content_Types].xml"] = """<?xml version="1.0"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
 <Override PartName="/xl/workbook.xml"
  ContentType="application/vnd.ms-excel.sheet.macro&#69;nabled.main+xml"/>
</Types>"""
    _write_zip(path, members)

    with pytest.raises(ArchiveSafetyError, match="macro"):
        _ingest(path)


def test_unknown_binary_ooxml_part_is_conservatively_rejected(tmp_path: Path):
    path = tmp_path / "unknown-binary.xlsx"
    members = _xlsx_members()
    members["xl/opaque.bin"] = b"untrusted binary"
    _write_zip(path, members)

    with pytest.raises(ArchiveSafetyError, match="embedded-object"):
        _ingest(path)


def test_docx_top_level_content_control_is_extracted(tmp_path: Path):
    path = tmp_path / "content-control.docx"
    document_xml = """<?xml version="1.0"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
 <w:body><w:sdt><w:sdtContent>
  <w:p><w:r><w:t>VISIBLE CONTROLLED TEXT</w:t></w:r></w:p>
 </w:sdtContent></w:sdt></w:body>
</w:document>"""
    _write_zip(path, _docx_members(document_xml))

    result = _ingest(path)
    evidence = result["fields"]["evidence"]
    assert [(item["locator"], item["text"]) for item in evidence] == [
        ("DOCX#paragraph-1", "VISIBLE CONTROLLED TEXT")
    ]


def test_docx_nested_table_is_rejected_instead_of_mislocated(tmp_path: Path):
    path = tmp_path / "nested-table.docx"
    document_xml = """<?xml version="1.0"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
 <w:body><w:tbl><w:tr><w:tc><w:p><w:r><w:t>outer</w:t></w:r></w:p>
  <w:tbl><w:tr><w:tc><w:p><w:r><w:t>inner</w:t></w:r></w:p></w:tc></w:tr></w:tbl>
 </w:tc></w:tr></w:tbl></w:body>
</w:document>"""
    _write_zip(path, _docx_members(document_xml))

    with pytest.raises(UnsupportedFormatError, match="nested tables"):
        _ingest(path)


def test_docx_table_content_control_is_rejected_instead_of_silently_skipped(
    tmp_path: Path,
):
    path = tmp_path / "table-content-control.docx"
    document_xml = """<?xml version="1.0"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
 <w:body><w:tbl><w:sdt><w:sdtContent><w:tr><w:tc>
  <w:p><w:r><w:t>controlled row</w:t></w:r></w:p>
 </w:tc></w:tr></w:sdtContent></w:sdt></w:tbl></w:body>
</w:document>"""
    _write_zip(path, _docx_members(document_xml))

    with pytest.raises(UnsupportedFormatError, match="content controls inside tables"):
        _ingest(path)


def test_docx_unparsed_header_is_rejected(tmp_path: Path):
    path = tmp_path / "header.docx"
    members = _docx_members()
    members["word/header1.xml"] = """<?xml version="1.0"?>
<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
 <w:p><w:r><w:t>controlled header</w:t></w:r></w:p>
</w:hdr>"""
    _write_zip(path, members)

    with pytest.raises(UnsupportedFormatError, match="unsupported text-bearing parts"):
        _ingest(path)


def test_xlsx_duplicate_cell_locator_is_rejected(tmp_path: Path):
    path = tmp_path / "duplicate-cell.xlsx"
    members = _xlsx_members()
    members["xl/worksheets/sheet1.xml"] = """<?xml version="1.0"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
 <sheetData><row r="1"><c r="A1"><v>1</v></c><c r="A1"><v>2</v></c></row></sheetData>
</worksheet>"""
    _write_zip(path, members)

    with pytest.raises(IngestionError, match="duplicate cell coordinate"):
        _ingest(path)


def test_xlsx_negative_shared_string_index_is_rejected(tmp_path: Path):
    path = tmp_path / "negative-string-index.xlsx"
    members = _xlsx_members()
    members["xl/sharedStrings.xml"] = """<?xml version="1.0"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
 <si><t>FIRST</t></si><si><t>LAST</t></si>
</sst>"""
    members["xl/worksheets/sheet1.xml"] = """<?xml version="1.0"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
 <sheetData><row r="1"><c r="A1" t="s"><v>-1</v></c></row></sheetData>
</worksheet>"""
    _write_zip(path, members)

    with pytest.raises(IngestionError, match="shared-string index"):
        _ingest(path)


@pytest.mark.parametrize("coordinate", ["XFE1", "A1048577", "AAAA1"])
def test_xlsx_coordinate_must_stay_inside_excel_bounds(
    tmp_path: Path, coordinate: str
):
    path = tmp_path / "out-of-bounds.xlsx"
    members = _xlsx_members()
    members["xl/worksheets/sheet1.xml"] = f"""<?xml version="1.0"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
 <sheetData><row r="1"><c r="{coordinate}"><v>1</v></c></row></sheetData>
</worksheet>"""
    _write_zip(path, members)

    with pytest.raises(IngestionError, match="outside Excel"):
        _ingest(path)


def test_external_ooxml_relationship_is_explicitly_rejected(tmp_path: Path):
    path = tmp_path / "external.xlsx"
    members = _xlsx_members()
    members["xl/_rels/workbook.xml.rels"] = """<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
 <Relationship Id="rId1"
  Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"
  Target="https://example.invalid/sheet.xml" TargetMode="External"/>
</Relationships>"""
    _write_zip(path, members)

    with pytest.raises(ArchiveSafetyError, match="external OOXML relationship"):
        _ingest(path)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_file_bytes": True},
        {"max_archive_members": 1.5},
        {"max_compression_ratio": math.nan},
        {"max_compression_ratio": math.inf},
    ],
)
def test_limits_require_positive_finite_values(kwargs: dict):
    with pytest.raises(ValueError):
        IngestionLimits(**kwargs)


def test_parent_symlink_swap_is_rejected_during_rooted_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    root = tmp_path / "root"
    slot = root / "slot"
    slot.mkdir(parents=True)
    source = slot / "source.csv"
    source.write_text("safe\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "source.csv").write_text("outside\n", encoding="utf-8")

    original_resolve = ingestion._resolve_source

    def resolve_then_swap(path, root_dir):
        location = original_resolve(path, root_dir)
        slot.rename(root / "original-slot")
        try:
            slot.symlink_to(outside, target_is_directory=True)
        except OSError:
            pytest.skip("directory symlinks are not available on this filesystem")
        return location

    monkeypatch.setattr(ingestion, "_resolve_source", resolve_then_swap)
    with pytest.raises(UnsafePathError, match="beneath root_dir|reparse"):
        ingest_document(
            source,
            document_id="DOC",
            document_type="CONTROL_PLAN",
            root_dir=root,
        )
