"""Safe, dependency-free ingestion for evidence-grounded document revisions.

The ingestion layer is deliberately conservative:

* source files are treated as untrusted, read-only bytes;
* no formula, macro, embedded object, or PDF action is executed;
* OOXML containers are inspected before any XML is parsed;
* every extracted item keeps a stable source locator; and
* PDF extraction is opt-in because the Python standard library has no reliable
  PDF text/layout parser.

The returned mapping has the same top-level identity/revision keys used by the
synthetic ``DocumentRevision`` records in QualityCI.  Domain-specific semantic
mapping (for example, mapping a spreadsheet column to ``characteristic_id``)
is intentionally a later, reviewed step.
"""

from __future__ import annotations

import csv
import hashlib
import io
import math
import os
import posixpath
import re
import stat
import zipfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from xml.etree import ElementTree as ET


class IngestionError(ValueError):
    """Base class for rejected or malformed source documents."""


class UnsafePathError(IngestionError):
    """Raised when a path escapes its allowed root or is not a regular file."""


class UnsupportedFormatError(IngestionError):
    """Raised when a file type or extraction path is intentionally unsupported."""


class ArchiveSafetyError(IngestionError):
    """Raised when an OOXML archive violates container safety limits."""


class LimitExceededError(IngestionError):
    """Raised when an input exceeds an explicit resource limit."""


class ScannedPdfError(IngestionError):
    """Raised when a PDF adapter finds no extractable text on any page."""


PdfPageExtractor = Callable[[bytes], Iterable[str]]


@dataclass(frozen=True)
class IngestionLimits:
    """Resource limits applied before and during parsing."""

    max_file_bytes: int = 10 * 1024 * 1024
    max_archive_members: int = 1_000
    max_archive_member_bytes: int = 20 * 1024 * 1024
    max_archive_uncompressed_bytes: int = 50 * 1024 * 1024
    max_compression_ratio: float = 200.0
    max_evidence_items: int = 20_000
    max_text_chars: int = 10_000_000
    max_cell_chars: int = 100_000
    max_csv_rows: int = 10_000
    max_csv_columns: int = 1_000
    max_pdf_pages: int = 500

    def __post_init__(self) -> None:
        integer_limits = {
            "max_file_bytes": self.max_file_bytes,
            "max_archive_members": self.max_archive_members,
            "max_archive_member_bytes": self.max_archive_member_bytes,
            "max_archive_uncompressed_bytes": self.max_archive_uncompressed_bytes,
            "max_evidence_items": self.max_evidence_items,
            "max_text_chars": self.max_text_chars,
            "max_cell_chars": self.max_cell_chars,
            "max_csv_rows": self.max_csv_rows,
            "max_csv_columns": self.max_csv_columns,
            "max_pdf_pages": self.max_pdf_pages,
        }
        for name, value in integer_limits.items():
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        ratio = self.max_compression_ratio
        if (
            isinstance(ratio, bool)
            or not isinstance(ratio, (int, float))
            or not math.isfinite(float(ratio))
            or ratio <= 0
        ):
            raise ValueError("max_compression_ratio must be positive and finite")


DEFAULT_LIMITS = IngestionLimits()
INGESTION_POLICY_VERSION = "qualityci-ingestion-policy-0.2"
_ALLOWED_EXTENSIONS = {".csv", ".xlsx", ".docx", ".pdf"}
_OOXML_EXTENSIONS = {".xlsx", ".docx"}
_XML_DANGER_MARKERS = ("<!DOCTYPE", "<!ENTITY")
_NON_UTF8_XML_BOMS = (
    b"\x00\x00\xfe\xff",  # UTF-32 BE
    b"\xff\xfe\x00\x00",  # UTF-32 LE
    b"\xfe\xff",  # UTF-16 BE
    b"\xff\xfe",  # UTF-16 LE
)
_XML_DECLARATION_ENCODING = re.compile(
    r"<\?xml\b[^>]*\bencoding\s*=\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)
_XLSX_CELL = re.compile(r"^[A-Za-z]+[1-9][0-9]*$")
_SIMPLE_SHEET_NAME = re.compile(r"^[A-Za-z0-9_.]+$")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_PDF_NAME = re.compile(rb"/(?:#[0-9A-Fa-f]{2}|[^\x00\x09\x0a\x0c\x0d\x20<>{}\[\]()/%%])+")
_PDF_FORBIDDEN_NAMES = {
    b"aa",
    b"acroform",
    b"embeddedfile",
    b"encrypt",
    b"gotoe",
    b"gotor",
    b"importdata",
    b"javascript",
    b"js",
    b"launch",
    b"movie",
    b"objstm",
    b"openaction",
    b"richmedia",
    b"sound",
    b"submitform",
    b"xfa",
}
_XLSX_MAX_ROW = 1_048_576
_XLSX_MAX_COLUMN = 16_384

_CONTENT_TYPES_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
_MAIN_CONTENT_TYPES = {
    "XLSX": (
        "xl/workbook.xml",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
    ),
    "DOCX": (
        "word/document.xml",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    ),
}
_DANGEROUS_CONTENT_TYPE_MARKERS = (
    "macroenabled",
    "vbaproject",
    "activex",
    "oleobject",
    "embedded",
    "executable",
)
_RELATIONSHIP_PREFIXES = (
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/",
    "http://schemas.openxmlformats.org/package/2006/relationships/",
    "http://purl.oclc.org/ooxml/officeDocument/relationships/",
)
_ALLOWED_RELATIONSHIP_KINDS = {
    "calcChain",
    "chart",
    "comments",
    "core-properties",
    "custom-properties",
    "customXml",
    "customXmlProps",
    "drawing",
    "endnotes",
    "extended-properties",
    "fontTable",
    "footer",
    "footnotes",
    "glossaryDocument",
    "header",
    "hyperlink",
    "image",
    "numbering",
    "officeDocument",
    "printerSettings",
    "settings",
    "sharedStrings",
    "styles",
    "theme",
    "vmlDrawing",
    "webSettings",
    "worksheet",
}

_NS_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_NS_REL_DOC = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_NS_REL_PACKAGE = "http://schemas.openxmlformats.org/package/2006/relationships"
_NS_WORD = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def ingest_document(
    path: str | Path,
    *,
    document_id: str,
    document_type: str,
    revision: str = "UNCONTROLLED",
    status: str = "DRAFT",
    owner: str = "UNASSIGNED",
    revision_date: str = "",
    root_dir: str | Path | None = None,
    limits: IngestionLimits = DEFAULT_LIMITS,
    pdf_page_extractor: PdfPageExtractor | None = None,
    trusted_pdf_adapter: bool = False,
) -> dict[str, Any]:
    """Ingest one local document into a DocumentRevision-style mapping.

    ``root_dir`` should be supplied whenever ``path`` originates from an
    upload or other untrusted string.  The resolved source must stay inside
    that root.  Symlink files are rejected even when their target is inside
    the root.

    PDF input is rejected unless ``pdf_page_extractor`` is explicitly
    provided *and* ``trusted_pdf_adapter=True``.  That flag is an explicit
    trust decision by the caller, not a safety attestation by this module.
    The adapter receives immutable source bytes and must yield one string per
    physical PDF page in order.  Empty output is treated as a scanned/image-
    only PDF, never as a successful extraction.
    """

    source = _resolve_source(path, root_dir)
    raw, _size = _read_source(source, limits)
    return ingest_document_bytes(
        raw,
        filename=source.path.name,
        relative_path=source.display_path,
        document_id=document_id,
        document_type=document_type,
        revision=revision,
        status=status,
        owner=owner,
        revision_date=revision_date,
        limits=limits,
        pdf_page_extractor=pdf_page_extractor,
        trusted_pdf_adapter=trusted_pdf_adapter,
    )


def ingest_document_bytes(
    raw: bytes,
    *,
    filename: str,
    relative_path: str,
    document_id: str,
    document_type: str,
    revision: str = "UNCONTROLLED",
    status: str = "DRAFT",
    owner: str = "UNASSIGNED",
    revision_date: str = "",
    limits: IngestionLimits = DEFAULT_LIMITS,
    pdf_page_extractor: PdfPageExtractor | None = None,
    trusted_pdf_adapter: bool = False,
) -> dict[str, Any]:
    """Hash and parse one immutable byte buffer without reopening a path."""

    if not isinstance(raw, bytes):
        raise TypeError("raw artifact content must be immutable bytes")
    if len(raw) > limits.max_file_bytes:
        raise LimitExceededError(
            f"source content exceeds {limits.max_file_bytes} byte limit"
        )
    metadata = {
        "document_id": _validate_metadata("document_id", document_id),
        "document_type": _validate_metadata("document_type", document_type),
        "revision": _validate_metadata("revision", revision),
        "status": _validate_metadata("status", status),
        "owner": _validate_metadata("owner", owner),
        "revision_date": _validate_metadata(
            "revision_date", revision_date, allow_empty=True
        ),
    }
    safe_filename = _validate_metadata("filename", filename)
    safe_relative_path = _validate_metadata("relative_path", relative_path)
    extension = Path(safe_filename).suffix.lower()
    if extension not in _ALLOWED_EXTENSIONS:
        raise UnsupportedFormatError(
            f"unsupported extension {extension or '<none>'}; allowed: {sorted(_ALLOWED_EXTENSIONS)}"
        )
    _verify_magic(extension, raw)

    source_hash = hashlib.sha256(raw).hexdigest()
    if extension == ".csv":
        fields = _parse_csv(raw, source_hash, limits)
        ingestion_mode = "STANDARD_LIBRARY_CSV"
    elif extension == ".xlsx":
        fields = _parse_xlsx(raw, source_hash, limits)
        ingestion_mode = "STANDARD_LIBRARY_OOXML"
    elif extension == ".docx":
        fields = _parse_docx(raw, source_hash, limits)
        ingestion_mode = "STANDARD_LIBRARY_OOXML"
    else:
        fields = _parse_pdf(
            raw,
            source_hash,
            limits,
            pdf_page_extractor,
            trusted_pdf_adapter=trusted_pdf_adapter,
        )
        ingestion_mode = "EXPLICIT_PDF_PAGE_ADAPTER"

    return {
        **metadata,
        "source_hash": source_hash,
        "source": {
            "filename": safe_filename,
            "relative_path": safe_relative_path,
            "format": extension[1:].upper(),
            "size_bytes": len(raw),
            "ingestion_mode": ingestion_mode,
            "read_only": True,
            "content_executed": False,
        },
        "fields": fields,
    }


def read_source_bytes(
    path: str | Path,
    *,
    root_dir: str | Path,
    limits: IngestionLimits = DEFAULT_LIMITS,
) -> tuple[str, str, bytes]:
    """Securely read a regular source once and return immutable captured bytes."""

    source = _resolve_source(path, root_dir)
    raw, _size = _read_source(source, limits)
    return source.path.name, source.display_path, raw


def _validate_metadata(name: str, value: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    if not value and not allow_empty:
        raise IngestionError(f"{name} must not be empty")
    if len(value) > 256:
        raise IngestionError(f"{name} exceeds 256 characters")
    if _CONTROL_CHARS.search(value):
        raise IngestionError(f"{name} contains control characters")
    return value


@dataclass(frozen=True)
class _SourceLocation:
    path: Path
    display_path: str
    root: Path | None = None
    relative_parts: tuple[str, ...] = ()
    root_device: int | None = None
    root_inode: int | None = None
    root_windows_file_id: tuple[int, bytes] | None = None
    source_device: int | None = None
    source_inode: int | None = None


def _resolve_source(path: str | Path, root_dir: str | Path | None) -> _SourceLocation:
    candidate = Path(path).expanduser()
    candidate_absolute = Path(os.path.abspath(os.fspath(candidate)))
    if root_dir is not None and ".." in candidate.parts:
        raise UnsafePathError("source path contains a parent traversal component")
    if candidate.is_symlink():
        raise UnsafePathError("symlink sources are not accepted")
    try:
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, RuntimeError, OSError) as error:
        raise UnsafePathError(f"source path cannot be resolved: {error}") from error
    if not resolved.is_file():
        raise UnsafePathError("source must be a regular file")

    if root_dir is None:
        source_stat = resolved.stat(follow_symlinks=False)
        if _CONTROL_CHARS.search(resolved.name):
            raise UnsafePathError("source filename contains control characters")
        return _SourceLocation(
            path=resolved,
            display_path=resolved.name,
            source_device=source_stat.st_dev,
            source_inode=source_stat.st_ino,
        )

    try:
        root_input = Path(root_dir).expanduser()
        root = root_input.resolve(strict=True)
    except (FileNotFoundError, RuntimeError, OSError) as error:
        raise UnsafePathError(f"root_dir cannot be resolved: {error}") from error
    if not root.is_dir():
        raise UnsafePathError("root_dir must be a directory")
    try:
        canonical_relative = resolved.relative_to(root)
    except ValueError as error:
        raise UnsafePathError("source path escapes the allowed root_dir") from error

    # Preserve the caller's lexical path beneath the canonical root whenever
    # possible.  Opening only ``resolved`` would silently erase an intermediate
    # symlink/reparse component before the descriptor-based opener can reject it.
    # A lexical root alias is accepted only after it is mapped back to the same
    # canonical source; otherwise the already-contained canonical path is used.
    try:
        relative = candidate_absolute.relative_to(root)
    except ValueError:
        root_alias = Path(os.path.abspath(os.fspath(root_input)))
        try:
            alias_relative = candidate_absolute.relative_to(root_alias)
            alias_source = root.joinpath(*alias_relative.parts)
            if alias_source.resolve(strict=True) == resolved:
                relative = alias_relative
            else:
                relative = canonical_relative
        except (ValueError, FileNotFoundError, RuntimeError, OSError):
            relative = canonical_relative
    root_stat = root.stat(follow_symlinks=False)
    source_stat = resolved.stat(follow_symlinks=False)
    root_windows_file_id = (
        _capture_windows_root_file_id(root) if os.name == "nt" else None
    )
    display_path = relative.as_posix()
    if _CONTROL_CHARS.search(display_path):
        raise UnsafePathError("source relative path contains control characters")
    return _SourceLocation(
        path=resolved,
        display_path=display_path,
        root=root,
        relative_parts=relative.parts,
        root_device=root_stat.st_dev,
        root_inode=root_stat.st_ino,
        root_windows_file_id=root_windows_file_id,
        source_device=source_stat.st_dev,
        source_inode=source_stat.st_ino,
    )


def _verify_magic(extension: str, raw: bytes) -> None:
    if extension in _OOXML_EXTENSIONS:
        if not raw.startswith(b"PK") or not zipfile.is_zipfile(io.BytesIO(raw)):
            raise UnsupportedFormatError(f"{extension} source is not a valid ZIP/OOXML container")
    elif extension == ".pdf":
        if not raw.lstrip().startswith(b"%PDF-"):
            raise UnsupportedFormatError(".pdf source is missing the PDF signature")
    elif extension == ".csv" and raw.startswith(b"PK"):
        raise UnsupportedFormatError(".csv source has ZIP content; extension/content mismatch")


def _read_source(source: _SourceLocation, limits: IngestionLimits) -> tuple[bytes, int]:
    """Open once beneath an optional root descriptor and bound the actual read."""

    descriptor = _open_source_descriptor(source)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise UnsafePathError("source must remain a regular file while being read")
        if before.st_nlink != 1:
            raise UnsafePathError("hard-linked sources are not accepted")
        if (
            before.st_dev != source.source_device
            or before.st_ino != source.source_inode
        ):
            raise UnsafePathError("source was replaced between validation and open")
        if before.st_size > limits.max_file_bytes:
            raise LimitExceededError(
                f"source file is {before.st_size} bytes; limit is {limits.max_file_bytes} bytes"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(limits.max_file_bytes + 1)
        if len(raw) > limits.max_file_bytes:
            raise LimitExceededError(
                f"source content exceeds {limits.max_file_bytes} bytes while being read"
            )
        after = os.fstat(descriptor)
        identity_before = (before.st_dev, before.st_ino)
        identity_after = (after.st_dev, after.st_ino)
        timestamps_before = (before.st_mtime_ns, before.st_ctime_ns)
        timestamps_after = (after.st_mtime_ns, after.st_ctime_ns)
        if (
            len(raw) != before.st_size
            or before.st_size != after.st_size
            or identity_before != identity_after
            or timestamps_before != timestamps_after
        ):
            raise IngestionError("source changed while being read; retry with a stable file")
        return raw, before.st_size
    finally:
        os.close(descriptor)


def _open_source_descriptor(source: _SourceLocation) -> int:
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    file_flags |= nofollow
    if source.root is None:
        try:
            return os.open(source.path, file_flags)
        except OSError as error:
            raise UnsafePathError(f"source cannot be opened safely: {error}") from error

    if not source.relative_parts:
        raise UnsafePathError("source path must name a file beneath root_dir")
    if os.name == "nt":
        return _open_source_descriptor_windows(source)
    if os.open not in os.supports_dir_fd or not nofollow or not hasattr(os, "O_DIRECTORY"):
        raise UnsafePathError(
            "this platform cannot securely open an untrusted path beneath root_dir"
        )

    directory_flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptors: list[int] = []
    try:
        root_descriptor = os.open(source.root, directory_flags)
        descriptors.append(root_descriptor)
        root_stat = os.fstat(root_descriptor)
        if (
            root_stat.st_dev != source.root_device
            or root_stat.st_ino != source.root_inode
        ):
            raise UnsafePathError("root_dir changed between validation and open")

        current = root_descriptor
        for component in source.relative_parts[:-1]:
            if component in {"", ".", ".."} or "/" in component or "\x00" in component:
                raise UnsafePathError("source path contains an unsafe component")
            current = os.open(component, directory_flags, dir_fd=current)
            descriptors.append(current)

        filename = source.relative_parts[-1]
        if filename in {"", ".", ".."} or "/" in filename or "\x00" in filename:
            raise UnsafePathError("source filename is unsafe")
        descriptor = os.open(filename, file_flags, dir_fd=current)
    except UnsafePathError:
        raise
    except OSError as error:
        raise UnsafePathError(f"source cannot be opened safely beneath root_dir: {error}") from error
    finally:
        for opened in reversed(descriptors):
            try:
                os.close(opened)
            except OSError:
                pass
    return descriptor


def _open_source_descriptor_windows(source: _SourceLocation) -> int:
    """Open a root-bounded source with native Windows handles.

    Windows does not expose POSIX ``dir_fd``/``O_NOFOLLOW`` through ``os.open``.
    Instead, this opener holds the canonical root and every directory component
    open without write/delete sharing, rejects any reparse-point handle, verifies
    the final path reported by each handle, and only then opens the source with
    ``FILE_FLAG_OPEN_REPARSE_POINT``.  The final handle is converted to a Python
    file descriptor so the common identity/size/change checks remain in force.
    """

    if os.name != "nt":  # pragma: no cover - defensive misuse guard
        raise UnsafePathError("Windows secure opener is unavailable on this platform")
    if source.root is None or not source.relative_parts:
        raise UnsafePathError("source path must name a file beneath root_dir")

    _assert_windows_local_ntfs(source.root)

    # Imports stay local so non-Windows builds never import Windows-only modules.
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class _FileAttributeTagInfo(ctypes.Structure):
        _fields_ = [
            ("FileAttributes", wintypes.DWORD),
            ("ReparseTag", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    get_attribute_tag = kernel32.GetFileInformationByHandleEx
    get_attribute_tag.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    get_attribute_tag.restype = wintypes.BOOL
    get_final_path = kernel32.GetFinalPathNameByHandleW
    get_final_path.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    get_final_path.restype = wintypes.DWORD

    generic_read = 0x80000000
    file_read_attributes = 0x00000080
    file_share_read = 0x00000001
    open_existing = 3
    file_attribute_directory = 0x00000010
    file_attribute_reparse_point = 0x00000400
    file_flag_backup_semantics = 0x02000000
    file_flag_open_reparse_point = 0x00200000
    file_flag_sequential_scan = 0x08000000
    file_attribute_tag_info = 9
    invalid_handle_value = ctypes.c_void_p(-1).value

    def windows_error(prefix: str) -> UnsafePathError:
        code = ctypes.get_last_error()
        return UnsafePathError(f"{prefix}: {ctypes.WinError(code)}")

    def extended_path(path: Path) -> str:
        value = os.path.abspath(os.fspath(path))
        if value.startswith("\\\\?\\"):
            return value
        if value.startswith("\\\\"):
            return "\\\\?\\UNC\\" + value[2:]
        return "\\\\?\\" + value

    def normalized_path(value: str | Path) -> str:
        text = os.fspath(value)
        if text.startswith("\\\\?\\UNC\\"):
            text = "\\\\" + text[8:]
        elif text.startswith("\\\\?\\"):
            text = text[4:]
        return os.path.normcase(os.path.abspath(text))

    def open_handle(path: Path, access: int, flags: int) -> int:
        handle = create_file(
            extended_path(path),
            access,
            file_share_read,
            None,
            open_existing,
            flags,
            None,
        )
        if handle is None or handle == invalid_handle_value:
            raise windows_error(f"source component cannot be opened safely: {path}")
        return int(handle)

    def attribute_info(handle: int) -> _FileAttributeTagInfo:
        info = _FileAttributeTagInfo()
        if not get_attribute_tag(
            handle,
            file_attribute_tag_info,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            raise windows_error("source component attributes cannot be inspected")
        return info

    def final_handle_path(handle: int) -> str:
        size = 512
        while size <= 32_768:
            buffer = ctypes.create_unicode_buffer(size)
            length = get_final_path(handle, buffer, size, 0)
            if length == 0:
                raise windows_error("source component final path cannot be inspected")
            if length < size:
                return normalized_path(buffer.value)
            size = length + 1
        raise UnsafePathError("source component final path exceeds the Windows safety limit")

    def validate_component(component: str) -> None:
        if (
            component in {"", ".", ".."}
            or any(character in component for character in "\\/\x00:<>\"|?*")
            or component.endswith((" ", "."))
            or _CONTROL_CHARS.search(component)
        ):
            raise UnsafePathError("source path contains an unsafe Windows component")
        stem = component.split(".", 1)[0].casefold()
        reserved = {"con", "prn", "aux", "nul"}
        reserved.update(f"com{number}" for number in range(1, 10))
        reserved.update(f"lpt{number}" for number in range(1, 10))
        if stem in reserved:
            raise UnsafePathError("source path contains a reserved Windows component")

    def validate_opened_path(handle: int, expected: Path, *, directory: bool) -> None:
        info = attribute_info(handle)
        if info.FileAttributes & file_attribute_reparse_point:
            raise UnsafePathError("source path contains a Windows reparse point")
        is_directory = bool(info.FileAttributes & file_attribute_directory)
        if is_directory != directory:
            expected_kind = "directory" if directory else "regular file"
            raise UnsafePathError(f"source component is not the expected {expected_kind}")
        if final_handle_path(handle) != normalized_path(expected):
            raise UnsafePathError("source component changed while its path was being opened")

    held_directories: list[int] = []
    file_handle: int | None = None
    try:
        directory_flags = file_flag_backup_semantics | file_flag_open_reparse_point
        root_handle = open_handle(source.root, file_read_attributes, directory_flags)
        held_directories.append(root_handle)
        validate_opened_path(root_handle, source.root, directory=True)
        if (
            source.root_windows_file_id is None
            or _windows_handle_file_id(root_handle) != source.root_windows_file_id
        ):
            raise UnsafePathError("root_dir changed between validation and open")

        current_path = source.root
        for component in source.relative_parts[:-1]:
            validate_component(component)
            current_path = current_path / component
            component_handle = open_handle(
                current_path, file_read_attributes, directory_flags
            )
            held_directories.append(component_handle)
            validate_opened_path(component_handle, current_path, directory=True)

        filename = source.relative_parts[-1]
        validate_component(filename)
        expected_file = current_path / filename
        file_handle = open_handle(
            expected_file,
            generic_read,
            file_flag_open_reparse_point | file_flag_sequential_scan,
        )
        validate_opened_path(file_handle, expected_file, directory=False)

        root_path = normalized_path(source.root)
        final_path = final_handle_path(file_handle)
        try:
            if os.path.commonpath([root_path, final_path]) != root_path:
                raise UnsafePathError("source path escapes the allowed root_dir")
        except ValueError as error:
            raise UnsafePathError("source path escapes the allowed root_dir") from error

        descriptor_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        descriptor_flags |= getattr(os, "O_NOINHERIT", 0)
        descriptor = msvcrt.open_osfhandle(file_handle, descriptor_flags)
        file_handle = None  # descriptor now owns the native handle
        return descriptor
    except UnsafePathError:
        raise
    except OSError as error:
        raise UnsafePathError(
            f"source cannot be opened safely beneath root_dir: {error}"
        ) from error
    finally:
        if file_handle is not None:
            close_handle(file_handle)
        for opened in reversed(held_directories):
            close_handle(opened)


def _windows_handle_file_id(handle: int) -> tuple[int, bytes]:
    """Return the volume serial plus 128-bit native ID for an open handle."""

    if os.name != "nt":  # pragma: no cover - Windows-only implementation
        raise UnsafePathError("Windows file identity is unavailable on this platform")

    import ctypes
    from ctypes import wintypes

    class _FileId128(ctypes.Structure):
        _fields_ = [("Identifier", ctypes.c_ubyte * 16)]

    class _FileIdInfo(ctypes.Structure):
        _fields_ = [
            ("VolumeSerialNumber", ctypes.c_ulonglong),
            ("FileId", _FileId128),
        ]

    get_information = ctypes.WinDLL(
        "kernel32", use_last_error=True
    ).GetFileInformationByHandleEx
    get_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    get_information.restype = wintypes.BOOL
    file_id_info = 18
    info = _FileIdInfo()
    if not get_information(
        handle,
        file_id_info,
        ctypes.byref(info),
        ctypes.sizeof(info),
    ):
        code = ctypes.get_last_error()
        raise UnsafePathError(
            "Windows filesystem cannot provide a stable 128-bit file identity: "
            f"{ctypes.WinError(code)}"
        )
    return int(info.VolumeSerialNumber), bytes(info.FileId.Identifier)


def _assert_windows_local_ntfs(path: Path) -> None:
    """Require a fixed local NTFS volume for the native root-bounded opener."""

    if os.name != "nt":  # pragma: no cover - Windows-only implementation
        raise UnsafePathError("Windows volume checks are unavailable on this platform")

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_volume_path = kernel32.GetVolumePathNameW
    get_volume_path.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    get_volume_path.restype = wintypes.BOOL
    get_drive_type = kernel32.GetDriveTypeW
    get_drive_type.argtypes = [wintypes.LPCWSTR]
    get_drive_type.restype = wintypes.UINT
    get_volume_information = kernel32.GetVolumeInformationW
    get_volume_information.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    get_volume_information.restype = wintypes.BOOL

    volume_path = ctypes.create_unicode_buffer(32_768)
    if not get_volume_path(os.fspath(path), volume_path, len(volume_path)):
        code = ctypes.get_last_error()
        raise UnsafePathError(
            f"Windows root volume cannot be identified safely: {ctypes.WinError(code)}"
        )

    drive_fixed = 3
    drive_type = get_drive_type(volume_path.value)
    if drive_type != drive_fixed:
        raise UnsafePathError(
            "Windows root_dir must be on a fixed local NTFS volume"
        )

    volume_serial = wintypes.DWORD()
    maximum_component_length = wintypes.DWORD()
    filesystem_flags = wintypes.DWORD()
    filesystem_name = ctypes.create_unicode_buffer(64)
    if not get_volume_information(
        volume_path.value,
        None,
        0,
        ctypes.byref(volume_serial),
        ctypes.byref(maximum_component_length),
        ctypes.byref(filesystem_flags),
        filesystem_name,
        len(filesystem_name),
    ):
        code = ctypes.get_last_error()
        raise UnsafePathError(
            f"Windows root filesystem cannot be inspected safely: {ctypes.WinError(code)}"
        )
    if filesystem_name.value.upper() != "NTFS":
        raise UnsafePathError(
            "Windows root_dir must be on a fixed local NTFS volume"
        )


def _capture_windows_root_file_id(path: Path) -> tuple[int, bytes]:
    """Capture a pre-open native root identity for later TOCTOU comparison."""

    if os.name != "nt":  # pragma: no cover - Windows-only implementation
        raise UnsafePathError("Windows file identity is unavailable on this platform")

    import ctypes
    from ctypes import wintypes

    _assert_windows_local_ntfs(path)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    get_attribute_tag = kernel32.GetFileInformationByHandleEx
    get_attribute_tag.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    get_attribute_tag.restype = wintypes.BOOL

    class _FileAttributeTagInfo(ctypes.Structure):
        _fields_ = [
            ("FileAttributes", wintypes.DWORD),
            ("ReparseTag", wintypes.DWORD),
        ]

    value = os.path.abspath(os.fspath(path))
    if not value.startswith("\\\\?\\"):
        value = (
            "\\\\?\\UNC\\" + value[2:]
            if value.startswith("\\\\")
            else "\\\\?\\" + value
        )
    file_read_attributes = 0x00000080
    file_share_read_write_delete = 0x00000007
    open_existing = 3
    file_attribute_directory = 0x00000010
    file_attribute_reparse_point = 0x00000400
    file_flag_backup_semantics = 0x02000000
    file_flag_open_reparse_point = 0x00200000
    file_attribute_tag_info = 9
    invalid_handle_value = ctypes.c_void_p(-1).value

    handle = create_file(
        value,
        file_read_attributes,
        file_share_read_write_delete,
        None,
        open_existing,
        file_flag_backup_semantics | file_flag_open_reparse_point,
        None,
    )
    if handle is None or handle == invalid_handle_value:
        code = ctypes.get_last_error()
        raise UnsafePathError(
            f"Windows root_dir cannot be opened for identity capture: {ctypes.WinError(code)}"
        )
    handle_value = int(handle)
    try:
        attributes = _FileAttributeTagInfo()
        if not get_attribute_tag(
            handle_value,
            file_attribute_tag_info,
            ctypes.byref(attributes),
            ctypes.sizeof(attributes),
        ):
            code = ctypes.get_last_error()
            raise UnsafePathError(
                "Windows root_dir attributes cannot be inspected safely: "
                f"{ctypes.WinError(code)}"
            )
        if attributes.FileAttributes & file_attribute_reparse_point:
            raise UnsafePathError("root_dir must not be a Windows reparse point")
        if not attributes.FileAttributes & file_attribute_directory:
            raise UnsafePathError("root_dir must remain a directory")
        return _windows_handle_file_id(handle_value)
    finally:
        close_handle(handle_value)


def _base_evidence(
    *, source_hash: str, kind: str, locator: str, text: str, **coordinates: Any
) -> dict[str, Any]:
    return {
        "kind": kind,
        "locator": locator,
        "text": text,
        "source_hash": source_hash,
        "coordinates": coordinates,
    }


def _check_evidence_limits(evidence: list[dict[str, Any]], limits: IngestionLimits) -> None:
    if len(evidence) > limits.max_evidence_items:
        raise LimitExceededError(
            f"evidence item count exceeds {limits.max_evidence_items}"
        )
    total_chars = sum(len(item["text"]) for item in evidence)
    if total_chars > limits.max_text_chars:
        raise LimitExceededError(f"extracted text exceeds {limits.max_text_chars} characters")


def _parse_csv(raw: bytes, source_hash: str, limits: IngestionLimits) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError as error:
        raise IngestionError("CSV must be UTF-8 or UTF-8 with BOM") from error
    if "\x00" in text:
        raise IngestionError("CSV contains NUL bytes")

    sample = text[:32_768]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|") if sample.strip() else csv.excel
    except csv.Error:
        dialect = csv.excel

    evidence: list[dict[str, Any]] = []
    row_count = 0
    column_count = 0
    try:
        reader = csv.reader(io.StringIO(text, newline=""), dialect)
        for row_number, row in enumerate(reader, start=1):
            row_count = row_number
            if row_number > limits.max_csv_rows:
                raise LimitExceededError(f"CSV row count exceeds {limits.max_csv_rows}")
            if len(row) > limits.max_csv_columns:
                raise LimitExceededError(
                    f"CSV row {row_number} exceeds {limits.max_csv_columns} columns"
                )
            column_count = max(column_count, len(row))
            for column_number, value in enumerate(row, start=1):
                if len(value) > limits.max_cell_chars:
                    raise LimitExceededError(
                        f"CSV cell at row {row_number}, column {column_number} exceeds "
                        f"{limits.max_cell_chars} characters"
                    )
                column_label = _column_label(column_number)
                item = _base_evidence(
                    source_hash=source_hash,
                    kind="CELL",
                    locator=f"CSV#row-{row_number}.cell-{column_label}",
                    text=value,
                    row=row_number,
                    column=column_number,
                    column_label=column_label,
                )
                if value.lstrip().startswith(("=", "+", "-", "@")):
                    item["potential_spreadsheet_formula"] = True
                    item["formula_executed"] = False
                evidence.append(item)
                if len(evidence) > limits.max_evidence_items:
                    raise LimitExceededError(
                        f"evidence item count exceeds {limits.max_evidence_items}"
                    )
    except csv.Error as error:
        raise IngestionError(f"malformed CSV: {error}") from error

    _check_evidence_limits(evidence, limits)
    return {
        "evidence": evidence,
        "structure": {
            "format": "CSV",
            "row_count": row_count,
            "column_count": column_count,
            "delimiter": getattr(dialect, "delimiter", ","),
            "header_values": [item["text"] for item in evidence if item["coordinates"]["row"] == 1],
        },
    }


def _parse_xlsx(raw: bytes, source_hash: str, limits: IngestionLimits) -> dict[str, Any]:
    with _SafeOOXML(raw, limits, expected_format="XLSX") as archive:
        if "xl/workbook.xml" not in archive.names:
            raise IngestionError("XLSX is missing xl/workbook.xml")
        workbook = archive.xml("xl/workbook.xml")
        rels = _xlsx_relationships(archive)
        shared_strings = _xlsx_shared_strings(archive, limits)
        evidence: list[dict[str, Any]] = []
        sheets_summary: list[dict[str, Any]] = []
        seen_sheet_names: set[str] = set()
        seen_relationship_ids: set[str] = set()
        seen_sheet_paths: set[str] = set()
        seen_locators: set[str] = set()

        sheets = workbook.find(f"{{{_NS_MAIN}}}sheets")
        if sheets is None:
            raise IngestionError("XLSX workbook has no sheets collection")
        for sheet_number, sheet in enumerate(sheets, start=1):
            sheet_name = sheet.attrib.get("name", f"Sheet{sheet_number}")
            _validate_sheet_name(sheet_name)
            sheet_key = sheet_name.casefold()
            if sheet_key in seen_sheet_names:
                raise IngestionError(f"XLSX has duplicate/colliding sheet name: {sheet_name!r}")
            seen_sheet_names.add(sheet_key)
            relationship_id = sheet.attrib.get(f"{{{_NS_REL_DOC}}}id")
            if not relationship_id or relationship_id not in rels:
                raise IngestionError(f"XLSX sheet {sheet_name!r} has no internal worksheet relationship")
            if relationship_id in seen_relationship_ids:
                raise IngestionError(
                    f"XLSX sheets reuse worksheet relationship {relationship_id!r}"
                )
            seen_relationship_ids.add(relationship_id)
            sheet_path, relationship_type = rels[relationship_id]
            if _relationship_kind(relationship_type) != "worksheet":
                raise IngestionError(
                    f"XLSX sheet {sheet_name!r} relationship is not a worksheet"
                )
            if sheet_path in seen_sheet_paths:
                raise IngestionError(f"XLSX sheets reuse worksheet member: {sheet_path}")
            seen_sheet_paths.add(sheet_path)
            if sheet_path not in archive.names:
                raise IngestionError(f"XLSX worksheet member is missing: {sheet_path}")
            worksheet = archive.xml(sheet_path)
            cell_count = 0
            max_row = 0
            max_column = 0
            seen_coordinates: set[str] = set()
            for cell in worksheet.iter(f"{{{_NS_MAIN}}}c"):
                coordinate = cell.attrib.get("r", "").upper()
                column_letters, row_number, column_number = _validate_xlsx_coordinate(
                    coordinate
                )
                if coordinate in seen_coordinates:
                    raise IngestionError(
                        f"XLSX sheet {sheet_name!r} has duplicate cell coordinate {coordinate}"
                    )
                seen_coordinates.add(coordinate)
                value, text, formula = _xlsx_cell_value(cell, shared_strings)
                if len(text) > limits.max_cell_chars:
                    raise LimitExceededError(
                        f"XLSX cell {_sheet_locator(sheet_name, coordinate)} exceeds "
                        f"{limits.max_cell_chars} characters"
                    )
                locator = _sheet_locator(sheet_name, coordinate)
                if locator in seen_locators:
                    raise IngestionError(f"XLSX evidence locator is not unique: {locator}")
                seen_locators.add(locator)
                item = _base_evidence(
                    source_hash=source_hash,
                    kind="CELL",
                    locator=locator,
                    text=text,
                    sheet=sheet_name,
                    sheet_number=sheet_number,
                    cell=coordinate,
                    row=row_number,
                    column=column_number,
                )
                item["value"] = value
                if formula is not None:
                    item["formula"] = formula
                    item["formula_executed"] = False
                    item["value_is_cached"] = True
                evidence.append(item)
                cell_count += 1
                max_row = max(max_row, row_number)
                max_column = max(max_column, column_number)
                if len(evidence) > limits.max_evidence_items:
                    raise LimitExceededError(
                        f"evidence item count exceeds {limits.max_evidence_items}"
                    )
            sheets_summary.append(
                {
                    "name": sheet_name,
                    "sheet_number": sheet_number,
                    "cell_count": cell_count,
                    "max_row": max_row,
                    "max_column": max_column,
                }
            )

    _check_evidence_limits(evidence, limits)
    return {
        "evidence": evidence,
        "structure": {"format": "XLSX", "sheets": sheets_summary},
    }


def _xlsx_relationships(archive: "_SafeOOXML") -> dict[str, tuple[str, str]]:
    rel_path = "xl/_rels/workbook.xml.rels"
    if rel_path not in archive.names:
        raise IngestionError("XLSX is missing workbook relationships")
    root = archive.xml(rel_path)
    relationships: dict[str, tuple[str, str]] = {}
    for relationship in root.findall(f"{{{_NS_REL_PACKAGE}}}Relationship"):
        relationship_id = relationship.attrib.get("Id")
        target = relationship.attrib.get("Target")
        relationship_type = relationship.attrib.get("Type")
        if not relationship_id or not target or not relationship_type:
            raise IngestionError("XLSX workbook relationship is missing Id, Type, or Target")
        if relationship_id in relationships:
            raise IngestionError(f"XLSX has duplicate relationship Id: {relationship_id}")
        if relationship.attrib.get("TargetMode", "").lower() == "external":
            raise ArchiveSafetyError(
                f"external OOXML relationship is not accepted: {relationship_id}"
            )
        relationships[relationship_id] = (
            _resolve_archive_target("xl/workbook.xml", target),
            relationship_type,
        )
    return relationships


def _xlsx_shared_strings(
    archive: "_SafeOOXML", limits: IngestionLimits
) -> list[str]:
    if "xl/sharedStrings.xml" not in archive.names:
        return []
    root = archive.xml("xl/sharedStrings.xml")
    values: list[str] = []
    for item in root.findall(f"{{{_NS_MAIN}}}si"):
        value = "".join(node.text or "" for node in item.iter(f"{{{_NS_MAIN}}}t"))
        _validate_text_length(value, limits, "XLSX shared string")
        values.append(value)
        if len(values) > limits.max_evidence_items:
            raise LimitExceededError(
                f"XLSX shared string count exceeds {limits.max_evidence_items}"
            )
    return values


def _xlsx_cell_value(
    cell: ET.Element, shared_strings: list[str]
) -> tuple[Any, str, str | None]:
    cell_type = cell.attrib.get("t", "n")
    formula_node = cell.find(f"{{{_NS_MAIN}}}f")
    formula = formula_node.text or "" if formula_node is not None else None
    value_node = cell.find(f"{{{_NS_MAIN}}}v")
    raw_value = value_node.text or "" if value_node is not None else ""

    if cell_type == "inlineStr":
        text = "".join(node.text or "" for node in cell.iter(f"{{{_NS_MAIN}}}t"))
        value: Any = text
    elif cell_type == "s":
        try:
            index = int(raw_value)
            if index < 0:
                raise IndexError
            value = shared_strings[index]
        except (ValueError, IndexError) as error:
            raise IngestionError(f"XLSX shared-string index is invalid: {raw_value!r}") from error
        text = value
    elif cell_type == "b":
        if raw_value not in {"0", "1"}:
            raise IngestionError(f"XLSX boolean cell has invalid value: {raw_value!r}")
        value = raw_value == "1"
        text = "TRUE" if value else "FALSE"
    elif cell_type in {"str", "e", "d"}:
        value = raw_value
        text = raw_value
    else:
        value = _safe_number(raw_value)
        text = raw_value

    if formula is not None and not text:
        text = f"={formula}"
    return value, text, formula


def _safe_number(raw_value: str) -> int | float | str:
    if raw_value == "":
        return ""
    try:
        number = float(raw_value)
    except ValueError:
        return raw_value
    if not math.isfinite(number):
        return raw_value
    return int(number) if number.is_integer() else number


def _parse_docx(raw: bytes, source_hash: str, limits: IngestionLimits) -> dict[str, Any]:
    with _SafeOOXML(raw, limits, expected_format="DOCX") as archive:
        if "word/document.xml" not in archive.names:
            raise IngestionError("DOCX is missing word/document.xml")
        unsupported_parts = sorted(
            name
            for name in archive.names
            if name.startswith(
                (
                    "word/header",
                    "word/footer",
                    "word/footnotes",
                    "word/endnotes",
                    "word/comments",
                    "word/glossary/",
                )
            )
            and name.endswith(".xml")
        )
        if unsupported_parts:
            raise UnsupportedFormatError(
                "DOCX contains unsupported text-bearing parts: "
                + ", ".join(unsupported_parts)
            )
        document = archive.xml("word/document.xml")
        body = document.find(f"{{{_NS_WORD}}}body")
        if body is None:
            raise IngestionError("DOCX document has no body")

        evidence: list[dict[str, Any]] = []
        paragraph_number = 0
        table_number = 0
        table_summaries: list[dict[str, Any]] = []
        for child in _word_blocks(body):
            if child.tag == f"{{{_NS_WORD}}}p":
                paragraph_number += 1
                text = _word_text(child)
                _validate_text_length(text, limits, f"DOCX paragraph {paragraph_number}")
                evidence.append(
                    _base_evidence(
                        source_hash=source_hash,
                        kind="PARAGRAPH",
                        locator=f"DOCX#paragraph-{paragraph_number}",
                        text=text,
                        paragraph=paragraph_number,
                    )
                )
            elif child.tag == f"{{{_NS_WORD}}}tbl":
                table_number += 1
                if child.find(f".//{{{_NS_WORD}}}sdt") is not None:
                    raise UnsupportedFormatError(
                        "DOCX content controls inside tables require a reviewed locator mapping"
                    )
                row_count = 0
                max_columns = 0
                for row_number, row in enumerate(child.findall(f"{{{_NS_WORD}}}tr"), start=1):
                    row_count = row_number
                    cells = row.findall(f"{{{_NS_WORD}}}tc")
                    max_columns = max(max_columns, len(cells))
                    for column_number, cell in enumerate(cells, start=1):
                        if cell.find(f".//{{{_NS_WORD}}}tbl") is not None:
                            raise UnsupportedFormatError(
                                "DOCX nested tables are not supported without a reviewed locator mapping"
                            )
                        text = _word_text(cell)
                        _validate_text_length(
                            text,
                            limits,
                            f"DOCX table {table_number}, row {row_number}, cell {column_number}",
                        )
                        evidence.append(
                            _base_evidence(
                                source_hash=source_hash,
                                kind="TABLE_CELL",
                                locator=(
                                    f"DOCX#table-{table_number}.row-{row_number}.cell-"
                                    f"{_column_label(column_number)}"
                                ),
                                text=text,
                                table=table_number,
                                row=row_number,
                                column=column_number,
                                column_label=_column_label(column_number),
                            )
                        )
                table_summaries.append(
                    {
                        "table_number": table_number,
                        "row_count": row_count,
                        "column_count": max_columns,
                    }
                )
            if len(evidence) > limits.max_evidence_items:
                raise LimitExceededError(
                    f"evidence item count exceeds {limits.max_evidence_items}"
                )

        if not evidence or not any(item["text"].strip() for item in evidence):
            raise IngestionError("DOCX produced no supported, non-empty text evidence")

    _check_evidence_limits(evidence, limits)
    return {
        "evidence": evidence,
        "structure": {
            "format": "DOCX",
            "paragraph_count": paragraph_number,
            "tables": table_summaries,
            "page_coordinates_available": False,
        },
    }


def _word_text(element: ET.Element) -> str:
    tokens: list[str] = []
    for node in element.iter():
        if node.tag == f"{{{_NS_WORD}}}t":
            tokens.append(node.text or "")
        elif node.tag == f"{{{_NS_WORD}}}tab":
            tokens.append("\t")
        elif node.tag in {f"{{{_NS_WORD}}}br", f"{{{_NS_WORD}}}cr"}:
            tokens.append("\n")
    return "".join(tokens)


def _word_blocks(container: ET.Element) -> Iterable[ET.Element]:
    """Yield supported block content, expanding top-level content controls."""

    paragraph_tag = f"{{{_NS_WORD}}}p"
    table_tag = f"{{{_NS_WORD}}}tbl"
    content_control_tag = f"{{{_NS_WORD}}}sdt"
    content_tag = f"{{{_NS_WORD}}}sdtContent"
    section_tag = f"{{{_NS_WORD}}}sectPr"
    for child in container:
        if child.tag in {paragraph_tag, table_tag}:
            yield child
        elif child.tag == content_control_tag:
            content = child.find(content_tag)
            if content is None:
                raise UnsupportedFormatError("DOCX content control has no sdtContent")
            yield from _word_blocks(content)
        elif child.tag == section_tag:
            continue
        else:
            raise UnsupportedFormatError(
                f"DOCX body contains unsupported block element: {child.tag}"
            )


def _parse_pdf(
    raw: bytes,
    source_hash: str,
    limits: IngestionLimits,
    extractor: PdfPageExtractor | None,
    *,
    trusted_pdf_adapter: bool,
) -> dict[str, Any]:
    if extractor is None:
        raise UnsupportedFormatError(
            "PDF text extraction requires an explicit pdf_page_extractor; "
            "the standard library cannot provide reliable page text"
        )
    if trusted_pdf_adapter is not True:
        raise UnsupportedFormatError(
            "PDF adapter use is disabled by default; set trusted_pdf_adapter=true only "
            "for a reviewed, sandboxed adapter with independent structural safety checks"
        )

    declared_names = _pdf_declared_names(raw)
    forbidden = sorted(declared_names & _PDF_FORBIDDEN_NAMES)
    if forbidden:
        names = ", ".join(name.decode("ascii", errors="replace") for name in forbidden)
        raise UnsupportedFormatError(
            f"PDF contains encrypted, active, embedded, or opaque object features: {names}"
        )

    try:
        pages = extractor(raw)
    except Exception as error:  # adapter errors are converted into an ingestion boundary error
        raise IngestionError(f"PDF page extractor failed: {error}") from error
    if isinstance(pages, (str, bytes, dict)) or pages is None:
        raise IngestionError("PDF page extractor must yield one string per physical page")

    evidence: list[dict[str, Any]] = []
    extractable_pages = 0
    try:
        for page_number, text in enumerate(pages, start=1):
            if page_number > limits.max_pdf_pages:
                raise LimitExceededError(f"PDF page count exceeds {limits.max_pdf_pages}")
            if not isinstance(text, str):
                raise IngestionError(
                    f"PDF page extractor returned {type(text).__name__} for page {page_number}; "
                    "expected str"
                )
            if len(text) > limits.max_text_chars:
                raise LimitExceededError(
                    f"PDF page {page_number} exceeds {limits.max_text_chars} characters"
                )
            if text.strip():
                extractable_pages += 1
            item = _base_evidence(
                source_hash=source_hash,
                kind="PAGE",
                locator=f"PDF#page-{page_number}",
                text=text,
                page=page_number,
            )
            item["extractable_text"] = bool(text.strip())
            evidence.append(item)
    except (IngestionError, LimitExceededError):
        raise
    except Exception as error:
        raise IngestionError(f"PDF page extractor iteration failed: {error}") from error

    if not evidence or extractable_pages == 0:
        raise ScannedPdfError(
            "PDF has no extractable text; scanned/image-only files require a reviewed OCR adapter"
        )
    _check_evidence_limits(evidence, limits)
    return {
        "evidence": evidence,
        "structure": {
            "format": "PDF",
            "page_count": len(evidence),
            "extractable_page_count": extractable_pages,
            "adapter_required": True,
        },
    }


def _pdf_declared_names(raw: bytes) -> set[bytes]:
    """Decode visible PDF name tokens for conservative pre-adapter rejection.

    This intentionally does not claim to parse the PDF object graph.  Opaque
    object streams are rejected, and the trusted adapter remains responsible
    for independent structural validation inside its sandbox.
    """

    names: set[bytes] = set()
    for match in _PDF_NAME.finditer(raw):
        token = match.group()[1:]
        decoded = re.sub(
            rb"#([0-9A-Fa-f]{2})",
            lambda encoded: bytes([int(encoded.group(1), 16)]),
            token,
        )
        names.add(decoded.lower())
    return names


class _SafeOOXML:
    """Context manager that validates an OOXML ZIP before exposing members."""

    def __init__(
        self, raw: bytes, limits: IngestionLimits, *, expected_format: str
    ):
        self._buffer = io.BytesIO(raw)
        _preflight_zip_directory(raw, limits.max_archive_members)
        try:
            self._archive = zipfile.ZipFile(self._buffer, "r")
        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
            self._buffer.close()
            raise ArchiveSafetyError(f"invalid OOXML ZIP container: {error}") from error
        self._limits = limits
        if expected_format not in _MAIN_CONTENT_TYPES:
            raise ValueError(f"unsupported OOXML expected_format: {expected_format}")
        self._expected_format = expected_format
        self.names: frozenset[str] = frozenset()

    def __enter__(self) -> "_SafeOOXML":
        try:
            self.names = self._validate_archive()
            self._validate_content_types()
            self._validate_relationships()
        except Exception:
            self._archive.close()
            self._buffer.close()
            raise
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self._archive.close()
        self._buffer.close()

    def _validate_archive(self) -> frozenset[str]:
        infos = self._archive.infolist()
        if len(infos) > self._limits.max_archive_members:
            raise ArchiveSafetyError(
                f"archive member count exceeds {self._limits.max_archive_members}"
            )
        total_uncompressed = 0
        total_compressed = 0
        normalized_names: set[str] = set()
        casefold_names: set[str] = set()
        for info in infos:
            normalized = _normalize_member_name(info.filename)
            key = normalized.casefold()
            if normalized in normalized_names or key in casefold_names:
                raise ArchiveSafetyError(f"archive has duplicate/colliding member: {normalized}")
            normalized_names.add(normalized)
            casefold_names.add(key)
            if info.flag_bits & 0x1:
                raise ArchiveSafetyError(f"encrypted archive member is not accepted: {normalized}")
            mode = (info.external_attr >> 16) & 0xFFFF
            if mode and stat.S_ISLNK(mode):
                raise ArchiveSafetyError(f"archive symlink is not accepted: {normalized}")
            if info.file_size > self._limits.max_archive_member_bytes:
                raise ArchiveSafetyError(
                    f"archive member {normalized} exceeds "
                    f"{self._limits.max_archive_member_bytes} bytes"
                )
            total_uncompressed += info.file_size
            total_compressed += info.compress_size
            if total_uncompressed > self._limits.max_archive_uncompressed_bytes:
                raise ArchiveSafetyError(
                    "archive uncompressed size exceeds "
                    f"{self._limits.max_archive_uncompressed_bytes} bytes"
                )
            ratio = info.file_size / max(info.compress_size, 1)
            if ratio > self._limits.max_compression_ratio:
                raise ArchiveSafetyError(
                    f"archive member {normalized} compression ratio {ratio:.1f} exceeds "
                    f"{self._limits.max_compression_ratio:.1f}"
                )
            lowered = normalized.casefold()
            if (
                lowered.endswith("vbaproject.bin")
                or lowered.endswith(".bin")
                or "/activex/" in f"/{lowered}/"
                or "/embeddings/" in f"/{lowered}/"
                or lowered.endswith(".xlam")
            ):
                raise ArchiveSafetyError(
                    f"macro, ActiveX, or embedded-object content is not accepted: {normalized}"
                )
        total_ratio = total_uncompressed / max(total_compressed, 1)
        if total_ratio > self._limits.max_compression_ratio:
            raise ArchiveSafetyError(
                f"archive compression ratio {total_ratio:.1f} exceeds "
                f"{self._limits.max_compression_ratio:.1f}"
            )
        return frozenset(normalized_names)

    def _validate_content_types(self) -> None:
        content_types_name = "[Content_Types].xml"
        if content_types_name not in self.names:
            raise IngestionError("OOXML container is missing [Content_Types].xml")
        root = self.xml(content_types_name)
        expected_part, expected_type = _MAIN_CONTENT_TYPES[self._expected_format]
        declared_main_type: str | None = None
        for element in root:
            content_type = element.attrib.get("ContentType", "")
            lowered_type = content_type.casefold()
            if any(
                marker in lowered_type for marker in _DANGEROUS_CONTENT_TYPE_MARKERS
            ):
                raise ArchiveSafetyError(
                    "OOXML content types declare macro, ActiveX, executable, or "
                    "embedded-object content"
                )
            if element.tag == f"{{{_CONTENT_TYPES_NS}}}Override":
                part_name = element.attrib.get("PartName", "").lstrip("/")
                if part_name == expected_part:
                    declared_main_type = content_type
        if declared_main_type != expected_type:
            raise UnsupportedFormatError(
                f"{self._expected_format} main part must declare {expected_type!r}; "
                f"found {declared_main_type!r}"
            )

    def _validate_relationships(self) -> None:
        for name in sorted(member for member in self.names if member.endswith(".rels")):
            root = self.xml(name)
            if root.tag != f"{{{_NS_REL_PACKAGE}}}Relationships":
                raise IngestionError(f"OOXML relationship part has invalid root: {name}")
            seen_ids: set[str] = set()
            relationships = root.findall(f"{{{_NS_REL_PACKAGE}}}Relationship")
            if len(relationships) != len(root):
                raise IngestionError(
                    f"OOXML relationship part contains unsupported elements: {name}"
                )
            for relationship in relationships:
                relationship_id = relationship.attrib.get("Id")
                relationship_type = relationship.attrib.get("Type")
                target = relationship.attrib.get("Target")
                if not relationship_id or not relationship_type or not target:
                    raise IngestionError(
                        f"OOXML relationship in {name} is missing Id, Type, or Target"
                    )
                if relationship_id in seen_ids:
                    raise IngestionError(
                        f"OOXML relationship file {name} has duplicate Id {relationship_id!r}"
                    )
                seen_ids.add(relationship_id)
                if relationship.attrib.get("TargetMode", "").casefold() == "external":
                    raise ArchiveSafetyError(
                        f"external OOXML relationship is not accepted: {name}#{relationship_id}"
                    )
                kind = _relationship_kind(relationship_type)
                if kind not in _ALLOWED_RELATIONSHIP_KINDS:
                    raise ArchiveSafetyError(
                        f"OOXML relationship type is not allowlisted: {relationship_type}"
                    )
                source_member = _relationship_source_member(name)
                resolved_target = _resolve_archive_target(source_member, target)
                if resolved_target not in self.names:
                    raise IngestionError(
                        f"OOXML relationship target is missing: {name}#{relationship_id} "
                        f"-> {resolved_target}"
                    )

    def read(self, name: str) -> bytes:
        normalized = _normalize_member_name(name)
        if normalized not in self.names:
            raise IngestionError(f"archive member is missing: {normalized}")
        try:
            return self._archive.read(normalized)
        except (KeyError, RuntimeError, zipfile.BadZipFile) as error:
            raise IngestionError(f"cannot read archive member {normalized}: {error}") from error

    def xml(self, name: str) -> ET.Element:
        payload = self.read(name)
        if payload.startswith(_NON_UTF8_XML_BOMS):
            raise ArchiveSafetyError(
                f"OOXML XML parts must use UTF-8 or UTF-8-BOM: {name}"
            )
        try:
            text = payload.decode("utf-8-sig", errors="strict")
        except UnicodeDecodeError as error:
            raise ArchiveSafetyError(
                f"OOXML XML parts must use UTF-8 or UTF-8-BOM: {name}"
            ) from error
        if "\x00" in text:
            raise ArchiveSafetyError(
                f"OOXML XML parts must use UTF-8 or UTF-8-BOM: {name}"
            )
        declaration = _XML_DECLARATION_ENCODING.search(text)
        if declaration is not None and declaration.group(1).casefold() != "utf-8":
            raise ArchiveSafetyError(
                f"OOXML XML encoding declaration must be UTF-8: {name}"
            )
        upper = text.upper()
        if any(marker in upper for marker in _XML_DANGER_MARKERS):
            raise ArchiveSafetyError(f"DTD/entity declarations are not accepted in {name}")
        try:
            return ET.fromstring(text)
        except ET.ParseError as error:
            raise IngestionError(f"malformed XML in {name}: {error}") from error


def _normalize_member_name(name: str) -> str:
    if not name or "\x00" in name:
        raise ArchiveSafetyError("archive member has an empty or NUL-containing name")
    replaced = name.replace("\\", "/")
    if replaced.startswith("/") or re.match(r"^[A-Za-z]:", replaced):
        raise ArchiveSafetyError(f"archive member has an absolute path: {name}")
    raw_parts = PurePosixPath(replaced).parts
    if ".." in raw_parts:
        raise ArchiveSafetyError(f"archive member contains path traversal: {name}")
    normalized = posixpath.normpath(replaced)
    parts = PurePosixPath(normalized).parts
    if normalized in {".", ".."} or ".." in parts:
        raise ArchiveSafetyError(f"archive member escapes its container: {name}")
    return normalized.rstrip("/") if normalized.endswith("/") else normalized


def _preflight_zip_directory(raw: bytes, max_members: int) -> None:
    """Bound central-directory entries before ZipFile allocates ZipInfo objects."""

    signature = b"PK\x05\x06"
    search_start = max(0, len(raw) - (65_535 + 22))
    eocd_offset = raw.rfind(signature, search_start)
    if eocd_offset < 0 or eocd_offset + 22 > len(raw):
        raise ArchiveSafetyError("ZIP end-of-central-directory record is missing")

    disk_number = int.from_bytes(raw[eocd_offset + 4:eocd_offset + 6], "little")
    central_disk = int.from_bytes(raw[eocd_offset + 6:eocd_offset + 8], "little")
    disk_entries = int.from_bytes(raw[eocd_offset + 8:eocd_offset + 10], "little")
    total_entries = int.from_bytes(raw[eocd_offset + 10:eocd_offset + 12], "little")
    central_size = int.from_bytes(raw[eocd_offset + 12:eocd_offset + 16], "little")
    central_offset = int.from_bytes(raw[eocd_offset + 16:eocd_offset + 20], "little")
    comment_size = int.from_bytes(raw[eocd_offset + 20:eocd_offset + 22], "little")

    if disk_number != 0 or central_disk != 0 or disk_entries != total_entries:
        raise ArchiveSafetyError("multi-disk ZIP containers are not accepted")
    if total_entries == 0xFFFF or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
        raise ArchiveSafetyError("ZIP64 OOXML containers are not accepted by this prototype")
    if eocd_offset + 22 + comment_size != len(raw):
        raise ArchiveSafetyError("ZIP has trailing data or an inconsistent comment length")
    if total_entries > max_members:
        raise ArchiveSafetyError(f"archive member count exceeds {max_members}")

    central_end = central_offset + central_size
    if central_offset < 0 or central_end != eocd_offset or central_end > len(raw):
        raise ArchiveSafetyError("ZIP central-directory bounds are inconsistent")

    cursor = central_offset
    observed_entries = 0
    while cursor < central_end:
        if cursor + 46 > central_end or raw[cursor:cursor + 4] != b"PK\x01\x02":
            raise ArchiveSafetyError("ZIP central-directory entry is malformed")
        name_size = int.from_bytes(raw[cursor + 28:cursor + 30], "little")
        extra_size = int.from_bytes(raw[cursor + 30:cursor + 32], "little")
        entry_comment_size = int.from_bytes(raw[cursor + 32:cursor + 34], "little")
        cursor += 46 + name_size + extra_size + entry_comment_size
        observed_entries += 1
        if observed_entries > max_members:
            raise ArchiveSafetyError(f"archive member count exceeds {max_members}")
    if cursor != central_end or observed_entries != total_entries:
        raise ArchiveSafetyError("ZIP central-directory member count is inconsistent")


def _resolve_archive_target(base_member: str, target: str) -> str:
    target = target.replace("\\", "/")
    if target.startswith("/"):
        candidate = target.lstrip("/")
    else:
        candidate = posixpath.join(posixpath.dirname(base_member), target)
    return _normalize_member_name(candidate)


def _relationship_source_member(relationship_member: str) -> str:
    if relationship_member == "_rels/.rels":
        return ""
    directory = posixpath.dirname(relationship_member)
    if posixpath.basename(directory) != "_rels" or not relationship_member.endswith(".rels"):
        raise ArchiveSafetyError(
            f"relationship part has an invalid package location: {relationship_member}"
        )
    source_directory = posixpath.dirname(directory)
    source_name = posixpath.basename(relationship_member)[:-5]
    if not source_name:
        raise ArchiveSafetyError(
            f"relationship part has no source member: {relationship_member}"
        )
    return posixpath.join(source_directory, source_name)


def _relationship_kind(relationship_type: str) -> str:
    for prefix in _RELATIONSHIP_PREFIXES:
        if relationship_type.startswith(prefix):
            kind = relationship_type[len(prefix):]
            if kind == "metadata/core-properties":
                return "core-properties"
            if kind and "/" not in kind:
                return kind
    raise ArchiveSafetyError(
        f"OOXML relationship namespace is not allowlisted: {relationship_type}"
    )


def _validate_sheet_name(sheet_name: str) -> None:
    if not sheet_name or len(sheet_name) > 31:
        raise IngestionError("XLSX sheet name must contain 1 to 31 characters")
    if _CONTROL_CHARS.search(sheet_name) or any(char in sheet_name for char in "[]:*?/\\"):
        raise IngestionError(f"XLSX sheet name contains invalid characters: {sheet_name!r}")
    if sheet_name.startswith("'") or sheet_name.endswith("'"):
        raise IngestionError(f"XLSX sheet name has invalid apostrophe placement: {sheet_name!r}")


def _validate_xlsx_coordinate(coordinate: str) -> tuple[str, int, int]:
    if not _XLSX_CELL.fullmatch(coordinate):
        raise IngestionError(f"XLSX cell has invalid coordinate: {coordinate!r}")
    column_letters, row_number = _split_cell_coordinate(coordinate)
    if len(column_letters) > 3:
        raise IngestionError(f"XLSX cell is outside Excel column bounds: {coordinate}")
    column_number = _column_number(column_letters)
    if row_number > _XLSX_MAX_ROW or column_number > _XLSX_MAX_COLUMN:
        raise IngestionError(f"XLSX cell is outside Excel bounds: {coordinate}")
    return column_letters, row_number, column_number


def _sheet_locator(sheet_name: str, cell: str) -> str:
    if _SIMPLE_SHEET_NAME.fullmatch(sheet_name):
        return f"{sheet_name}!{cell}"
    escaped = sheet_name.replace("'", "''")
    return f"'{escaped}'!{cell}"


def _split_cell_coordinate(coordinate: str) -> tuple[str, int]:
    split = next(index for index, char in enumerate(coordinate) if char.isdigit())
    return coordinate[:split], int(coordinate[split:])


def _column_label(column_number: int) -> str:
    if column_number <= 0:
        raise ValueError("column_number must be positive")
    letters: list[str] = []
    value = column_number
    while value:
        value, remainder = divmod(value - 1, 26)
        letters.append(chr(65 + remainder))
    return "".join(reversed(letters))


def _column_number(column_letters: str) -> int:
    value = 0
    for letter in column_letters.upper():
        value = value * 26 + (ord(letter) - 64)
    return value


def _validate_text_length(text: str, limits: IngestionLimits, description: str) -> None:
    if len(text) > limits.max_cell_chars:
        raise LimitExceededError(
            f"{description} exceeds {limits.max_cell_chars} characters"
        )


__all__ = [
    "ArchiveSafetyError",
    "DEFAULT_LIMITS",
    "IngestionError",
    "IngestionLimits",
    "LimitExceededError",
    "PdfPageExtractor",
    "ScannedPdfError",
    "UnsafePathError",
    "UnsupportedFormatError",
    "ingest_document",
]
