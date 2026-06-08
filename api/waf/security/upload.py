"""File-upload inspection using content-type matching and magic-byte signatures.

Falls back to a hardcoded magic-byte database when python-magic is unavailable.
"""

# Hardcoded magic bytes for common file types
MAGIC_SIGNATURES: list[tuple[str, bytes, int, str]] = [
    ("elf", b"\x7fELF", 0, "application/x-executable"),
    ("pe", b"MZ", 0, "application/x-dosexec"),
    ("macho", b"\xfe\xed\xfa\xce", 0, "application/x-mach-binary"),
    ("macho64", b"\xfe\xed\xfa\xcf", 0, "application/x-mach-binary"),
    ("macho_be", b"\xce\xfa\xed\xfe", 0, "application/x-mach-binary"),
    ("macho_be64", b"\xcf\xfa\xed\xfe", 0, "application/x-mach-binary"),
    ("gzip", b"\x1f\x8b\x08", 0, "application/gzip"),
    ("zip", b"PK\x03\x04", 0, "application/zip"),
    ("jar", b"PK\x03\x04", 0, "application/java-archive"),
    ("rar", b"Rar!\x1a\x07", 0, "application/vnd.rar"),
    ("7z", b"7z\xbc\xaf\x27\x1c", 0, "application/x-7z-compressed"),
    ("pdf", b"%PDF", 0, "application/pdf"),
    ("png", b"\x89PNG\r\n\x1a\n", 0, "image/png"),
    ("jpg", b"\xff\xd8\xff", 0, "image/jpeg"),
    ("gif", b"GIF8", 0, "image/gif"),
    ("webp", b"RIFF", 0, "image/webp"),
    ("mp3", b"\xff\xfb", 0, "audio/mpeg"),
    ("mp4", b"\x00\x00\x00\x1c\x66\x74\x79\x70", 4, "video/mp4"),
    ("avi", b"RIFF", 0, "video/x-msvideo"),
    ("bmp", b"BM", 0, "image/bmp"),
    ("svg", b"<svg", 0, "image/svg+xml"),
    ("xml", b"<?xml", 0, "application/xml"),
    ("html", b"<html", 0, "text/html"),
    ("html5", b"<!DOCTYPE html", 0, "text/html"),
    ("php", b"<?php", 0, "application/x-php"),
    ("pyc", b"\x6f\x0c\x0d\x0a", 0, "application/x-python-bytecode"),
]

# Executable/binary MIME types that should be flagged in uploads
SUSPICIOUS_MIME_SUBSTRINGS = [
    "x-executable",
    "x-dosexec",
    "x-mach-binary",
    "x-python-bytecode",
    "x-msdownload",
    "x-sharedlib",
    "x-object",
    "java-archive",
]

# Dangerous extensions
DANGEROUS_EXTENSIONS = frozenset(
    {
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".elf",
        ".bin",
        ".sh",
        ".bash",
        ".cmd",
        ".bat",
        ".ps1",
        ".vbs",
        ".jar",
        ".class",
        ".pyc",
        ".pyd",
        ".scr",
        ".cpl",
        ".msi",
        ".msp",
        ".com",
    }
)


def _check_magic_bytes(data: bytes) -> str | None:
    """Return MIME type string if magic bytes match, else None."""
    for _name, sig, offset, mime in MAGIC_SIGNATURES:
        if len(data) >= offset + len(sig) and data[offset : offset + len(sig)] == sig:
            return mime
    return None


def _get_ext(filename: str) -> str:
    if "." not in (filename or ""):
        return ""
    _, dot_ext = filename.rsplit(".", 1)
    return f".{dot_ext.lower()}"


def inspect_upload(filename: str, content_type: str, data: bytes) -> dict:
    """Inspect an uploaded file for suspicious content.

    Returns a dict with:
      - ``safe`` (bool) — True if upload appears legitimate
      - ``detected_mime`` (str or None) — MIME type from magic bytes
      - ``reason`` (str) — explanation if unsafe
    """
    result = {"safe": True, "detected_mime": None, "reason": ""}

    if not data:
        return result

    ext = _get_ext(filename)

    # Check by extension
    if ext in DANGEROUS_EXTENSIONS:
        result["safe"] = False
        result["reason"] = f"Dangerous file extension: {ext}"
        return result

    # Check magic bytes
    detected_mime = _check_magic_bytes(data)
    result["detected_mime"] = detected_mime

    if detected_mime:
        # Check if detected MIME is executable
        for sus in SUSPICIOUS_MIME_SUBSTRINGS:
            if sus in detected_mime:
                result["safe"] = False
                result["reason"] = f"Executable content detected: {detected_mime}"
                return result

    # Check content-type mismatch (claimed vs actual)
    if detected_mime and content_type and "multipart" not in content_type:
        claimed_base = content_type.split(";")[0].strip()
        detected_base = detected_mime.split(";")[0].strip()
        if claimed_base != detected_base and claimed_base not in detected_base:
            result["safe"] = False
            result["reason"] = f"MIME mismatch: declared '{claimed_base}', detected '{detected_base}'"
            return result

    # Check for null bytes (exploit indicator)
    if b"\x00" in data[:1024]:
        result["safe"] = False
        result["reason"] = "Null bytes detected in file header"
        return result

    return result
