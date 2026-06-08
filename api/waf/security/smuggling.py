"""HTTP Request Smuggling Detection.

Detects CL.TE, TE.CL, and TE.TE smuggling vectors by checking for
conflicting or malformed Content-Length and Transfer-Encoding headers.
"""

_VALID_TE_VALUES = frozenset({"chunked", "identity", "gzip", "deflate", "compress"})


def _is_te_obfuscated(key: str, value: str) -> bool:
    """Check if a Transfer-Encoding header uses obfuscation to bypass parsers."""
    val_stripped = value.strip().lower()
    if val_stripped in _VALID_TE_VALUES:
        return False
    return "chunked" in val_stripped


def check_smuggling_headers(headers: dict, raw_headers: list[tuple[str, str]] | None = None) -> dict:
    """Check a request's headers for HTTP smuggling indicators.

    Accepts a dict (duplicate keys lost) and optionally a raw list of
    ``(key, value)`` tuples for accurate duplicate detection.

    Returns a dict with keys:
      - ``smuggling_detected`` (bool)
      - ``vector`` (str or None) — e.g. "CL.TE", "TE.CL", "TE.TE"
      - ``detail`` (str)
    """
    result = {"smuggling_detected": False, "vector": None, "detail": ""}

    # Use raw headers for duplicate-aware detection
    source = raw_headers if raw_headers else list(headers.items())

    content_lengths: list[int] = []
    transfer_encoding_keys: list[str] = []

    for raw_key, value in source:
        key_lower = raw_key.lower().strip()

        if key_lower == "content-length":
            try:
                content_lengths.append(int(value.strip()))
            except (ValueError, AttributeError):
                result["smuggling_detected"] = True
                result["vector"] = "CL.TE"
                result["detail"] = f"Invalid Content-Length value: {value!r}"
                return result

        if "transfer-encoding" in key_lower:
            transfer_encoding_keys.append(raw_key)
            if _is_te_obfuscated(raw_key, value):
                result["smuggling_detected"] = True
                result["vector"] = "TE.TE"
                result["detail"] = f"Obfuscated Transfer-Encoding: {raw_key}: {value}"
                return result

    # Multiple Content-Length headers → ambiguous
    if len(content_lengths) > 1 and len(set(content_lengths)) > 1:
        result["smuggling_detected"] = True
        result["vector"] = "CL.TE"
        result["detail"] = f"Conflicting Content-Length values: {content_lengths}"
        return result

    # CL + TE → smuggling possible
    if content_lengths and transfer_encoding_keys:
        result["smuggling_detected"] = True
        result["vector"] = "CL.TE"
        result["detail"] = "Both Content-Length and Transfer-Encoding headers present"
        return result

    # Multiple TE headers → TE.TE vector
    if len(transfer_encoding_keys) > 1:
        result["smuggling_detected"] = True
        result["vector"] = "TE.TE"
        result["detail"] = f"Multiple Transfer-Encoding headers: {transfer_encoding_keys}"
        return result

    return result
