import re
from typing import Any

DLP_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "dlp-cc-visa",
        "name": "Credit Card (Visa)",
        "severity": "critical",
        "pattern": re.compile(r"\b4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b"),
    },
    {
        "id": "dlp-cc-mastercard",
        "name": "Credit Card (MasterCard)",
        "severity": "critical",
        "pattern": re.compile(r"\b5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b"),
    },
    {
        "id": "dlp-cc-amex",
        "name": "Credit Card (Amex)",
        "severity": "critical",
        "pattern": re.compile(r"\b3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}\b"),
    },
    {
        "id": "dlp-ssn",
        "name": "US Social Security Number",
        "severity": "critical",
        "pattern": re.compile(r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"),
    },
    {
        "id": "dlp-aws-access-key",
        "name": "AWS Access Key ID",
        "severity": "high",
        "pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    },
    {
        "id": "dlp-aws-secret-key",
        "name": "AWS Secret Access Key",
        "severity": "critical",
        "pattern": re.compile(
            r"(?i)(?:aws_secret_access_key|aws secret access key)[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"
        ),
    },
    {
        "id": "dlp-pem-key",
        "name": "PEM Private Key",
        "severity": "critical",
        "pattern": re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
    },
    {
        "id": "dlp-ssh-key",
        "name": "SSH Private Key",
        "severity": "critical",
        "pattern": re.compile(r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----"),
    },
    {
        "id": "dlp-github-token",
        "name": "GitHub Personal Access Token",
        "severity": "high",
        "pattern": re.compile(r"\bghp_[0-9a-zA-Z]{36}\b"),
    },
    {
        "id": "dlp-generic-api-key",
        "name": "Generic API Key (high entropy)",
        "severity": "medium",
        "pattern": re.compile(
            r"(?i)(?:api[_-]?key|apikey|api_secret|api[_-]?token)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?"
        ),
    },
    {
        "id": "dlp-jwt",
        "name": "JWT Token",
        "severity": "medium",
        "pattern": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    },
]

_MAX_SCAN_BYTES = 1 * 1024 * 1024  # 1 MB max scan size


def scan_for_dlp(body: bytes) -> list[dict[str, Any]]:
    """Scan response body bytes for all DLP patterns.

    Returns list of matched DLP findings (deduplicated by pattern id).
    """
    if len(body) > _MAX_SCAN_BYTES:
        body = body[:_MAX_SCAN_BYTES]

    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        return []

    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for rule in DLP_PATTERNS:
        if rule["id"] in seen:
            continue
        try:
            if rule["pattern"].search(text):
                findings.append(
                    {
                        "dlp_id": rule["id"],
                        "name": rule["name"],
                        "severity": rule["severity"],
                    }
                )
                seen.add(rule["id"])
        except Exception:
            continue

    return findings
