"""
scanner/heuristics.py — Shannon Entropy Heuristic Analyzer

When a file's hash does NOT match any known signature, this module
provides a second layer of defense by calculating the file's
Shannon entropy — a measure of randomness / information density.

Why Entropy Matters in Cybersecurity (2026)
-------------------------------------------
- Legitimate text files, source code, and documents typically have
  entropy between 3.0 and 5.5 bits per byte.
- Encrypted payloads, packed executables (UPX, Themida), and
  obfuscated shellcode approach the theoretical maximum of 8.0 bits
  per byte because encryption/compression removes all patterns.
- Modern malware authors routinely pack their payloads to evade
  signature scanners. Entropy analysis catches what signatures miss.

Threshold Rationale
-------------------
- < 6.0  → Almost certainly benign (text, code, configs).
- 6.0–7.5 → Compressed but likely legitimate (ZIP, JPEG, MP4).
- > 7.5  → Suspiciously high — potential packed/encrypted malware.

Author : Maniya Jay Maheshbhai (24DCS050)
Project: CwX Antivirus Simulation — DEPSTAR
"""

import math
from collections import Counter
from typing import Optional

from utils.logger import log_event


# ── Constants ────────────────────────────────────────────────────
ENTROPY_THRESHOLD = 7.5  # Bits per byte — flags packed/encrypted files
READ_LIMIT = 10 * 1024 * 1024  # 10 MiB cap to avoid RAM exhaustion


def calculate_entropy(filepath: str) -> Optional[float]:
    """
    Calculate the Shannon entropy of a file's byte distribution.

    Shannon entropy formula:
        H = -Σ p(x) * log₂(p(x))  for each byte value x ∈ [0, 255]

    Where p(x) is the probability of byte value x appearing in the file.

    Parameters
    ----------
    filepath : str
        Absolute or relative path to the file to analyze.

    Returns
    -------
    float or None
        Entropy value in bits per byte [0.0, 8.0], or None on error.
    """
    try:
        with open(filepath, "rb") as f:
            data = f.read(READ_LIMIT)
    except (PermissionError, OSError) as exc:
        log_event(
            "HEURISTIC_READ_ERROR",
            f"Cannot read file for entropy analysis: {exc}",
            severity="MEDIUM",
            metadata={"file": filepath},
        )
        return None

    if not data:
        # Empty files have zero entropy — no information content
        return 0.0

    # Count occurrences of each byte value (0x00 through 0xFF)
    byte_counts = Counter(data)
    total_bytes = len(data)

    # Apply the Shannon entropy formula
    entropy = 0.0
    for count in byte_counts.values():
        probability = count / total_bytes
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def analyze_file(filepath: str) -> dict:
    """
    Perform full heuristic analysis on a single file.

    Returns a result dictionary with the entropy value,
    whether the file is flagged as suspicious, and a
    human-readable verdict.

    Returns
    -------
    dict
        Keys: "entropy", "suspicious", "verdict"
    """
    entropy = calculate_entropy(filepath)

    if entropy is None:
        return {
            "entropy": None,
            "suspicious": False,
            "verdict": "UNREADABLE — skipped heuristic analysis",
        }

    suspicious = entropy > ENTROPY_THRESHOLD

    if suspicious:
        verdict = (
            f"HIGH ENTROPY ({entropy:.4f} bits/byte) — "
            f"Possible packed/encrypted payload detected"
        )
        log_event(
            "HEURISTIC_FLAG",
            verdict,
            severity="HIGH",
            metadata={
                "file": filepath,
                "entropy": entropy,
                "threshold": ENTROPY_THRESHOLD,
            },
        )
    elif entropy > 6.0:
        verdict = (
            f"MODERATE ENTROPY ({entropy:.4f} bits/byte) — "
            f"Likely compressed archive or media file"
        )
    else:
        verdict = f"NORMAL ENTROPY ({entropy:.4f} bits/byte) — Benign"

    return {
        "entropy": entropy,
        "suspicious": suspicious,
        "verdict": verdict,
    }
