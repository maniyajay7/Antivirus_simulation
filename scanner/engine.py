"""
scanner/engine.py — SHA-256 Signature Scanning Engine

Core detection module that reads files in safe binary chunks,
computes their SHA-256 cryptographic digest, and compares the
result against a loaded database of known malware signatures.

Security Design Notes
---------------------
- Files are read in 8 KiB chunks to prevent memory exhaustion on
  large binaries (defense against zip-bomb style DoS).
- All file I/O is wrapped in exception handlers to tolerate
  permission errors and locked files gracefully.
- The signature database uses SHA-256 (256-bit, collision-resistant)
  which remains unbroken as of 2026.

Author : Maniya Jay Maheshbhai (24DCS050)
Project: CwX Antivirus Simulation — DEPSTAR
"""

import hashlib
import json
import os
import shutil
from typing import Optional

from utils.logger import log_event


# ── Constants ────────────────────────────────────────────────────
CHUNK_SIZE = 8192  # 8 KiB — balance between speed and memory safety
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
SIGNATURE_DB = os.path.join(BASE_DIR, "database", "signatures.json")
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")


# ── Signature Database ───────────────────────────────────────────

def load_signatures() -> dict:
    """
    Load the malware signature database from disk.

    Returns a dict mapping SHA-256 hex digests to threat metadata.
    Returns an empty dict (fail-open) if the file is missing or corrupt,
    but logs the failure for SOC review.
    """
    if not os.path.exists(SIGNATURE_DB):
        log_event(
            "DB_MISSING",
            f"Signature database not found at {SIGNATURE_DB}",
            severity="HIGH",
        )
        return {}
    try:
        with open(SIGNATURE_DB, "r", encoding="utf-8") as f:
            data = json.load(f)
        log_event(
            "DB_LOADED",
            f"Loaded {len(data)} signatures from database.",
            severity="INFO",
            metadata={"path": SIGNATURE_DB, "count": len(data)},
        )
        return data
    except (json.JSONDecodeError, IOError) as exc:
        log_event(
            "DB_ERROR",
            f"Failed to parse signature database: {exc}",
            severity="CRITICAL",
        )
        return {}


# ── Hashing ──────────────────────────────────────────────────────

def calculate_sha256(filepath: str) -> Optional[str]:
    """
    Compute the SHA-256 digest of a file using chunked binary reads.

    This approach is memory-safe: even a 10 GB ISO will consume
    only ~8 KiB of RAM at any point during hashing.

    Returns
    -------
    str or None
        Hex digest string, or None if the file could not be read.
    """
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()
    except PermissionError:
        log_event(
            "ACCESS_DENIED",
            f"Permission denied reading {filepath}",
            severity="MEDIUM",
            metadata={"file": filepath},
        )
        return None
    except OSError as exc:
        log_event(
            "READ_ERROR",
            f"OS error reading {filepath}: {exc}",
            severity="MEDIUM",
            metadata={"file": filepath, "error": str(exc)},
        )
        return None


# ── Quarantine ───────────────────────────────────────────────────

def quarantine_file(filepath: str) -> bool:
    """
    Move a confirmed malicious file to the quarantine directory.

    The quarantine folder acts as a restricted holding zone,
    isolating threats from the live filesystem to prevent execution.

    Returns True on success, False on failure.
    """
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    filename = os.path.basename(filepath)
    dest = os.path.join(QUARANTINE_DIR, filename)

    # Avoid overwriting a previously quarantined file with the same name
    counter = 1
    while os.path.exists(dest):
        name, ext = os.path.splitext(filename)
        dest = os.path.join(QUARANTINE_DIR, f"{name}_{counter}{ext}")
        counter += 1

    try:
        shutil.move(filepath, dest)
        log_event(
            "QUARANTINE_SUCCESS",
            f"File isolated: {filepath} → {dest}",
            severity="HIGH",
            metadata={"source": filepath, "destination": dest},
        )
        return True
    except PermissionError:
        log_event(
            "QUARANTINE_FAIL",
            f"Permission denied quarantining {filepath}",
            severity="CRITICAL",
            metadata={"file": filepath},
        )
        return False
    except OSError as exc:
        log_event(
            "QUARANTINE_FAIL",
            f"OS error quarantining {filepath}: {exc}",
            severity="CRITICAL",
            metadata={"file": filepath, "error": str(exc)},
        )
        return False


# ── Full Scan Orchestrator ───────────────────────────────────────

def collect_files(target_dir: str) -> list[str]:
    """
    Recursively collect all file paths within the target directory.

    Skips symbolic links to prevent infinite traversal loops
    (a common attack vector against naive scanners).
    """
    file_list = []
    for root, _dirs, files in os.walk(target_dir, followlinks=False):
        for fname in files:
            file_list.append(os.path.join(root, fname))
    return file_list
