"""
utils/logger.py — Structured JSON Audit Logger (SIEM-Compatible)

Generates professional, timestamped JSON audit logs for every
scanner action. Each log entry is a self-contained JSON object
written to both a rotating log file and optionally streamed
to the Rich console in real-time.

Format designed for direct ingestion by modern SIEM platforms
(Splunk, Elastic Security, Microsoft Sentinel).

Author : Maniya Jay Maheshbhai (24DCS050)
Project: CwX Antivirus Simulation — DEPSTAR
"""

import json
import os
from datetime import datetime, timezone


# ── Constants ────────────────────────────────────────────────────
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
LOG_FILE = os.path.join(LOG_DIR, "cwx_audit.jsonl")


def _ensure_log_dir() -> None:
    """Create the logs directory if it does not exist."""
    os.makedirs(LOG_DIR, exist_ok=True)


def log_event(
    event_type: str,
    message: str,
    severity: str = "INFO",
    metadata: dict | None = None,
) -> dict:
    """
    Write a single structured audit event to the JSONL log file.

    Parameters
    ----------
    event_type : str
        Category tag, e.g. "SCAN_START", "THREAT_DETECTED",
        "QUARANTINE_SUCCESS", "HEURISTIC_FLAG".
    message : str
        Human-readable description of the event.
    severity : str
        One of INFO | LOW | MEDIUM | HIGH | CRITICAL.
    metadata : dict, optional
        Arbitrary key-value payload (file path, hash, entropy, etc.).

    Returns
    -------
    dict
        The log entry that was persisted (useful for unit tests).
    """
    _ensure_log_dir()

    # Build a SIEM-ready log entry with ISO-8601 timestamps
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "severity": severity,
        "message": message,
        "source": "CwX-AV-Engine",
        "metadata": metadata or {},
    }

    # Append to the JSONL (JSON Lines) file — one JSON object per line
    # This format is natively supported by Elastic, Splunk, and Loki
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    return entry


def get_log_path() -> str:
    """Return the absolute path to the active log file."""
    return LOG_FILE
