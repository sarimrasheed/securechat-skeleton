"""
Append-only transcript + TranscriptHash helpers.
Implements:
- append()            -> store encrypted message metadata
- compute_hash()      -> SHA256 digest over ordered transcript
- save_receipt()      -> store final SessionReceipt (signed)
- load_transcript()   -> read transcript for verification
"""

import json
import os
import hashlib
from pathlib import Path
from datetime import datetime


TRANSCRIPT_DIR = Path("transcripts")
TRANSCRIPT_DIR.mkdir(exist_ok=True)


def _session_file(session_id: str) -> Path:
    """Return path to transcript file for this session."""
    return TRANSCRIPT_DIR / f"{session_id}.jsonl"


def _receipt_file(session_id: str) -> Path:
    """Return path to SessionReceipt file."""
    return TRANSCRIPT_DIR / f"{session_id}.receipt.json"


# --------------------------------------------------------
# Append a transcript entry
# --------------------------------------------------------

def append(session_id: str, direction: str, enc_type: str,
           ciphertext_b64: str, signature_b64: str | None, ts: int):
    """
    Append one transcript line as JSON:
    {
        "dir": "client→server" or "server→client",
        "enc_type": "register/login/msg",
        "cipher": "...",
        "sig": "...",
        "ts": 123456789
    }
    """
    entry = {
        "dir": direction,
        "enc_type": enc_type,
        "cipher": ciphertext_b64,
        "sig": signature_b64,
        "ts": ts,
    }

    fpath = _session_file(session_id)
    with fpath.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


# --------------------------------------------------------
# Compute ordered transcript hash
# --------------------------------------------------------

def compute_hash(session_id: str) -> str:
    """
    Compute SHA256 hash over the concatenation of all transcript lines.
    This prevents deletion/reordering of messages.
    """
    fpath = _session_file(session_id)
    h = hashlib.sha256()

    if not fpath.exists():
        return None

    with fpath.open("r", encoding="utf-8") as f:
        for line in f:
            h.update(line.encode())

    return h.hexdigest()


# --------------------------------------------------------
# Save SessionReceipt (signed digest)
# --------------------------------------------------------

def save_receipt(session_id: str, server_signature_b64: str, client_username: str):
    """
    Save final NR receipt:
    {
        "session_id": "...",
        "client": "alice",
        "transcript_hash": "...",
        "server_sig": "...",
        "timestamp": "2025-11-15T18:22:00Z"
    }
    """
    digest = compute_hash(session_id)

    receipt = {
        "session_id": session_id,
        "client": client_username,
        "transcript_hash": digest,
        "server_sig": server_signature_b64,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    with _receipt_file(session_id).open("w", encoding="utf-8") as f:
        json.dump(receipt, f, indent=4)

    return receipt


# --------------------------------------------------------
# Load transcript (for verification)
# --------------------------------------------------------

def load_transcript(session_id: str) -> list[dict]:
    """Return list of transcript entries."""
    fpath = _session_file(session_id)

    if not fpath.exists():
        return []

    lines = []
    with fpath.open("r", encoding="utf-8") as f:
        for line in f:
            try:
                lines.append(json.loads(line))
            except:
                pass
    return lines
