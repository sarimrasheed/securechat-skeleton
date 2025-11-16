"""
Append-only transcript + TranscriptHash helpers.

Transcript format:
[
  {
    "dir": "client" | "server",
    "ciphertext": "<base64>",
    "sig": "<base64>",
    "ts": <int_timestamp>
  },
  ...
]

Transcript hash:
SHA256(json-serialized transcript)
"""

import json
import os
import hashlib
from typing import List, Dict

TRANSCRIPT_DIR = "transcripts"


# ---------------------------------------------------------
# Ensure directory exists
# ---------------------------------------------------------

def ensure_dir():
    if not os.path.exists(TRANSCRIPT_DIR):
        os.makedirs(TRANSCRIPT_DIR, exist_ok=True)


# ---------------------------------------------------------
# Append entry
# ---------------------------------------------------------

def append_entry(session_id: str, entry: Dict):
    """
    Append a new transcript entry for a session.
    """
    ensure_dir()
    path = os.path.join(TRANSCRIPT_DIR, f"{session_id}.json")

    if os.path.exists(path):
        with open(path, "r") as f:
            arr = json.load(f)
    else:
        arr = []

    arr.append(entry)

    with open(path, "w") as f:
        json.dump(arr, f, indent=2)


# ---------------------------------------------------------
# Load entries
# ---------------------------------------------------------

def load_entries(session_id: str) -> List[Dict]:
    path = os.path.join(TRANSCRIPT_DIR, f"{session_id}.json")
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return json.load(f)


# ---------------------------------------------------------
# Compute transcript hash
# ---------------------------------------------------------

def compute_transcript_hash(session_id: str) -> str:
    """
    Deterministic SHA256 hash of full transcript.
    """
    entries = load_entries(session_id)
    dumped = json.dumps(entries, sort_keys=True).encode()
    return hashlib.sha256(dumped).hexdigest()


# ---------------------------------------------------------
# Save signed SessionReceipt
# ---------------------------------------------------------

def save_session_receipt(session_id: str, receipt: Dict):
    """
    Save SessionReceipt to disk.
    """
    ensure_dir()
    path = os.path.join(TRANSCRIPT_DIR, f"{session_id}_receipt.json")
    with open(path, "w") as f:
        json.dump(receipt, f, indent=2)
