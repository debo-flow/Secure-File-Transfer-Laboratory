"""Immutable Signature Audit Logging System."""
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from core.config import CONFIG

def get_audit_path() -> Path:
    return CONFIG.pki.pki_dir / CONFIG.pki.audit_log_file

def log_signature_event(action: str, file_name: str, key_id: str, status: str, details: str):
    """Appends an event securely to the JSONL audit log. Private keys NEVER logged."""
    event = {
        "Timestamp": datetime.now().isoformat(),
        "Action": action, # e.g., "SIGN", "VERIFY"
        "File": file_name,
        "Key_ID": key_id,
        "Status": status,
        "Details": details
    }
    
    with open(get_audit_path(), "a") as f:
        f.write(json.dumps(event) + "\n")

def get_audit_history() -> List[Dict[str, Any]]:
    """Retrieves all parsed audit events."""
    path = get_audit_path()
    events = []
    if path.exists():
        with open(path, "r") as f:
            for line in f:
                if line.strip():
                    events.append(json.loads(line))
    return events
