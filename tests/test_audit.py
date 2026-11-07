"""Pytest suite for immutable signature auditing."""
import pytest
from core.config import CONFIG
from modules.audit import log_signature_event, get_audit_history

def test_audit_logging(tmp_path):
    CONFIG.pki.pki_dir = tmp_path
    
    log_signature_event("SIGN", "test.txt", "key_123", "SUCCESS", "Signed")
    log_signature_event("VERIFY", "test.txt", "key_123", "INVALID", "Tampered")
    
    history = get_audit_history()
    assert len(history) == 2
    
    assert history[0]["Action"] == "SIGN"
    assert history[1]["Status"] == "INVALID"
    
    # Verify private key data is absent (checked structurally)
    assert "Private_Key" not in history[0]
