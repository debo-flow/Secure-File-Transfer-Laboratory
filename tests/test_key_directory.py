"""Pytest suite for PKI Directory management."""
import pytest
import os
from pathlib import Path

from core.config import CONFIG
from modules.pki import generate_ed25519_keypair, export_public_key
from modules.key_directory import add_public_key, get_public_key, list_keys, update_trust_label

def test_key_directory_workflow(tmp_path):
    # Route PKI dir to tmp for test isolation
    CONFIG.pki.pki_dir = tmp_path
    
    priv, pub = generate_ed25519_keypair()
    pub_pem = export_public_key(pub)
    
    # Add Key
    key_id = add_public_key("Alice", pub_pem)
    assert key_id is not None
    
    # List Keys
    registry = list_keys()
    assert key_id in registry
    assert registry[key_id]["Owner_Alias"] == "Alice"
    assert registry[key_id]["Trust_Label"] == "Unverified"
    
    # Update Trust
    update_trust_label(key_id, "Trusted")
    assert list_keys()[key_id]["Trust_Label"] == "Trusted"
    
    # Fetch Key Object
    fetched_pub = get_public_key(key_id)
    assert export_public_key(fetched_pub) == pub_pem
