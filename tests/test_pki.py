"""Pytest suite for Digital Signatures (Ed25519 & RSA-PSS)."""
import pytest
from pathlib import Path
from cryptography.exceptions import InvalidSignature

from modules.pki import (
    generate_ed25519_keypair, generate_rsa_keypair, export_private_key, 
    export_public_key, load_private_key, load_public_key, 
    sign_file_streaming, verify_file_signature
)
from core.exceptions import PKIError, SignatureVerificationError

def test_ed25519_key_lifecycle():
    priv, pub = generate_ed25519_keypair()
    priv_pem = export_private_key(priv, "secure_pass")
    pub_pem = export_public_key(pub)
    
    loaded_priv = load_private_key(priv_pem, "secure_pass")
    loaded_pub = load_public_key(pub_pem)
    
    # Verify exact roundtrip serialization match
    assert export_public_key(loaded_priv.public_key()) == export_public_key(loaded_pub)
    
    with pytest.raises(PKIError):
        load_private_key(priv_pem, "wrong_pass")

def test_streaming_signature_ed25519(tmp_path):
    priv, pub = generate_ed25519_keypair()
    test_file = tmp_path / "data.bin"
    test_file.write_bytes(b"Secure data stream")
    
    sig = sign_file_streaming(test_file, priv)
    
    # Must succeed silently
    assert verify_file_signature(test_file, sig, pub) is True
    
    # Modify file -> Must throw
    test_file.write_bytes(b"Secure data stream - TAMPERED")
    with pytest.raises(SignatureVerificationError):
        verify_file_signature(test_file, sig, pub)

def test_streaming_signature_rsa(tmp_path):
    priv, pub = generate_rsa_keypair(key_size=2048) # 2048 for faster testing
    test_file = tmp_path / "rsa_data.bin"
    test_file.write_bytes(b"RSA PSS Testing")
    
    sig = sign_file_streaming(test_file, priv)
    assert verify_file_signature(test_file, sig, pub) is True
