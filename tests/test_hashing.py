"""Pytest suite for cryptographic hashing engine."""
import pytest
import hashlib
from modules.hashing import calculate_hashes
from core.exceptions import FileValidationError

def test_calculate_hashes_all_algorithms(tmp_path):
    test_file = tmp_path / "hash_test.txt"
    content = b"The quick brown fox jumps over the lazy dog"
    test_file.write_bytes(content)
    
    hashes = calculate_hashes(test_file)
    
    # M1 Hashes
    assert "SHA-256" in hashes
    assert "SHA-512" in hashes
    assert "BLAKE2b" in hashes
    
    # M3 Hashes
    assert "SHA-384" in hashes
    assert "SHA3-256" in hashes
    assert "SHA3-512" in hashes
    assert "BLAKE2s" in hashes
    
    assert hashes["SHA-256"] == hashlib.sha256(content).hexdigest()
    assert hashes["SHA3-256"] == hashlib.sha3_256(content).hexdigest()

def test_calculate_hashes_invalid_file(tmp_path):
    fake_file = tmp_path / "nope.txt"
    with pytest.raises(FileValidationError):
        calculate_hashes(fake_file)
