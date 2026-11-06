"""Pytest suite for cryptographic hashing engine."""
import pytest
import hashlib
from modules.hashing import calculate_hashes
from core.exceptions import FileValidationError

def test_calculate_hashes_success(tmp_path):
    test_file = tmp_path / "hash_test.txt"
    content = b"The quick brown fox jumps over the lazy dog"
    test_file.write_bytes(content)
    
    # Calculate manually to compare
    expected_sha256 = hashlib.sha256(content).hexdigest()
    
    hashes = calculate_hashes(test_file)
    
    assert "SHA-256" in hashes
    assert "SHA-512" in hashes
    assert "BLAKE2b" in hashes
    assert hashes["SHA-256"] == expected_sha256

def test_calculate_hashes_invalid_file(tmp_path):
    fake_file = tmp_path / "nope.txt"
    
    with pytest.raises(FileValidationError, match="Invalid file path"):
        calculate_hashes(fake_file)
        
def test_calculate_hashes_large_file_chunking(tmp_path):
    """Simulates a file larger than the chunk size."""
    large_file = tmp_path / "large.bin"
    # Write 100KB (larger than default 64KB chunk size)
    large_file.write_bytes(os.urandom(102400)) 
    
    hashes = calculate_hashes(large_file, chunk_size=1024) # Force chunking
    assert len(hashes["SHA-256"]) == 64
