"""Pytest suite for Chunk Integrity and Baselines."""
import pytest
from pathlib import Path
from modules.integrity import create_baseline, verify_against_baseline

def test_baseline_creation_and_verification(tmp_path):
    test_file = tmp_path / "data.bin"
    test_file.write_bytes(b"A" * 2048) # 2KB
    
    # Create baseline with 1KB chunks
    baseline = create_baseline(test_file, chunk_size_kb=1)
    
    assert baseline["Total_Chunks"] == 2
    assert baseline["File_Size_Bytes"] == 2048
    
    # Verify unchanged file
    result = verify_against_baseline(test_file, baseline)
    assert result["Status"] == "VERIFIED"
    assert result["Chunks_Modified"] == 0

def test_baseline_modified_file(tmp_path):
    test_file = tmp_path / "data.bin"
    test_file.write_bytes(b"A" * 2048)
    baseline = create_baseline(test_file, chunk_size_kb=1)
    
    # Modify file size
    test_file.write_bytes(b"A" * 2048 + b"B")
    
    result = verify_against_baseline(test_file, baseline)
    assert result["Status"] == "MODIFIED"
    assert result["Chunks_Modified"] > 0

def test_baseline_corrupted_file(tmp_path):
    test_file = tmp_path / "data.bin"
    test_file.write_bytes(b"A" * 2048)
    baseline = create_baseline(test_file, chunk_size_kb=1)
    
    # Modify data but keep size identical
    test_file.write_bytes(b"B" * 2048)
    
    result = verify_against_baseline(test_file, baseline)
    assert result["Status"] == "CORRUPTED"
    assert result["Chunks_Modified"] == 2

def test_baseline_missing_file(tmp_path):
    fake_file = tmp_path / "missing.bin"
    result = verify_against_baseline(fake_file, {"Mock": "Baseline"})
    assert result["Status"] == "MISSING"
