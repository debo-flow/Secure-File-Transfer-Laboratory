"""Pytest suite for performance benchmarking."""
import pytest
from modules.benchmark import run_hash_benchmarks

def test_run_hash_benchmarks(tmp_path):
    test_file = tmp_path / "bench.bin"
    test_file.write_bytes(b"A" * (1024 * 100)) # 100 KB
    
    results = run_hash_benchmarks(test_file)
    
    assert "File_Size_MB" in results
    assert "Total_Duration_Seconds" in results
    assert "Throughput_MB_s" in results
    assert len(results["Hashes_Generated"]) == 7 # Ensures all algorithms fired
