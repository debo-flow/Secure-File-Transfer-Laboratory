"""Performance benchmarking for cryptographic hashing and PKI."""
import time
import tracemalloc
from pathlib import Path
from typing import Dict, Any

from modules.hashing import calculate_hashes
from modules.pki import generate_ed25519_keypair, sign_file_streaming, verify_file_signature
from core.logger import get_logger

logger = get_logger(__name__)

# -- [Original M3 run_hash_benchmarks preserved] --
def run_hash_benchmarks(file_path: Path, chunk_size: int = 65536) -> Dict[str, Any]:
    file_size_mb = file_path.stat().st_size / (1024 * 1024)
    tracemalloc.start()
    start_time = time.perf_counter()
    hashes = calculate_hashes(file_path, chunk_size)
    end_time = time.perf_counter()
    _, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    return {
        "File_Size_MB": round(file_size_mb, 2),
        "Total_Duration_Seconds": round(end_time - start_time, 4),
        "Peak_Memory_Overhead_KB": round(peak_mem / 1024, 2),
    }

# --- [M5 NEW: Signature Benchmarking] ---
def run_signature_benchmarks(file_path: Path) -> Dict[str, Any]:
    """Measures PKI performance metrics (Ed25519)."""
    file_size_mb = file_path.stat().st_size / (1024 * 1024)
    
    # Key Gen
    t0 = time.perf_counter()
    priv, pub = generate_ed25519_keypair()
    t1 = time.perf_counter()
    
    # Signing
    sig = sign_file_streaming(file_path, priv)
    t2 = time.perf_counter()
    
    # Verification
    verify_file_signature(file_path, sig, pub)
    t3 = time.perf_counter()
    
    return {
        "File_Size_MB": round(file_size_mb, 2),
        "KeyGen_Time_Sec": round(t1 - t0, 5),
        "Sign_Time_Sec": round(t2 - t1, 4),
        "Verify_Time_Sec": round(t3 - t2, 4),
        "Algorithm": "Ed25519"
    }
