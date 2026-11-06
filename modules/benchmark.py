"""Performance benchmarking for cryptographic hashing."""
import time
import tracemalloc
from pathlib import Path
from typing import Dict, Any

from modules.hashing import calculate_hashes
from core.logger import get_logger

logger = get_logger(__name__)

def run_hash_benchmarks(file_path: Path, chunk_size: int = 65536) -> Dict[str, Any]:
    """
    Measures processing speed and memory overhead for the hashing engine.
    """
    logger.info(f"Starting benchmark for {file_path.name}")
    
    results = {}
    file_size_mb = file_path.stat().st_size / (1024 * 1024)
    
    tracemalloc.start()
    start_time = time.perf_counter()
    
    # Run the comprehensive M3 hasher
    hashes = calculate_hashes(file_path, chunk_size)
    
    end_time = time.perf_counter()
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    duration = end_time - start_time
    throughput_mb_s = file_size_mb / duration if duration > 0 else 0
    
    results = {
        "File_Size_MB": round(file_size_mb, 2),
        "Total_Duration_Seconds": round(duration, 4),
        "Throughput_MB_s": round(throughput_mb_s, 2),
        "Peak_Memory_Overhead_KB": round(peak_mem / 1024, 2),
        "Hashes_Generated": list(hashes.keys())
    }
    
    return results
