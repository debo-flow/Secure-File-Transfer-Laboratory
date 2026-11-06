"""Chunk-level integrity analysis and Baseline management."""
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Tuple

from core.config import CONFIG
from core.logger import get_logger
from core.exceptions import BaselineError
from modules.merkle import generate_merkle_tree

logger = get_logger(__name__)

def generate_chunk_hashes(file_path: Path, chunk_size: int) -> List[str]:
    """Generates standard SHA-256 hashes for individual file chunks."""
    hashes = []
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            hashes.append(hashlib.sha256(chunk).hexdigest())
    return hashes

def create_baseline(file_path: Path, chunk_size_kb: int = None) -> Dict[str, Any]:
    """Creates a secure integrity baseline for a given file."""
    chunk_size = (chunk_size_kb or CONFIG.integrity.default_chunk_size_kb) * 1024
    
    stat = file_path.stat()
    chunk_hashes = generate_chunk_hashes(file_path, chunk_size)
    merkle_root, _ = generate_merkle_tree(file_path, chunk_size)
    
    # Full file hash
    full_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            full_hash.update(chunk)
            
    baseline = {
        "Baseline_Version": "1.0",
        "Timestamp": datetime.now().isoformat(),
        "Filename": file_path.name,
        "File_Size_Bytes": stat.st_size,
        "Chunk_Size_Bytes": chunk_size,
        "Total_Chunks": len(chunk_hashes),
        "SHA256_Full": full_hash.hexdigest(),
        "Merkle_Root": merkle_root,
        "Chunk_Hashes": chunk_hashes
    }
    
    logger.info(f"Baseline created for {file_path.name}")
    return baseline

def verify_against_baseline(file_path: Path, baseline: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compares a current file against a provided baseline.
    Returns status: VERIFIED, MODIFIED, CORRUPTED.
    """
    if not file_path.exists():
        return {"Status": "MISSING", "Details": "File does not exist on disk."}
        
    current_stat = file_path.stat()
    chunk_size = baseline.get("Chunk_Size_Bytes", CONFIG.integrity.default_chunk_size_kb * 1024)
    current_chunk_hashes = generate_chunk_hashes(file_path, chunk_size)
    current_merkle_root, _ = generate_merkle_tree(file_path, chunk_size)
    
    base_hashes = baseline.get("Chunk_Hashes", [])
    
    differences = []
    max_len = max(len(base_hashes), len(current_chunk_hashes))
    
    for i in range(max_len):
        base_h = base_hashes[i] if i < len(base_hashes) else "MISSING_IN_BASELINE"
        curr_h = current_chunk_hashes[i] if i < len(current_chunk_hashes) else "MISSING_IN_FILE"
        if base_h != curr_h:
            differences.append({
                "Chunk_Index": i,
                "Expected": base_h,
                "Actual": curr_h
            })

    # Determine Status
    status = "VERIFIED"
    if current_merkle_root != baseline.get("Merkle_Root"):
        # Could be MODIFIED (intentional size change) or CORRUPTED (same size, bad chunk)
        if current_stat.st_size != baseline.get("File_Size_Bytes"):
            status = "MODIFIED"
        else:
            status = "CORRUPTED"

    return {
        "Status": status,
        "Original_Size": baseline.get("File_Size_Bytes"),
        "Current_Size": current_stat.st_size,
        "Original_Merkle_Root": baseline.get("Merkle_Root"),
        "Current_Merkle_Root": current_merkle_root,
        "Chunks_Modified": len(differences),
        "Differences": differences[:50]  # Cap reporting to prevent massive payloads
    }
