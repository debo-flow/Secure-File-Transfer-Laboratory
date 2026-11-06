"""Cryptographic hashing engine supporting large files via chunking."""
import hashlib
from pathlib import Path
from typing import Dict

from core.logger import get_logger
from core.exceptions import FileValidationError

logger = get_logger(__name__)

def calculate_hashes(file_path: Path, chunk_size: int = 65536) -> Dict[str, str]:
    """
    Calculates SHA-256, SHA-512, and BLAKE2b hashes safely using a streaming
    chunk approach. This prevents memory exhaustion on large files.
    """
    if not file_path.exists() or not file_path.is_file():
        raise FileValidationError("Invalid file path provided for hashing.")
        
    sha256_hash = hashlib.sha256()
    sha512_hash = hashlib.sha512()
    blake2b_hash = hashlib.blake2b()
    
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                sha256_hash.update(chunk)
                sha512_hash.update(chunk)
                blake2b_hash.update(chunk)
                
        logger.info(f"Successfully calculated hashes for {file_path.name}")
        
        return {
            "SHA-256": sha256_hash.hexdigest(),
            "SHA-512": sha512_hash.hexdigest(),
            "BLAKE2b": blake2b_hash.hexdigest()
        }
        
    except IOError as e:
        logger.error(f"IO Error during hashing of {file_path.name}: {str(e)}")
        raise FileValidationError("Could not read file for hash calculation.")
