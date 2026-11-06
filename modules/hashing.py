"""Cryptographic hashing engine supporting large files via chunking."""
import hashlib
from pathlib import Path
from typing import Dict

from core.logger import get_logger
from core.exceptions import FileValidationError

logger = get_logger(__name__)

def calculate_hashes(file_path: Path, chunk_size: int = 65536) -> Dict[str, str]:
    """
    Calculates multiple cryptographic hashes safely using a streaming
    chunk approach. Memory-efficient for massive files.
    """
    if not file_path.exists() or not file_path.is_file():
        raise FileValidationError("Invalid file path provided for hashing.")
        
    hashers = {
        "SHA-256": hashlib.sha256(),
        "SHA-384": hashlib.sha384(),
        "SHA-512": hashlib.sha512(),
        "SHA3-256": hashlib.sha3_256(),
        "SHA3-512": hashlib.sha3_512(),
        "BLAKE2b": hashlib.blake2b(),
        "BLAKE2s": hashlib.blake2s()
    }
    
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                for hasher in hashers.values():
                    hasher.update(chunk)
                
        logger.info(f"Successfully calculated hashes for {file_path.name}")
        return {name: hasher.hexdigest() for name, hasher in hashers.items()}
        
    except IOError as e:
        logger.error(f"IO Error during hashing of {file_path.name}: {str(e)}")
        raise FileValidationError("Could not read file for hash calculation.")
