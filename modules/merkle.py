"""Domain-Separated Merkle Tree Engine for File Integrity."""
import hashlib
import math
from pathlib import Path
from typing import List, Tuple, Dict, Optional

from core.logger import get_logger
from core.exceptions import MerkleTreeError

logger = get_logger(__name__)

def hash_leaf(data: bytes) -> str:
    """Domain separated leaf hashing: Prevents second-preimage attacks."""
    return hashlib.sha256(b'\x00' + data).hexdigest()

def hash_node(left_hex: str, right_hex: str) -> str:
    """Domain separated internal node hashing."""
    left_bytes = bytes.fromhex(left_hex)
    right_bytes = bytes.fromhex(right_hex)
    return hashlib.sha256(b'\x01' + left_bytes + right_bytes).hexdigest()

def generate_merkle_tree(file_path: Path, chunk_size: int) -> Tuple[str, List[List[str]]]:
    """
    Constructs a Merkle tree from a file using streaming chunks.
    Handles odd numbers of leaves by duplicating the last node of the level.
    Returns (Merkle Root, Full Tree Matrix).
    """
    leaves = []
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                leaves.append(hash_leaf(chunk))
    except IOError as e:
        raise MerkleTreeError(f"Failed to read file for Merkle tree: {str(e)}")

    if not leaves:
        # Empty file standard root
        empty_root = hash_leaf(b'')
        return empty_root, [[empty_root]]

    tree = [leaves]
    current_level = leaves

    while len(current_level) > 1:
        next_level = []
        # Duplicate last node if odd number
        if len(current_level) % 2 != 0:
            current_level.append(current_level[-1])
            
        for i in range(0, len(current_level), 2):
            next_level.append(hash_node(current_level[i], current_level[i+1]))
            
        tree.append(next_level)
        current_level = next_level

    root = tree[-1][0]
    logger.info(f"Generated Merkle Root: {root}")
    return root, tree

def verify_merkle_proof(leaf_data: bytes, proof: List[Tuple[str, str]], expected_root: str) -> bool:
    """
    Validates a specific chunk of data against a Merkle proof.
    proof is a list of tuples: (sibling_hash, 'left' or 'right')
    """
    current_hash = hash_leaf(leaf_data)
    
    for sibling_hash, direction in proof:
        if direction == 'left':
            current_hash = hash_node(sibling_hash, current_hash)
        else:
            current_hash = hash_node(current_hash, sibling_hash)
            
    return current_hash == expected_root
