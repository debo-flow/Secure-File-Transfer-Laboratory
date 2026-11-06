"""Pytest suite for Domain-Separated Merkle Trees."""
import pytest
from modules.merkle import generate_merkle_tree, hash_leaf, hash_node, verify_merkle_proof

def test_merkle_tree_generation(tmp_path):
    test_file = tmp_path / "merkle.bin"
    # Write 3 chunks of data (odd number)
    test_file.write_bytes(b"123456") 
    
    root, tree = generate_merkle_tree(test_file, chunk_size=2)
    
    # 3 leaves -> 1st level has 4 elements (last duplicated) -> 2nd level has 2 -> Root has 1
    assert len(tree[0]) == 4 
    assert len(tree[1]) == 2
    assert len(tree[2]) == 1
    
    assert root == tree[-1][0]
    
def test_merkle_tree_empty(tmp_path):
    test_file = tmp_path / "empty.bin"
    test_file.write_bytes(b"")
    
    root, tree = generate_merkle_tree(test_file, chunk_size=2)
    assert root == hash_leaf(b'')
    assert len(tree) == 1

def test_merkle_proof_verification():
    leaf_data = b"chunk1"
    leaf_hash = hash_leaf(leaf_data)
    sibling_hash = hash_leaf(b"chunk2")
    
    expected_root = hash_node(leaf_hash, sibling_hash)
    
    # Proof: (sibling_hash, direction)
    proof = [(sibling_hash, "right")]
    
    assert verify_merkle_proof(leaf_data, proof, expected_root) is True
    assert verify_merkle_proof(b"wrong_chunk", proof, expected_root) is False
