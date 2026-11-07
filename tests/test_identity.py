"""Pytest suite for File Fingerprinting and Manifest Identity Management."""
import pytest
import json
from pathlib import Path
from modules.identity import (
    generate_file_manifest, serialize_manifest_canonical, 
    parse_and_validate_manifest, verify_manifest_integrity, 
    detect_duplicate_content, create_manifest_version
)
from core.exceptions import ManifestError

def test_generate_file_manifest(tmp_path):
    test_file = tmp_path / "data.txt"
    test_file.write_bytes(b"Hello Identity")
    
    manifest = generate_file_manifest(test_file)
    
    assert "Manifest_ID" in manifest
    assert "Schema_Version" in manifest
    assert "File_Identity" in manifest
    assert manifest["File_Identity"]["Filename"] == "data.txt"
    assert "SHA-256" in manifest["Cryptographic_Fingerprints"]
    assert "Authentication" in manifest
    assert manifest["Authentication"]["Status"] == "Unsigned"

def test_serialize_manifest_canonical():
    manifest = {"B": 2, "A": 1, "C": {"Z": 9, "Y": 8}}
    canonical = serialize_manifest_canonical(manifest)
    
    # Keys must be alphabetically sorted and whitespace stripped
    assert canonical == '{"A":1,"B":2,"C":{"Y":8,"Z":9}}'

def test_parse_and_validate_manifest_malformed():
    bad_json = '{"Invalid": "JSON'
    with pytest.raises(ManifestError, match="Invalid JSON format"):
        parse_and_validate_manifest(bad_json)
        
    missing_keys_json = '{"Manifest_ID": "123"}'
    with pytest.raises(ManifestError, match="Missing critical key"):
        parse_and_validate_manifest(missing_keys_json)

def test_verify_manifest_integrity(tmp_path):
    test_file = tmp_path / "data.txt"
    test_file.write_bytes(b"Consistent Data")
    
    manifest = generate_file_manifest(test_file)
    
    # Verify exact match
    result = verify_manifest_integrity(test_file, manifest)
    assert result["Valid"] is True
    
    # Modify file and test rejection
    test_file.write_bytes(b"Modified Data")
    result = verify_manifest_integrity(test_file, manifest)
    assert result["Valid"] is False
    assert "Size mismatch" in result["Error"] or "fingerprint mismatch" in result["Error"]

def test_create_manifest_version(tmp_path):
    v1_file = tmp_path / "v1.txt"
    v1_file.write_bytes(b"Version 1")
    v1_manifest = generate_file_manifest(v1_file)
    
    v2_file = tmp_path / "v2.txt"
    v2_file.write_bytes(b"Version 2")
    
    v2_manifest = create_manifest_version(v1_manifest, v2_file)
    
    # ID must be retained
    assert v2_manifest["Manifest_ID"] == v1_manifest["Manifest_ID"]
    # History must contain exactly 1 old version
    assert len(v2_manifest["Version_History"]) == 1
    # Old history must be wiped in the archive to prevent recursion
    assert len(v2_manifest["Version_History"][0]["Previous_State"]["Version_History"]) == 0

def test_detect_duplicate_content(tmp_path):
    f1 = tmp_path / "doc1.txt"
    f2 = tmp_path / "renamed_doc.txt"
    f3 = tmp_path / "unique.txt"
    
    f1.write_bytes(b"Duplicate Payload")
    f2.write_bytes(b"Duplicate Payload")
    f3.write_bytes(b"Unique Payload")
    
    m1 = generate_file_manifest(f1)
    m2 = generate_file_manifest(f2)
    m3 = generate_file_manifest(f3)
    
    duplicates = detect_duplicate_content([m1, m2, m3])
    
    assert len(duplicates) == 1 # Only one shared hash
    shared_hash = list(duplicates.keys())[0]
    
    assert len(duplicates[shared_hash]) == 2
    filenames = [f["Filename"] for f in duplicates[shared_hash]]
    assert "doc1.txt" in filenames
    assert "renamed_doc.txt" in filenames
    assert "unique.txt" not in filenames
