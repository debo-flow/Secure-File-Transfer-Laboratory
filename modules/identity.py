"""Secure File Fingerprinting and Manifest Identity Management Engine."""
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from core.config import CONFIG
from core.logger import get_logger
from core.exceptions import ManifestError
from modules.file_analyzer import get_file_metadata
from modules.signatures import detect_file_signature
from modules.hashing import calculate_hashes
from modules.merkle import generate_merkle_tree
from modules.integrity import generate_chunk_hashes

logger = get_logger(__name__)

def generate_file_manifest(file_path: Path, include_chunks: bool = True) -> Dict[str, Any]:
    """
    Generates a structured, deterministic file identity manifest.
    Contains no absolute file paths—only relative file identities and fingerprints.
    """
    logger.info(f"Generating file identity manifest for {file_path.name}")
    
    # Extract structural and heuristic metadata
    metadata = get_file_metadata(file_path)
    sig_data = detect_file_signature(file_path)
    
    # Extract cryptographic fingerprints
    fingerprints = calculate_hashes(file_path)
    
    # Extract Chunk and Merkle data
    chunk_size = CONFIG.integrity.default_chunk_size_kb * 1024
    merkle_root, _ = generate_merkle_tree(file_path, chunk_size)
    
    chunk_hashes = []
    if include_chunks:
        chunk_hashes = generate_chunk_hashes(file_path, chunk_size)

    manifest = {
        "Manifest_ID": str(uuid.uuid4()),
        "Schema_Version": CONFIG.identity.manifest_schema_version,
        "Generated_At": datetime.now().isoformat(),
        "File_Identity": {
            "Filename": file_path.name,
            "Size_Bytes": metadata.get("Size (Bytes)", 0),
            "Format_Description": sig_data.get("Format Description", "Unknown"),
            "MIME_Type": sig_data.get("Detected MIME", metadata.get("MIME Type", ""))
        },
        "Cryptographic_Fingerprints": fingerprints,
        "Integrity_Data": {
            "Chunk_Size_Bytes": chunk_size,
            "Merkle_Root": merkle_root,
            "Chunk_Hashes": chunk_hashes
        },
        "Authentication": {
            "Status": "Unsigned",
            "Signature_Algorithm": None,
            "Public_Key_ID": None,
            "Signature": None,
            "Signer_Metadata": None
        },
        "Version_History": []
    }
    
    return manifest

def serialize_manifest_canonical(manifest: Dict[str, Any]) -> str:
    """
    Serializes a manifest deterministically for future cryptographic signing.
    Sorts keys and removes whitespace for consistent byte representation.
    """
    try:
        return json.dumps(manifest, separators=(',', ':'), sort_keys=True)
    except (TypeError, ValueError) as e:
        raise ManifestError(f"Failed to serialize manifest: {str(e)}")

def parse_and_validate_manifest(manifest_json: str) -> Dict[str, Any]:
    """Parses JSON safely and validates basic manifest schema structure."""
    try:
        manifest = json.loads(manifest_json)
    except json.JSONDecodeError as e:
        raise ManifestError(f"Invalid JSON format: {str(e)}")
        
    required_keys = ["Manifest_ID", "Schema_Version", "File_Identity", "Cryptographic_Fingerprints"]
    for key in required_keys:
        if key not in manifest:
            raise ManifestError(f"Malformed manifest: Missing critical key '{key}'")
            
    return manifest

def verify_manifest_integrity(file_path: Path, manifest: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates a physical file against an existing manifest.
    Differentiates structural validity from cryptographic authenticity.
    """
    if not file_path.exists():
        return {"Valid": False, "Error": "File does not exist."}
        
    current_size = file_path.stat().st_size
    expected_size = manifest.get("File_Identity", {}).get("Size_Bytes")
    
    if current_size != expected_size:
        return {
            "Valid": False, 
            "Error": f"Size mismatch. Expected {expected_size}, got {current_size}"
        }
        
    current_fingerprints = calculate_hashes(file_path)
    expected_fingerprints = manifest.get("Cryptographic_Fingerprints", {})
    
    mismatches = []
    for algo, expected_hash in expected_fingerprints.items():
        if algo in current_fingerprints:
            if current_fingerprints[algo] != expected_hash:
                mismatches.append(algo)
                
    if mismatches:
        return {
            "Valid": False,
            "Error": f"Cryptographic fingerprint mismatch on algorithms: {', '.join(mismatches)}"
        }
        
    # Check signature placeholder (M4 logic)
    auth_status = manifest.get("Authentication", {}).get("Status", "Unsigned")
    auth_note = "Valid structural match. Cryptographic signature is present." if auth_status != "Unsigned" else "Valid structural match. NOTE: Manifest is Unsigned (lacks cryptographic authenticity)."
        
    return {
        "Valid": True,
        "Message": auth_note,
        "Matched_Fingerprints": list(expected_fingerprints.keys())
    }

def create_manifest_version(old_manifest: Dict[str, Any], new_file_path: Path) -> Dict[str, Any]:
    """
    Generates a new manifest for an updated file, preserving the ID
    and storing the previous state in the Version_History array.
    """
    new_manifest = generate_file_manifest(new_file_path)
    
    # Preserve Identity lineage
    new_manifest["Manifest_ID"] = old_manifest.get("Manifest_ID")
    
    # Store old version (strip its history to prevent recursive bloat)
    old_archive = old_manifest.copy()
    old_archive["Version_History"] = []
    
    history = old_manifest.get("Version_History", [])
    history.append({
        "Archived_At": datetime.now().isoformat(),
        "Previous_State": old_archive
    })
    
    new_manifest["Version_History"] = history
    return new_manifest

def detect_duplicate_content(manifests: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, str]]]:
    """
    Analyzes multiple manifests to detect identical content using SHA-256 fingerprints,
    even if the filenames differ.
    Returns a mapping of SHA-256 Hash -> List of matching file identities.
    """
    content_map: Dict[str, List[Dict[str, str]]] = {}
    
    for m in manifests:
        sha256 = m.get("Cryptographic_Fingerprints", {}).get("SHA-256")
        if not sha256:
            continue
            
        file_name = m.get("File_Identity", {}).get("Filename", "Unknown")
        manifest_id = m.get("Manifest_ID", "Unknown")
        
        if sha256 not in content_map:
            content_map[sha256] = []
            
        content_map[sha256].append({
            "Filename": file_name,
            "Manifest_ID": manifest_id
        })
        
    # Filter out unique files, returning only duplicates
    duplicates = {hash_val: files for hash_val, files in content_map.items() if len(files) > 1}
    return duplicates
