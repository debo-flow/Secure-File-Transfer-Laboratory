 """Secure File Fingerprinting and Manifest Identity Management Engine."""
import json
import uuid
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from core.config import CONFIG
from core.logger import get_logger
from core.exceptions import ManifestError, SignatureVerificationError
from modules.file_analyzer import get_file_metadata
from modules.signatures import detect_file_signature
from modules.hashing import calculate_hashes
from modules.merkle import generate_merkle_tree
from modules.integrity import generate_chunk_hashes
from modules.pki import load_public_key, verify_file_signature
from modules.key_directory import get_public_key

logger = get_logger(__name__)

# -- [M4 Original Generation functions omitted for brevity in thought, but included here in full] --
def generate_file_manifest(file_path: Path, include_chunks: bool = True) -> Dict[str, Any]:
    metadata = get_file_metadata(file_path)
    sig_data = detect_file_signature(file_path)
    fingerprints = calculate_hashes(file_path)
    
    chunk_size = CONFIG.integrity.default_chunk_size_kb * 1024
    merkle_root, _ = generate_merkle_tree(file_path, chunk_size)
    chunk_hashes = generate_chunk_hashes(file_path, chunk_size) if include_chunks else []

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
            "Signature": None
        },
        "Version_History": []
    }
    return manifest

def serialize_manifest_canonical(manifest: Dict[str, Any]) -> str:
    try:
        return json.dumps(manifest, separators=(',', ':'), sort_keys=True)
    except Exception as e:
        raise ManifestError(f"Serialization failed: {str(e)}")

def parse_and_validate_manifest(manifest_json: str) -> Dict[str, Any]:
    try:
        manifest = json.loads(manifest_json)
    except json.JSONDecodeError as e:
        raise ManifestError(f"Invalid JSON format: {str(e)}")
    for key in ["Manifest_ID", "Schema_Version", "File_Identity", "Cryptographic_Fingerprints"]:
        if key not in manifest: raise ManifestError(f"Missing key '{key}'")
    return manifest

# --- [M5 NEW: Signature Wrapping for Manifests] ---
def authenticate_manifest(manifest: Dict[str, Any], private_key: Any, key_id: str) -> Dict[str, Any]:
    """Signs a manifest deterministically to prove authenticity."""
    m = manifest.copy()
    m["Authentication"] = {
        "Status": "Signed",
        "Signature_Algorithm": private_key.__class__.__name__,
        "Public_Key_ID": key_id,
        "Signature": None # Clear before hashing
    }
    
    canonical = serialize_manifest_canonical(m)
    digest = hashlib.sha256(canonical.encode()).digest()
    
    # Import locally to avoid circular dependencies
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
    
    if "RSAPrivateKey" in m["Authentication"]["Signature_Algorithm"]:
        sig = private_key.sign(
            digest, 
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            Prehashed(hashes.SHA256())
        )
    else:
        # Ed25519 signs the hash directly in this custom envelope
        sig = private_key.sign(digest)
        
    m["Authentication"]["Signature"] = sig.hex()
    return m

def verify_manifest_integrity(file_path: Path, manifest: Dict[str, Any]) -> Dict[str, Any]:
    """Validates structural and cryptographic authenticity of file and manifest."""
    if not file_path.exists(): return {"Valid": False, "Error": "File missing."}
    
    current_size = file_path.stat().st_size
    expected_size = manifest.get("File_Identity", {}).get("Size_Bytes")
    if current_size != expected_size:
        return {"Valid": False, "Error": "Size mismatch."}
        
    current_fp = calculate_hashes(file_path)
    for algo, exp_hash in manifest.get("Cryptographic_Fingerprints", {}).items():
        if algo in current_fp and current_fp[algo] != exp_hash:
            return {"Valid": False, "Error": f"Fingerprint mismatch ({algo})"}
            
    # M5: Verify Signature if present
    auth = manifest.get("Authentication", {})
    if auth.get("Status") == "Signed":
        try:
            pub_key = get_public_key(auth.get("Public_Key_ID"))
            sig_hex = auth.get("Signature")
            
            # Recreate canonical payload without signature
            verify_m = manifest.copy()
            verify_m["Authentication"]["Signature"] = None
            canonical = serialize_manifest_canonical(verify_m)
            digest = hashlib.sha256(canonical.encode()).digest()
            
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
            
            if "RSAPublicKey" in auth.get("Signature_Algorithm"):
                pub_key.verify(
                    bytes.fromhex(sig_hex), digest,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    Prehashed(hashes.SHA256())
                )
            else:
                pub_key.verify(bytes.fromhex(sig_hex), digest)
                
            return {"Valid": True, "Message": "VALID SIGNATURE. Manifest and File authenticated."}
        except Exception as e:
            return {"Valid": False, "Error": f"SIGNATURE INVALID: {str(e)}"}
            
    return {"Valid": True, "Message": "Valid structural match. NOTE: Manifest is UNSIGNED."}
