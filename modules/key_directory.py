"""Local Public Key Directory and Trust Management."""
import json
import hashlib
from pathlib import Path
from typing import Dict, Any

from core.config import CONFIG
from core.exceptions import PKIError
from modules.pki import export_public_key, load_public_key

def get_registry_path() -> Path:
    return CONFIG.pki.pki_dir / CONFIG.pki.key_directory_file

def _load_registry() -> Dict[str, Any]:
    path = get_registry_path()
    if not path.exists(): return {}
    with open(path, "r") as f: return json.load(f)

def _save_registry(registry: Dict[str, Any]):
    with open(get_registry_path(), "w") as f:
        json.dump(registry, f, indent=4)

def generate_key_id(public_key: Any) -> str:
    """Generates a unique SHA-256 fingerprint for a public key."""
    pem_bytes = export_public_key(public_key)
    return hashlib.sha256(pem_bytes).hexdigest()[:16] # Shortened for usability

def add_public_key(name: str, public_key_pem: bytes, trust_label: str = "Unverified") -> str:
    """Imports a public key into the local directory."""
    pub_key = load_public_key(public_key_pem)
    key_id = generate_key_id(pub_key)
    
    registry = _load_registry()
    
    # Save the PEM file securely
    pem_path = CONFIG.pki.pki_dir / f"{key_id}.pem"
    with open(pem_path, "wb") as f: f.write(public_key_pem)
        
    registry[key_id] = {
        "Owner_Alias": name,
        "Algorithm": pub_key.__class__.__name__,
        "Trust_Label": trust_label,
        "File_Path": str(pem_path.name)
    }
    
    _save_registry(registry)
    return key_id

def get_public_key(key_id: str) -> Any:
    """Retrieves and instantiates a public key from the directory."""
    registry = _load_registry()
    if key_id not in registry:
        raise PKIError(f"Key ID {key_id} not found in directory.")
        
    pem_path = CONFIG.pki.pki_dir / registry[key_id]["File_Path"]
    if not pem_path.exists():
        raise PKIError("Key file missing from disk.")
        
    with open(pem_path, "rb") as f:
        return load_public_key(f.read())

def list_keys() -> Dict[str, Any]:
    """Returns metadata for all keys in the directory."""
    return _load_registry()

def update_trust_label(key_id: str, label: str):
    """Updates local trust label (Trusted, Unverified, Revoked)."""
    registry = _load_registry()
    if key_id in registry:
        registry[key_id]["Trust_Label"] = label
        _save_registry(registry)
