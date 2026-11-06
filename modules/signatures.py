"""Advanced file signature (magic bytes) and MIME verification engine."""
import mimetypes
from pathlib import Path
from typing import Dict, Tuple, Optional

from core.config import CONFIG
from core.logger import get_logger

logger = get_logger(__name__)

# Dictionary of Magic Bytes to (MIME, Standard Extension, Description)
MAGIC_BYTES_MAP = {
    b'%PDF-': ('application/pdf', '.pdf', 'PDF Document'),
    b'PK\x03\x04': ('application/zip', '.zip', 'ZIP Archive'),
    b'\x89PNG\r\n\x1a\n': ('image/png', '.png', 'PNG Image'),
    b'\xff\xd8\xff': ('image/jpeg', '.jpg', 'JPEG Image'),
    b'{': ('application/json', '.json', 'JSON Data (Heuristic)'),
    b'[': ('application/json', '.json', 'JSON Data (Heuristic)')
}

def detect_file_signature(file_path: Path) -> Dict[str, str]:
    """
    Reads the file header safely to detect magic bytes.
    Returns format information based strictly on file contents, not extensions.
    """
    detected_mime = "application/octet-stream"
    detected_ext = ".bin"
    detected_desc = "Unknown / Binary Data"
    
    try:
        with open(file_path, "rb") as f:
            header = f.read(CONFIG.inspection.magic_bytes_read_len)
            
            # Find matching signature
            for magic, (mime, ext, desc) in MAGIC_BYTES_MAP.items():
                if header.startswith(magic):
                    detected_mime = mime
                    detected_ext = ext
                    detected_desc = desc
                    break
                    
        return {
            "Detected MIME": detected_mime,
            "Detected Extension": detected_ext,
            "Format Description": detected_desc,
            "Signature Verified": "Yes" if detected_desc != "Unknown / Binary Data" else "No"
        }
        
    except IOError as e:
        logger.error(f"Error reading header of {file_path.name}: {str(e)}")
        return {"Error": "Failed to read file signature"}

def verify_mime_type(file_path: Path, signature_data: Dict[str, str]) -> Dict[str, str]:
    """
    Compares the OS/Extension-guessed MIME type with the Signature-detected MIME type.
    """
    guessed_mime, _ = mimetypes.guess_type(file_path.name)
    guessed_mime = guessed_mime or "application/octet-stream"
    
    detected_mime = signature_data.get("Detected MIME", "application/octet-stream")
    detected_ext = signature_data.get("Detected Extension", "")
    
    mismatch = False
    if detected_mime != "application/octet-stream":
        if guessed_mime != detected_mime:
            mismatch = True
            
    # Also check extension mismatch directly
    ext_mismatch = False
    actual_ext = file_path.suffix.lower()
    if detected_ext and detected_ext != '.bin' and actual_ext != detected_ext:
        # Handling aliases (e.g. .jpeg and .jpg)
        if not (actual_ext in ['.jpg', '.jpeg'] and detected_ext in ['.jpg', '.jpeg']):
            ext_mismatch = True

    return {
        "User Provided Extension": actual_ext,
        "Guessed MIME (from ext)": guessed_mime,
        "Signature MIME": detected_mime,
        "MIME Mismatch": "Yes" if mismatch else "No",
        "Extension Mismatch": "Yes" if ext_mismatch else "No"
    }
