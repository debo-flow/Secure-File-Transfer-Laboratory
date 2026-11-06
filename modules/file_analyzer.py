"""File inspection, validation, and full reporting orchestrator."""
import mimetypes
import re
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

from core.config import CONFIG
from core.exceptions import FileValidationError
from core.logger import get_logger

# Import M1 and M2 modules
from modules.hashing import calculate_hashes
from modules.signatures import detect_file_signature, verify_mime_type
from modules.archive_inspector import inspect_zip_archive
from modules.risk_analyzer import analyze_file_risk

logger = get_logger(__name__)

def is_safe_path(base_dir: Path, target_path: Path) -> bool:
    try:
        resolved_target = target_path.resolve(strict=False)
        resolved_base = base_dir.resolve(strict=False)
        return resolved_target.is_relative_to(resolved_base)
    except Exception as e:
        logger.error(f"Path resolution error: {str(e)}")
        return False

def sanitize_filename(filename: str) -> str:
    sanitized = re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)
    return sanitized.lstrip('.')

def validate_file(file_path: Path) -> bool:
    if not file_path.exists():
        raise FileValidationError(f"File does not exist: {file_path.name}")
    if not file_path.is_file():
        raise FileValidationError("Path is not a regular file.")
    
    size_bytes = file_path.stat().st_size
    if size_bytes == 0:
        raise FileValidationError("Empty files are not permitted.")
        
    max_bytes = CONFIG.security.max_file_size_mb * 1024 * 1024
    if size_bytes > max_bytes:
        raise FileValidationError(f"File exceeds maximum size of {CONFIG.security.max_file_size_mb} MB.")
        
    ext = file_path.suffix.lower()
    if ext not in CONFIG.security.allowed_extensions:
        raise FileValidationError(f"File extension '{ext}' is not allowed.")
        
    return True

def get_file_metadata(file_path: Path) -> Dict[str, Any]:
    try:
        stat_info = file_path.stat()
        mime_type, _ = mimetypes.guess_type(file_path.name)
        
        return {
            "Filename": file_path.name,
            "Extension": file_path.suffix.lower(),
            "Size (Bytes)": stat_info.st_size,
            "MIME Type": mime_type or "application/octet-stream",
            "Last Modified": datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            "Readable": os.access(file_path, os.R_OK) if 'os' in globals() else True
        }
    except Exception as e:
        logger.error(f"Failed to extract metadata: {str(e)}")
        raise FileValidationError("Could not safely read file metadata.")

def generate_validation_report(file_path: Path) -> Dict[str, Any]:
    """
    Orchestrates all inspection modules to generate a complete validation report.
    Required for Milestone 2 JSON export functionality.
    """
    logger.info(f"Generating comprehensive validation report for {file_path.name}")
    
    # 1. Base Metadata & Hashing (M1)
    metadata = get_file_metadata(file_path)
    hashes = calculate_hashes(file_path)
    
    # 2. Signatures & MIME Verification (M2)
    sig_data = detect_file_signature(file_path)
    mime_info = verify_mime_type(file_path, sig_data)
    
    # 3. Structural Archive Inspection (M2)
    archive_info = inspect_zip_archive(file_path)
    
    # 4. Heuristic Risk Analysis (M2)
    risk_info = analyze_file_risk(metadata, mime_info, archive_info)
    
    return {
        "Inspection Timestamp": datetime.now().isoformat(),
        "File Information": metadata,
        "Cryptographic Hashes": hashes,
        "Signature Detection": sig_data,
        "MIME Verification": mime_info,
        "Archive Inspection": archive_info,
        "Risk Assessment": risk_info
    }
