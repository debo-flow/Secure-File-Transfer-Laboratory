"""File inspection and validation engine."""
import mimetypes
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

from core.config import CONFIG
from core.exceptions import FileValidationError, PathTraversalError
from core.logger import get_logger

logger = get_logger(__name__)

def is_safe_path(base_dir: Path, target_path: Path) -> bool:
    """
    Validates that the target path securely resides within the base directory.
    Prevents directory traversal (e.g., ../../etc/passwd).
    """
    try:
        resolved_target = target_path.resolve(strict=False)
        resolved_base = base_dir.resolve(strict=False)
        return resolved_target.is_relative_to(resolved_base)
    except Exception as e:
        logger.error(f"Path resolution error: {str(e)}")
        return False

def sanitize_filename(filename: str) -> str:
    """Removes potentially dangerous characters from filenames."""
    # Keep alphanumeric, dashes, underscores, and dots.
    sanitized = re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)
    return sanitized.lstrip('.') # Prevent hidden files

def validate_file(file_path: Path) -> bool:
    """
    Runs comprehensive security validations on the file.
    Raises FileValidationError if checks fail.
    """
    if not file_path.exists():
        raise FileValidationError(f"File does not exist: {file_path.name}")
        
    if not file_path.is_file():
        raise FileValidationError("Path is not a regular file.")
        
    # Check emptiness
    size_bytes = file_path.stat().st_size
    if size_bytes == 0:
        raise FileValidationError("Empty files are not permitted.")
        
    # Check size limits
    max_bytes = CONFIG.security.max_file_size_mb * 1024 * 1024
    if size_bytes > max_bytes:
        raise FileValidationError(f"File exceeds maximum size of {CONFIG.security.max_file_size_mb} MB.")
        
    # Check extension
    ext = file_path.suffix.lower()
    if ext not in CONFIG.security.allowed_extensions:
        raise FileValidationError(f"File extension '{ext}' is not allowed.")
        
    return True

def get_file_metadata(file_path: Path) -> Dict[str, Any]:
    """
    Safely inspects file metadata without executing contents.
    Assumes file has already passed validate_file().
    """
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
        logger.error(f"Failed to extract metadata for {file_path.name}: {str(e)}")
        raise FileValidationError("Could not safely read file metadata.")
