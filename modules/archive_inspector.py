"""Safe structural inspection for archive formats (e.g., ZIP)."""
import zipfile
from pathlib import Path
from typing import Dict, Any

from core.config import CONFIG
from core.logger import get_logger

logger = get_logger(__name__)

def inspect_zip_archive(file_path: Path) -> Dict[str, Any]:
    """
    Safely inspects a ZIP archive's metadata without extracting files.
    Detects potential zip bombs, extreme compression ratios, and member limits.
    """
    if not zipfile.is_zipfile(file_path):
        return {"Is Archive": False}
        
    inspection_results = {
        "Is Archive": True,
        "Archive Type": "ZIP",
        "Total Members": 0,
        "Compressed Size (Bytes)": 0,
        "Uncompressed Size (Bytes)": 0,
        "Compression Ratio": 1.0,
        "Contains Nested Archives": False,
        "Archive Flags": []
    }
    
    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            infolist = zf.infolist()
            inspection_results["Total Members"] = len(infolist)
            
            if len(infolist) > CONFIG.archive.max_members:
                inspection_results["Archive Flags"].append("Exceeds maximum allowed members")
                
            for info in infolist:
                inspection_results["Compressed Size (Bytes)"] += info.compress_size
                inspection_results["Uncompressed Size (Bytes)"] += info.file_size
                
                # Check for nested archives
                if info.filename.lower().endswith('.zip'):
                    inspection_results["Contains Nested Archives"] = True
                    
            # Calculate compression ratio
            c_size = inspection_results["Compressed Size (Bytes)"]
            u_size = inspection_results["Uncompressed Size (Bytes)"]
            
            if c_size > 0:
                ratio = u_size / c_size
                inspection_results["Compression Ratio"] = round(ratio, 2)
                
                if ratio > CONFIG.archive.suspicious_compression_ratio:
                    inspection_results["Archive Flags"].append("Suspicious compression ratio (Potential Zip Bomb)")
                    
            uncompressed_mb = u_size / (1024 * 1024)
            if uncompressed_mb > CONFIG.archive.max_uncompressed_size_mb:
                inspection_results["Archive Flags"].append("Exceeds maximum uncompressed size limit")
                
        return inspection_results
        
    except zipfile.BadZipFile:
        logger.warning(f"Malformed or truncated ZIP file detected: {file_path.name}")
        return {"Is Archive": True, "Error": "Malformed or truncated ZIP file"}
    except Exception as e:
        logger.error(f"Archive inspection failed: {str(e)}")
        return {"Is Archive": True, "Error": str(e)}
