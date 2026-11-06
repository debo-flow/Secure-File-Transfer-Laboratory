"""Rule-based heuristic file risk analysis engine."""
from typing import Dict, Any, List

def analyze_file_risk(
    metadata: Dict[str, Any], 
    mime_info: Dict[str, str], 
    archive_info: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Analyzes aggregated file data against heuristic rules to determine risk status.
    NOTE: This is not an antivirus. It highlights structural and metadata anomalies.
    """
    flags: List[str] = []
    risk_level = "Informational"
    
    # Rule 1: Extension/Signature Mismatch
    if mime_info.get("Extension Mismatch") == "Yes":
        flags.append(f"Extension mismatch: User claims {mime_info.get('User Provided Extension')}, but signature is {mime_info.get('Signature MIME')}")
        risk_level = "Warning" if risk_level == "Informational" else risk_level
        
    # Rule 2: MIME Mismatch
    if mime_info.get("MIME Mismatch") == "Yes":
        flags.append("MIME type inconsistency detected between OS guess and file signature.")
        risk_level = "Warning" if risk_level == "Informational" else risk_level

    # Rule 3: Unknown format for executable-like behavior
    if metadata.get("MIME Type") == "application/octet-stream" and mime_info.get("Signature MIME") == "application/octet-stream":
        flags.append("Unknown binary format detected. Manual inspection required.")
        risk_level = "Warning" if risk_level == "Informational" else risk_level

    # Rule 4: Archive Analysis (Zip Bombs and nesting)
    if archive_info.get("Is Archive"):
        if "Error" in archive_info:
            flags.append(f"Malformed Archive: {archive_info['Error']}")
            risk_level = "High-Risk"
        
        archive_flags = archive_info.get("Archive Flags", [])
        if archive_flags:
            flags.extend(archive_flags)
            risk_level = "High-Risk"  # Zip bombs and limit breaches are high risk
            
        if archive_info.get("Contains Nested Archives"):
            flags.append("Nested archives detected (often used to obscure payloads).")
            risk_level = "Warning" if risk_level == "Informational" else risk_level

    return {
        "Risk Level": risk_level,
        "Risk Flags": flags if flags else ["No immediate structural anomalies detected."],
        "Disclaimer": "Heuristic inspection only. This does not guarantee the file is free of malicious payloads."
    }
