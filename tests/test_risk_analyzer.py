"""Pytest suite for heuristic risk engine."""
import pytest
from modules.risk_analyzer import analyze_file_risk

def test_informational_risk():
    metadata = {"MIME Type": "application/pdf"}
    mime = {"Extension Mismatch": "No", "MIME Mismatch": "No"}
    archive = {"Is Archive": False}
    
    result = analyze_file_risk(metadata, mime, archive)
    assert result["Risk Level"] == "Informational"

def test_warning_on_mismatch():
    metadata = {"MIME Type": "image/png"}
    mime = {"Extension Mismatch": "Yes", "MIME Mismatch": "Yes"}
    archive = {"Is Archive": False}
    
    result = analyze_file_risk(metadata, mime, archive)
    assert result["Risk Level"] == "Warning"
    assert any("mismatch" in f.lower() for f in result["Risk Flags"])

def test_high_risk_zip_bomb():
    metadata = {"MIME Type": "application/zip"}
    mime = {"Extension Mismatch": "No"}
    archive = {
        "Is Archive": True, 
        "Archive Flags": ["Suspicious compression ratio (Potential Zip Bomb)"]
    }
    
    result = analyze_file_risk(metadata, mime, archive)
    assert result["Risk Level"] == "High-Risk"
    assert "Suspicious compression ratio" in result["Risk Flags"][0]
