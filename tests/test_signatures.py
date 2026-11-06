"""Pytest suite for magic bytes and MIME detection."""
import pytest
from pathlib import Path
from modules.signatures import detect_file_signature, verify_mime_type

def test_detect_pdf_signature(tmp_path):
    pdf_file = tmp_path / "document.pdf"
    pdf_file.write_bytes(b"%PDF-1.4\n%...\n")
    
    result = detect_file_signature(pdf_file)
    assert result["Detected MIME"] == "application/pdf"
    assert result["Signature Verified"] == "Yes"

def test_mime_mismatch(tmp_path):
    # Fake PNG that is actually a PDF signature
    fake_png = tmp_path / "image.png"
    fake_png.write_bytes(b"%PDF-1.4\n")
    
    sig_result = detect_file_signature(fake_png)
    mime_result = verify_mime_type(fake_png, sig_result)
    
    assert mime_result["Extension Mismatch"] == "Yes"
    assert mime_result["MIME Mismatch"] == "Yes"
    assert mime_result["Guessed MIME (from ext)"] == "image/png"
    assert mime_result["Signature MIME"] == "application/pdf"
