"""Pytest suite for safe archive structural inspection."""
import pytest
import zipfile
from pathlib import Path
from modules.archive_inspector import inspect_zip_archive
from core.config import CONFIG

def create_test_zip(path: Path, files_dict: dict):
    """Helper to create a real zip file for testing."""
    with zipfile.ZipFile(path, 'w') as zf:
        for fname, content in files_dict.items():
            zf.writestr(fname, content)

def test_not_an_archive(tmp_path):
    txt_file = tmp_path / "test.txt"
    txt_file.write_bytes(b"Just a normal text file.")
    
    result = inspect_zip_archive(txt_file)
    assert result["Is Archive"] is False

def test_valid_archive_inspection(tmp_path):
    zip_path = tmp_path / "test.zip"
    create_test_zip(zip_path, {"file1.txt": b"Hello", "file2.txt": b"World"})
    
    result = inspect_zip_archive(zip_path)
    assert result["Is Archive"] is True
    assert result["Total Members"] == 2
    assert "Archive Flags" in result
    assert len(result["Archive Flags"]) == 0

def test_archive_nested_detection(tmp_path):
    zip_path = tmp_path / "nested.zip"
    create_test_zip(zip_path, {"inner.zip": b"fakezipdata"})
    
    result = inspect_zip_archive(zip_path)
    assert result["Contains Nested Archives"] is True
