"""Pytest suite for file analysis and validation logic."""
import pytest
from pathlib import Path
from modules.file_analyzer import is_safe_path, sanitize_filename, validate_file, get_file_metadata
from core.exceptions import FileValidationError
from core.config import CONFIG

def test_sanitize_filename():
    assert sanitize_filename("safe_file.txt") == "safe_file.txt"
    assert sanitize_filename("../unsafe_file.txt") == "unsafe_file.txt"
    assert sanitize_filename("space name.pdf") == "space_name.pdf"
    assert sanitize_filename(".hidden") == "hidden"

def test_is_safe_path(tmp_path):
    base = tmp_path / "base"
    base.mkdir()
    
    safe_target = base / "test.txt"
    unsafe_target = base / ".." / "outside.txt"
    
    assert is_safe_path(base, safe_target) is True
    assert is_safe_path(base, unsafe_target) is False

def test_validate_file_not_exist(tmp_path):
    fake_file = tmp_path / "does_not_exist.txt"
    with pytest.raises(FileValidationError, match="does not exist"):
        validate_file(fake_file)

def test_validate_empty_file(tmp_path):
    empty_file = tmp_path / "empty.txt"
    empty_file.touch()
    
    with pytest.raises(FileValidationError, match="Empty files are not permitted"):
        validate_file(empty_file)

def test_validate_invalid_extension(tmp_path):
    bad_file = tmp_path / "malicious.exe"
    bad_file.write_text("dummy payload")
    
    with pytest.raises(FileValidationError, match="is not allowed"):
        validate_file(bad_file)

def test_validate_success(tmp_path):
    good_file = tmp_path / "document.txt"
    good_file.write_text("Hello secure world!")
    
    # Should not raise any exceptions
    assert validate_file(good_file) is True

def test_get_file_metadata(tmp_path):
    test_file = tmp_path / "data.json"
    test_file.write_text('{"key": "value"}')
    
    metadata = get_file_metadata(test_file)
    assert metadata["Filename"] == "data.json"
    assert metadata["Extension"] == ".json"
    assert metadata["Size (Bytes)"] > 0
    assert metadata["MIME Type"] == "application/json"
