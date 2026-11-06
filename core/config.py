"""Configuration management and secure defaults."""
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Set

@dataclass
class ArchiveConfig:
    """Security configurations for archive inspection."""
    max_members: int = 10000
    max_uncompressed_size_mb: int = 500
    suspicious_compression_ratio: float = 100.0  # e.g., Uncompressed is 100x Compressed (Zip Bomb threshold)

@dataclass
class InspectionConfig:
    """Configurations for file signature and structural inspection."""
    magic_bytes_read_len: int = 2048

@dataclass
class SecurityConfig:
    """Security-focused configuration parameters."""
    max_file_size_mb: int = 50
    allowed_extensions: Set[str] = field(default_factory=lambda: {
        ".txt", ".pdf", ".csv", ".json", ".png", ".jpg", ".jpeg", ".zip"
    })
    temp_storage_dir: Path = field(default_factory=lambda: Path("temp"))
    log_dir: Path = field(default_factory=lambda: Path("logs"))

    def __post_init__(self):
        """Ensure critical directories exist securely."""
        self.temp_storage_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        if os.name == "posix":
            self.temp_storage_dir.chmod(0o700)
            self.log_dir.chmod(0o700)

@dataclass
class AppConfig:
    """General application configuration."""
    app_name: str = "Secure File Transfer Lab"
    version: str = "1.1.0-M2"
    milestone: int = 2
    security: SecurityConfig = field(default_factory=SecurityConfig)
    archive: ArchiveConfig = field(default_factory=ArchiveConfig)
    inspection: InspectionConfig = field(default_factory=InspectionConfig)

# Global configuration instance
CONFIG = AppConfig()
