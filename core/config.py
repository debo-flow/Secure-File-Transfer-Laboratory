"""Configuration management and secure defaults."""
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Set

@dataclass
class SecurityConfig:
    """Security-focused configuration parameters."""
    max_file_size_mb: int = 50
    allowed_extensions: Set[str] = field(default_factory=lambda: {
        ".txt", ".pdf", ".csv", ".json", ".png", ".jpg", ".jpeg"
    })
    temp_storage_dir: Path = field(default_factory=lambda: Path("temp"))
    log_dir: Path = field(default_factory=lambda: Path("logs"))

    def __post_init__(self):
        """Ensure critical directories exist securely."""
        self.temp_storage_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Ensure temp directory has restrictive permissions if on POSIX
        if os.name == "posix":
            self.temp_storage_dir.chmod(0o700)
            self.log_dir.chmod(0o700)

@dataclass
class AppConfig:
    """General application configuration."""
    app_name: str = "Secure File Transfer Lab"
    version: str = "1.0.0-M1"
    milestone: int = 1
    security: SecurityConfig = field(default_factory=SecurityConfig)

# Global configuration instance
CONFIG = AppConfig()
