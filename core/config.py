"""Configuration management and secure defaults."""
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Set

@dataclass
class ArchiveConfig:
    max_members: int = 10000
    max_uncompressed_size_mb: int = 500
    suspicious_compression_ratio: float = 100.0

@dataclass
class InspectionConfig:
    magic_bytes_read_len: int = 2048

@dataclass
class IntegrityConfig:
    default_chunk_size_kb: int = 1024
    baseline_dir: Path = field(default_factory=lambda: Path("baselines"))
    
    def __post_init__(self):
        self.baseline_dir.mkdir(parents=True, exist_ok=True)
        if os.name == "posix": self.baseline_dir.chmod(0o700)

@dataclass
class IdentityConfig:
    manifest_schema_version: str = "1.1.0"
    manifest_dir: Path = field(default_factory=lambda: Path("manifests"))
    
    def __post_init__(self):
        self.manifest_dir.mkdir(parents=True, exist_ok=True)
        if os.name == "posix": self.manifest_dir.chmod(0o700)

@dataclass
class PKIConfig:
    """Configurations for M5 Public Key Infrastructure and Signatures."""
    pki_dir: Path = field(default_factory=lambda: Path("pki"))
    key_directory_file: str = "trusted_keys.json"
    audit_log_file: str = "signature_audit.jsonl"
    
    def __post_init__(self):
        self.pki_dir.mkdir(parents=True, exist_ok=True)
        if os.name == "posix": self.pki_dir.chmod(0o700)

@dataclass
class SecurityConfig:
    max_file_size_mb: int = 50
    allowed_extensions: Set[str] = field(default_factory=lambda: {
        ".txt", ".pdf", ".csv", ".json", ".png", ".jpg", ".jpeg", ".zip", ".pem"
    })
    temp_storage_dir: Path = field(default_factory=lambda: Path("temp"))
    log_dir: Path = field(default_factory=lambda: Path("logs"))

    def __post_init__(self):
        self.temp_storage_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            self.temp_storage_dir.chmod(0o700)
            self.log_dir.chmod(0o700)

@dataclass
class AppConfig:
    app_name: str = "Secure File Transfer Lab"
    version: str = "1.4.0-M5"
    milestone: int = 5
    security: SecurityConfig = field(default_factory=SecurityConfig)
    archive: ArchiveConfig = field(default_factory=ArchiveConfig)
    inspection: InspectionConfig = field(default_factory=InspectionConfig)
    integrity: IntegrityConfig = field(default_factory=IntegrityConfig)
    identity: IdentityConfig = field(default_factory=IdentityConfig)
    pki: PKIConfig = field(default_factory=PKIConfig)

CONFIG = AppConfig()
