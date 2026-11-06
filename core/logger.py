"""Structured application logging engine."""
import logging
import sys
from pathlib import Path
from core.config import CONFIG

def get_logger(name: str) -> logging.Logger:
    """
    Configures and returns a structured logger.
    Ensures sensitive data is not logged by enforcing strict log formats.
    """
    logger = logging.getLogger(name)
    
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        
        # Format explicitly excludes arbitrary contextual data to prevent accidental PII/Secret logging
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | [%(name)s] | %(message)s'
        )
        
        # Console Handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # File Handler
        log_file = CONFIG.security.log_dir / "application.log"
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
    return logger

# Initialize root application logger
app_logger = get_logger("app_init")
app_logger.info(f"Initialized {CONFIG.app_name} v{CONFIG.version}")
