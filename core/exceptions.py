"""Custom exceptions for the Secure File Transfer Laboratory."""

class SecureFileLabError(Exception):
    """Base exception for all application-specific errors."""
    pass

class ConfigurationError(SecureFileLabError):
    """Raised when there is an issue with application configuration."""
    pass

class FileValidationError(SecureFileLabError):
    """Raised when a file fails security or integrity validation."""
    pass

class PathTraversalError(FileValidationError):
    """Raised when an attempted path traversal is detected."""
    pass
