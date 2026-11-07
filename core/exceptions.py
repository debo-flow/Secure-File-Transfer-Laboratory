"""Custom exceptions for the Secure File Transfer Laboratory."""

class SecureFileLabError(Exception):
    pass

class ConfigurationError(SecureFileLabError):
    pass

class FileValidationError(SecureFileLabError):
    pass

class PathTraversalError(FileValidationError):
    pass

class ArchiveInspectionError(FileValidationError):
    pass

class SignatureDetectionError(FileValidationError):
    pass

class BaselineError(SecureFileLabError):
    pass

class MerkleTreeError(SecureFileLabError):
    pass

class ManifestError(SecureFileLabError):
    """Raised when a manifest is malformed, invalid, or fails structural verification."""
    pass
