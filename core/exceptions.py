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
    """Raised when there is an issue reading or validating a file baseline."""
    pass

class MerkleTreeError(SecureFileLabError):
    """Raised during Merkle Tree generation or proof validation failures."""
    pass
