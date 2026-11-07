"""Custom exceptions for the Secure File Transfer Laboratory."""

class SecureFileLabError(Exception): pass
class ConfigurationError(SecureFileLabError): pass
class FileValidationError(SecureFileLabError): pass
class PathTraversalError(FileValidationError): pass
class ArchiveInspectionError(FileValidationError): pass
class SignatureDetectionError(FileValidationError): pass
class BaselineError(SecureFileLabError): pass
class MerkleTreeError(SecureFileLabError): pass
class ManifestError(SecureFileLabError): pass

class PKIError(SecureFileLabError):
    """Raised for Key generation or formatting errors."""
    pass

class SignatureVerificationError(SecureFileLabError):
    """Raised when a cryptographic signature fails verification."""
    pass
