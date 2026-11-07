"""Digital Signature and Key Management Engine."""
import hashlib
from pathlib import Path
from typing import Any, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature

from core.logger import get_logger
from core.exceptions import PKIError, SignatureVerificationError

logger = get_logger(__name__)

def generate_ed25519_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generates a secure Ed25519 elliptic curve key pair."""
    priv_key = ed25519.Ed25519PrivateKey.generate()
    return priv_key, priv_key.public_key()

def generate_rsa_keypair(key_size: int = 4096) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generates a secure RSA key pair for PSS signatures."""
    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return priv_key, priv_key.public_key()

def export_private_key(private_key: Any, password: str) -> bytes:
    """Exports private key to PEM format using AES-256 encryption."""
    encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )

def export_public_key(public_key: Any) -> bytes:
    """Exports public key to standardized PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_private_key(pem_data: bytes, password: str) -> Any:
    """Safely loads an encrypted private key."""
    try:
        return serialization.load_pem_private_key(pem_data, password=password.encode())
    except Exception as e:
        logger.error("Failed to load private key.")
        raise PKIError(f"Private key decryption failed: {str(e)}")

def load_public_key(pem_data: bytes) -> Any:
    """Loads a public key from PEM."""
    try:
        return serialization.load_pem_public_key(pem_data)
    except Exception as e:
        raise PKIError(f"Invalid public key format: {str(e)}")

def sign_file_streaming(file_path: Path, private_key: Any) -> bytes:
    """
    Cryptographically signs a large file using streaming pre-hashing.
    - RSA uses PSS with SHA-256 Prehashed context.
    - Ed25519 uses a documented SHA-512 pre-hash payload to support memory-safe streaming.
    """
    if isinstance(private_key, rsa.RSAPrivateKey):
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""): sha256.update(chunk)
        return private_key.sign(
            sha256.digest(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            Prehashed(hashes.SHA256())
        )
    elif isinstance(private_key, ed25519.Ed25519PrivateKey):
        # Ed25519 Pre-hash construction for large file streaming compatibility
        sha512 = hashlib.sha512()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""): sha512.update(chunk)
        return private_key.sign(sha512.digest())
    else:
        raise PKIError("Unsupported private key type.")

def verify_file_signature(file_path: Path, signature: bytes, public_key: Any) -> bool:
    """Verifies a streaming file signature."""
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""): sha256.update(chunk)
            public_key.verify(
                signature,
                sha256.digest(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                Prehashed(hashes.SHA256())
            )
            return True
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            sha512 = hashlib.sha512()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""): sha512.update(chunk)
            public_key.verify(signature, sha512.digest())
            return True
        else:
            raise PKIError("Unsupported public key type.")
    except InvalidSignature:
        raise SignatureVerificationError("Cryptographic signature mismatch. File tampered or wrong key.")
